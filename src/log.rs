//! Transaction log replay: a dirty hive's `.LOG1` / `.LOG2` (or `.LOG`) applied over it, as
//! Windows applies them when it loads the hive.
//!
//! The format is Maxim Suhanov's *Windows registry file format specification*
//! (<https://github.com/msuhanov/regf>, CC BY 4.0), and the replay gives what yarp recovers:
//! new-format logs (`HvLE` entries, Windows 8.1 and later) from the sequence number in the log's
//! base block on, each entry one more than the last, the first invalid one (signature, size,
//! hive bins data size, Marvin32 hashes, sequence number) ending the log; both logs, the one with
//! the earlier entries first, the other when it continues the sequence; a primary file whose
//! base block is invalid takes only the log with the latest entries, and its base block; old
//! format logs (a `DIRT` dirty vector) when not older than the hive. The recovered hive gets the
//! last sequence number, the hive bins data size and flags of the last entry, and a new checksum.

use std::path::Path;

use crate::bytes::{u32_at, u64_at};

/// The base block's size; cell offsets count from its end.
pub(crate) const BASE: usize = 4096;
const LOG_BASE: usize = 512;
pub(crate) const HBIN_ALIGNMENT: u32 = 4096;
/// The largest hive bins data size: cell offsets are 31 bits, so a hive holds at most 2 GiB.
const MAX_HIVE_BINS: u32 = 0x8000_0000;
const MARVIN_SEED: u64 = 0x82EF_4D88_7A4E_55C5;

/// A transaction log file: its name (`SYSTEM.LOG1`, ...) and bytes.
#[derive(Debug, Clone)]
pub struct LogFile {
    /// Its name; `.LOG`, `.LOG1` and `.LOG2` (in any case) say which it is.
    pub name: String,
    /// Its bytes.
    pub data: Vec<u8>,
}

/// What opening a hive did with its transaction logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovery {
    /// The hive was dirty (its sequence numbers differ, or its base block is invalid).
    pub dirty: bool,
    /// Logs were applied.
    pub recovered: bool,
    /// The logs applied, by name.
    pub logs_applied: Vec<String>,
    /// The last sequence number applied.
    pub last_sequence: Option<u32>,
    /// What was done with each log, and why one was not used.
    pub messages: Vec<String>,
}

/// The transaction logs next to the hive at `path`: `<name>.LOG`, `.LOG1` and `.LOG2`, in any
/// case, sorted by name; empty ones are left out.
#[must_use]
pub fn find_logs(path: &Path) -> Vec<LogFile> {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_uppercase()) else {
        return Vec::new();
    };
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let wanted: Vec<String> = [".LOG", ".LOG1", ".LOG2"]
        .iter()
        .map(|x| format!("{name}{x}"))
        .collect();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut logs: Vec<LogFile> = entries
        .flatten()
        .filter(|e| wanted.contains(&e.file_name().to_string_lossy().to_uppercase()))
        .filter_map(|e| {
            let data = std::fs::read(e.path()).ok().filter(|d| !d.is_empty())?;
            Some(LogFile {
                name: e.file_name().to_string_lossy().to_string(),
                data,
            })
        })
        .collect();
    logs.sort_by_key(|l| l.name.to_uppercase());
    logs
}

/// The base block fields recovery uses.
#[derive(Debug, Clone)]
pub(crate) struct BaseBlock {
    pub(crate) valid: bool,
    pub(crate) dirty: bool,
    primary_sequence: u32,
    secondary_sequence: u32,
    last_written: i64,
    hive_bins_data_size: u32,
    flags: u32,
}

impl BaseBlock {
    pub(crate) fn new(b: &[u8], primary: bool) -> Self {
        let valid =
            b.len() >= 512 && b.get(0..4) == Some(b"regf") && u32_at(b, 508) == Some(checksum(b));
        let primary_sequence = u32_at(b, 4).unwrap_or(0);
        let secondary_sequence = u32_at(b, 8).unwrap_or(0);
        let mut bb = Self {
            valid,
            dirty: !valid || primary_sequence != secondary_sequence,
            primary_sequence,
            secondary_sequence,
            last_written: u64_at(b, 12).unwrap_or(0).cast_signed(),
            hive_bins_data_size: u32_at(b, 40).unwrap_or(0),
            flags: u32_at(b, 144).unwrap_or(0),
        };
        if primary && !valid {
            // the base block can't be trusted: the size from the file, the time from the first bin
            bb.hive_bins_data_size = u32::try_from(
                b.len().saturating_sub(BASE) / HBIN_ALIGNMENT as usize * HBIN_ALIGNMENT as usize,
            )
            .unwrap_or(0);
            bb.last_written = u64_at(b, BASE + 0x14).unwrap_or(0).cast_signed();
        }
        bb
    }
}

/// The XOR-32 checksum of the first 508 bytes (0 is written as 1, 0xFFFFFFFF as 0xFFFFFFFE).
pub(crate) fn checksum(b: &[u8]) -> u32 {
    let mut x = 0u32;
    for i in (0..508).step_by(4) {
        x ^= u32_at(b, i).unwrap_or(0);
    }
    match x {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        x => x,
    }
}

/// What a log held for the hive at one time: an entry's dirty pages (a new-format log's entry,
/// or an old-format log's pages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEntry {
    /// The log's name.
    pub(crate) log: String,
    /// The entry's sequence number (new-format logs).
    pub(crate) sequence: Option<u32>,
    /// The pages: their offsets in the hive bins, and their bytes.
    pub(crate) pages: Vec<(u32, Vec<u8>)>,
}

/// Every entry of `files` whose hashes are right, whether the replay applied it or not (a log
/// keeps older entries after the current ones), in the order of the logs and entries.
pub(crate) fn entries(files: &[LogFile]) -> Vec<LogEntry> {
    let mut out = Vec::new();
    for log in files {
        let b = &log.data;
        if b.len() > LOG_BASE + 40 && b.get(0..4) == Some(b"regf") && u32_at(b, 28) == Some(6) {
            let mut pos = LOG_BASE;
            while pos + 40 <= b.len() {
                let sequence = u32_at(b, pos + 12).unwrap_or(0);
                if invalid_entry(b, pos, sequence).is_some() {
                    pos += 512;
                    continue;
                }
                let size = u32_at(b, pos + 4).unwrap_or(0) as usize;
                let entry_end = pos + size;
                let hbins = u32_at(b, pos + 16).unwrap_or(0);
                let count = u32_at(b, pos + 20).unwrap_or(0) as usize;
                let mut at = pos + 40 + 8 * count;
                let mut pages = Vec::new();
                for i in 0..count {
                    let offset = u32_at(b, pos + 40 + 8 * i).unwrap_or(0);
                    let len = u32_at(b, pos + 44 + 8 * i).unwrap_or(0);
                    let Some(end) = at.checked_add(len as usize) else {
                        break;
                    };
                    if end > entry_end
                        || offset
                            .checked_add(len)
                            .is_none_or(|page_end| page_end > hbins)
                    {
                        break;
                    }
                    let page = &b[at..end];
                    pages.push((offset, page.to_vec()));
                    at = end;
                }
                if pages.len() == count {
                    out.push(LogEntry {
                        log: log.name.clone(),
                        sequence: Some(sequence),
                        pages,
                    });
                }
                pos += size;
            }
        } else if is_old_log(log, &mut Vec::new()) {
            let bb = BaseBlock::new(b, false);
            let start = dirty_pages_start(bb.hive_bins_data_size);
            let mut pages = Vec::new();
            for bit in 0..(bb.hive_bins_data_size / 512) as usize {
                let Some(byte) = b.get(LOG_BASE + 4 + bit / 8) else {
                    break;
                };
                if (byte >> (bit % 8)) & 1 == 0 {
                    continue;
                }
                let from = start + pages.len() * 512;
                let Some(page) = b.get(from..from + 512) else {
                    break;
                };
                pages.push(((bit * 512) as u32, page.to_vec()));
            }
            out.push(LogEntry {
                log: log.name.clone(),
                sequence: None,
                pages,
            });
        }
    }
    out
}

pub(crate) struct Replayed {
    pub(crate) bytes: Vec<u8>,
    pub(crate) recovered: bool,
    pub(crate) last_sequence: Option<u32>,
    pub(crate) logs_applied: Vec<String>,
    pub(crate) messages: Vec<String>,
}

struct State {
    primary: BaseBlock,
    bytes: Vec<u8>,
    applied: usize,
    last_sequence: Option<u32>,
    hive_bins_data_size: u32,
    flags: u32,
    log_base: Option<Vec<u8>>,
    logs_applied: Vec<String>,
    messages: Vec<String>,
}

impl State {
    /// Grow the file to hold `hbins_end` bytes of hive bins; `false` when the memory for it
    /// can't be had (the file is then as it was).
    fn grow(&mut self, hbins_end: u64) -> bool {
        let Ok(end) = usize::try_from(hbins_end + BASE as u64) else {
            return false;
        };
        if end > self.bytes.len() {
            if self
                .bytes
                .try_reserve_exact(end - self.bytes.len())
                .is_err()
            {
                return false;
            }
            self.bytes.resize(end, 0);
        }
        true
    }

    /// Write a page at a hive bins offset, growing the file when it is past the end.
    fn write(&mut self, offset: u32, page: &[u8]) -> bool {
        let end = u64::from(offset) + page.len() as u64;
        if !self.grow(end) {
            return false;
        }
        let start = BASE + offset as usize;
        self.bytes[start..start + page.len()].copy_from_slice(page);
        true
    }
}

/// `a` is an earlier sequence number than `b` (allowing for overflow).
fn is_earlier(a: u32, b: u32) -> bool {
    if a >= b {
        a - b > 0x7FFF_FFFF
    } else {
        b - a <= 0x7FFF_FFFF
    }
}

pub(crate) fn replay(primary: Vec<u8>, files: &[LogFile]) -> Replayed {
    let base = BaseBlock::new(&primary, true);
    let mut st = State {
        hive_bins_data_size: base.hive_bins_data_size,
        flags: base.flags,
        primary: base,
        bytes: primary,
        applied: 0,
        last_sequence: None,
        log_base: None,
        logs_applied: Vec::new(),
        messages: Vec::new(),
    };
    let named = |ext: &str| {
        files
            .iter()
            .find(|l| !l.data.is_empty() && l.name.to_uppercase().ends_with(ext))
    };
    let legacy = named(".LOG");
    let mut log1 = named(".LOG1");
    let mut log2 = named(".LOG2");
    // logs not named like the hive's: the first two as LOG1 and LOG2
    let others: Vec<&LogFile> = files
        .iter()
        .filter(|l| !l.data.is_empty())
        .filter(|l| {
            ![legacy, log1, log2]
                .iter()
                .any(|n| n.is_some_and(|n| std::ptr::eq(n, *l)))
        })
        .collect();
    if log1.is_none() {
        log1 = others.first().copied();
    }
    if log2.is_none() {
        log2 = others
            .iter()
            .copied()
            .find(|l| log1.is_none_or(|a| !std::ptr::eq(*l, a)));
    }
    let new1 = log1.filter(|l| is_new_log(l, &mut st.messages));
    let new2 = log2.filter(|l| is_new_log(l, &mut st.messages));
    let new0 = legacy.filter(|l| is_new_log(l, &mut st.messages));
    let old1 = log1.filter(|l| is_old_log(l, &mut st.messages));
    let old2 = log2.filter(|l| is_old_log(l, &mut st.messages));
    let old0 = legacy.filter(|l| is_old_log(l, &mut st.messages));
    let outcome = match (new1, new2) {
        (Some(a), Some(b)) => apply_new_logs(&mut st, a, b),
        (Some(a), None) | (None, Some(a)) => apply_new_log(&mut st, a),
        (None, None) => {
            if let Some(l) = new0 {
                apply_new_log(&mut st, l)
            } else {
                match (old1, old2) {
                    (Some(a), Some(b)) => {
                        let (ta, tb) = (
                            BaseBlock::new(&a.data, false).last_written,
                            BaseBlock::new(&b.data, false).last_written,
                        );
                        apply_old_log(&mut st, if ta >= tb { a } else { b })
                    }
                    (Some(a), None) | (None, Some(a)) => apply_old_log(&mut st, a),
                    (None, None) => match old0 {
                        Some(l) => apply_old_log(&mut st, l),
                        None => Err("No transaction log that can be applied was found".to_owned()),
                    },
                }
            }
        }
    };
    if let Err(m) = outcome {
        st.messages.push(m);
    }
    if st.applied == 0 {
        return Replayed {
            bytes: st.bytes,
            recovered: false,
            last_sequence: None,
            logs_applied: st.logs_applied,
            messages: st.messages,
        };
    }
    finish_base_block(&mut st);
    Replayed {
        bytes: st.bytes,
        recovered: true,
        last_sequence: st.last_sequence,
        logs_applied: st.logs_applied,
        messages: st.messages,
    }
}

fn is_new_log(l: &LogFile, messages: &mut Vec<String>) -> bool {
    let b = &l.data;
    if b.len() <= LOG_BASE + 40 || b.get(0..4) != Some(b"regf") || u32_at(b, 28) != Some(6) {
        return false;
    }
    if BaseBlock::new(b, false).dirty {
        messages.push(format!(
            "{}: its base block is invalid or dirty, so it is not used",
            l.name
        ));
        return false;
    }
    true
}

fn is_old_log(l: &LogFile, messages: &mut Vec<String>) -> bool {
    let b = &l.data;
    if b.len() < LOG_BASE + 4 || b.get(0..4) != Some(b"regf") {
        return false;
    }
    let file_type = u32_at(b, 28).unwrap_or(0);
    if file_type != 1 && file_type != 2 {
        return false;
    }
    let bb = BaseBlock::new(b, false);
    if bb.dirty {
        messages.push(format!(
            "{}: its base block is invalid or dirty, so it is not used",
            l.name
        ));
        return false;
    }
    b.len() >= dirty_pages_start(bb.hive_bins_data_size) + 512
        && b.get(LOG_BASE..LOG_BASE + 4) == Some(b"DIRT")
}

fn apply_new_logs(st: &mut State, log1: &LogFile, log2: &LogFile) -> Result<(), String> {
    let seq1 = u32_at(&log1.data, 4).unwrap_or(0);
    let seq2 = u32_at(&log2.data, 4).unwrap_or(0);
    let (first, second) = if is_earlier(seq1, seq2) {
        (log1, log2)
    } else {
        (log2, log1)
    };
    if !st.primary.valid {
        // only the log with the latest entries (as Windows does)
        return apply_new_log(st, second);
    }
    if let Err(m) = apply_new_log(st, first) {
        st.messages.push(m);
        return apply_new_log(st, second);
    }
    if let Some(last) = st.last_sequence
        && u32_at(&second.data, 4) == Some(last.wrapping_add(1))
    {
        return apply_new_log(st, second);
    }
    Ok(())
}

fn apply_new_log(st: &mut State, log: &LogFile) -> Result<(), String> {
    let bb = BaseBlock::new(&log.data, false);
    if st.applied >= 2 {
        return Err(format!(
            "{}: no more than two logs can be applied",
            log.name
        ));
    }
    if let Some(last) = st.last_sequence
        && is_earlier(bb.primary_sequence, last.wrapping_add(1))
    {
        return Err(format!(
            "{}: its entries are not after the last one applied",
            log.name
        ));
    }
    if st.primary.valid && is_earlier(bb.primary_sequence, st.primary.secondary_sequence) {
        return Err(format!(
            "{}: its entries (from sequence number {}) are older than the hive ({})",
            log.name, bb.primary_sequence, st.primary.secondary_sequence
        ));
    }
    let flags = st.flags;
    st.flags = bb.flags;
    let applied = apply_entries(st, &log.data, bb.primary_sequence, &log.name);
    if applied == 0 {
        // nothing of it is in the hive: not applied (and with two logs, the other one is tried)
        st.flags = flags;
        return Err(format!(
            "{}: no log entry could be applied, so it is not used",
            log.name
        ));
    }
    st.log_base = Some(log.data.get(..LOG_BASE).unwrap_or_default().to_vec());
    st.applied += 1;
    st.logs_applied.push(log.name.clone());
    st.messages.push(format!(
        "{}: applied {applied} log entries (sequence numbers {} to {})",
        log.name,
        bb.primary_sequence,
        st.last_sequence.unwrap_or(0)
    ));
    Ok(())
}

/// Apply the entries of a new-format log from `first` on, until one is invalid or out of
/// sequence; how many were applied.
fn apply_entries(st: &mut State, b: &[u8], first: u32, name: &str) -> usize {
    let mut expected = first;
    let mut pos = LOG_BASE;
    let mut applied = 0;
    while pos + 40 <= b.len() {
        if invalid_entry(b, pos, expected).is_some() {
            // a log holds older entries after the current ones, so this is how most logs end
            break;
        }
        let size = u32_at(b, pos + 4).unwrap_or(0) as usize;
        let hbins = u32_at(b, pos + 16).unwrap_or(0);
        let count = u32_at(b, pos + 20).unwrap_or(0) as usize;
        let Some(pages) = count
            .checked_mul(8)
            .and_then(|n| pos.checked_add(40)?.checked_add(n))
        else {
            st.messages.push(format!(
                "{name}: the dirty-page references of the entry with sequence number {expected} overflow"
            ));
            break;
        };
        let refs: Vec<(u32, u32)> = (0..count)
            .map(|i| {
                (
                    u32_at(b, pos + 40 + 8 * i).unwrap_or(0),
                    u32_at(b, pos + 44 + 8 * i).unwrap_or(0),
                )
            })
            .collect();
        let total = refs.iter().map(|r| u64::from(r.1)).sum::<u64>();
        let entry_end = pos + size;
        if total + pages as u64 > entry_end as u64 {
            st.messages.push(format!(
                "{name}: the dirty pages of the entry with sequence number {expected} are past the end of the entry"
            ));
            break;
        }
        // a page is in the hive bins the entry gives (which are never more than 2 GiB)
        if refs
            .iter()
            .any(|&(offset, len)| u64::from(offset) + u64::from(len) > u64::from(hbins))
        {
            st.messages.push(format!(
                "{name}: a dirty page of the entry with sequence number {expected} is past its hive bins data size (0x{hbins:X})"
            ));
            break;
        }
        // grow once, so that an entry is applied whole or not at all
        let end = refs
            .iter()
            .map(|&(offset, len)| u64::from(offset) + u64::from(len))
            .max()
            .unwrap_or(0);
        if !st.grow(end) {
            st.messages.push(format!(
                "{name}: the hive could not grow to 0x{end:X} bytes for the entry with sequence number {expected}"
            ));
            break;
        }
        let mut at = pages;
        for &(offset, len) in &refs {
            let len = len as usize;
            st.write(offset, &b[at..at + len]);
            at += len;
        }
        st.last_sequence = Some(expected);
        st.flags = (st.flags & !1) | (u32_at(b, pos + 8).unwrap_or(0) & 1);
        st.hive_bins_data_size = hbins;
        applied += 1;
        pos += size;
        expected = expected.wrapping_add(1);
    }
    applied
}

/// Why the log entry at `pos` can't be applied, if it can't.
fn invalid_entry(b: &[u8], pos: usize, expected: u32) -> Option<String> {
    if b.get(pos..pos + 4) != Some(b"HvLE") {
        return Some("no log entry signature".to_owned());
    }
    let size = u32_at(b, pos + 4).unwrap_or(0) as usize;
    if size < 512 || !size.is_multiple_of(512) {
        return Some(format!("invalid size 0x{size:X}"));
    }
    let Some(end) = pos.checked_add(size) else {
        return Some("the entry size overflows".to_owned());
    };
    if end > b.len() {
        return Some("the entry is past the end of the log".to_owned());
    }
    let hbins = u32_at(b, pos + 16).unwrap_or(0);
    if hbins < HBIN_ALIGNMENT || !hbins.is_multiple_of(HBIN_ALIGNMENT) || hbins > MAX_HIVE_BINS {
        return Some(format!("invalid hive bins data size 0x{hbins:X}"));
    }
    let count = u32_at(b, pos + 20).unwrap_or(0) as usize;
    let references_end = count.checked_mul(8).and_then(|n| 40usize.checked_add(n));
    if count == 0 || references_end.is_none_or(|end| end > size) {
        return Some(format!("invalid dirty pages count {count}"));
    }
    let hash1 = u64_at(b, pos + 24).unwrap_or(0);
    let hash2 = u64_at(b, pos + 32).unwrap_or(0);
    if marvin32(&b[pos..pos + 32], MARVIN_SEED) != hash2
        || marvin32(&b[pos + 40..end], MARVIN_SEED) != hash1
    {
        return Some("invalid hashes".to_owned());
    }
    let sequence = u32_at(b, pos + 12).unwrap_or(0);
    (sequence != expected)
        .then(|| format!("sequence number {sequence} where {expected} was expected"))
}

fn dirty_pages_start(hive_bins_data_size: u32) -> usize {
    let unaligned = LOG_BASE + 4 + (hive_bins_data_size / 4096) as usize;
    unaligned.div_ceil(512) * 512
}

fn apply_old_log(st: &mut State, log: &LogFile) -> Result<(), String> {
    let b = &log.data;
    let bb = BaseBlock::new(b, false);
    if bb.last_written < st.primary.last_written {
        return Err(format!("{}: it is older than the hive", log.name));
    }
    if bb.hive_bins_data_size > MAX_HIVE_BINS {
        return Err(format!(
            "{}: invalid hive bins data size 0x{:X}",
            log.name, bb.hive_bins_data_size
        ));
    }
    let bitmap_len = (bb.hive_bins_data_size / 4096) as usize;
    let pages = dirty_pages_start(bb.hive_bins_data_size);
    let mut n = 0usize;
    for bit in 0..bitmap_len * 8 {
        let Some(byte) = b.get(LOG_BASE + 4 + bit / 8) else {
            break;
        };
        if (byte >> (bit % 8)) & 1 == 0 {
            continue;
        }
        let from = pages + n * 512;
        let Some(page) = b.get(from..from + 512) else {
            st.messages.push(format!(
                "{}: dirty page {n} is past the end of the log",
                log.name
            ));
            break;
        };
        // within the hive bins data size, which is at most 2 GiB
        if !st.write((bit * 512) as u32, page) {
            st.messages.push(format!(
                "{}: the hive could not grow for dirty page {n}",
                log.name
            ));
            break;
        }
        n += 1;
    }
    if n == 0 {
        return Err(format!(
            "{}: no dirty page could be applied, so it is not used",
            log.name
        ));
    }
    st.log_base = Some(b.get(..LOG_BASE).unwrap_or_default().to_vec());
    st.hive_bins_data_size = bb.hive_bins_data_size;
    st.flags = bb.flags;
    st.applied += 1;
    st.logs_applied.push(log.name.clone());
    st.messages.push(format!(
        "{}: applied {n} dirty pages (old format)",
        log.name
    ));
    Ok(())
}

/// The primary file's base block when it is valid, else the log's; with the sequence numbers,
/// hive bins data size and flags recovery ended with, file type 0, and its checksum.
fn finish_base_block(st: &mut State) {
    let mut base = vec![0u8; BASE];
    if st.primary.valid {
        base.copy_from_slice(&st.bytes[..BASE]);
    } else if let Some(log) = &st.log_base {
        base[..log.len()].copy_from_slice(log);
    }
    let sequence = st
        .last_sequence
        .unwrap_or_else(|| u32_at(&base, 4).unwrap_or(0));
    base[4..8].copy_from_slice(&sequence.to_le_bytes());
    base[8..12].copy_from_slice(&sequence.to_le_bytes());
    base[40..44].copy_from_slice(&st.hive_bins_data_size.to_le_bytes());
    base[144..148].copy_from_slice(&st.flags.to_le_bytes());
    base[28..32].copy_from_slice(&0u32.to_le_bytes());
    let sum = checksum(&base);
    base[508..512].copy_from_slice(&sum.to_le_bytes());
    if st.bytes.len() < BASE {
        st.bytes.resize(BASE, 0);
    }
    st.bytes[..BASE].copy_from_slice(&base);
}

/// The 64-bit Marvin32 hash (as .NET computes it).
fn marvin32(data: &[u8], seed: u64) -> u64 {
    fn block(p0: &mut u32, p1: &mut u32) {
        *p1 ^= *p0;
        *p0 = p0.rotate_left(20);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(9);
        *p1 ^= *p0;
        *p0 = p0.rotate_left(27);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(19);
    }
    let mut p0 = seed as u32;
    let mut p1 = (seed >> 32) as u32;
    let (chunks, rest) = data.as_chunks::<4>();
    for &c in chunks {
        p0 = p0.wrapping_add(u32::from_le_bytes(c));
        block(&mut p0, &mut p1);
    }
    let tail = match rest.len() {
        0 => 0x80u32,
        1 => 0x8000 | u32::from(rest[0]),
        2 => 0x80_0000 | u32::from(u16::from_le_bytes([rest[0], rest[1]])),
        _ => {
            0x8000_0000
                | (u32::from(rest[2]) << 16)
                | u32::from(u16::from_le_bytes([rest[0], rest[1]]))
        }
    };
    p0 = p0.wrapping_add(tail);
    block(&mut p0, &mut p1);
    block(&mut p0, &mut p1);
    (u64::from(p1) << 32) | u64::from(p0)
}

/// Logs built for tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A base block (`regf`) with these sequence numbers, file type and hive bins data size, and
    /// its checksum.
    pub(crate) fn base_block(
        len: usize,
        seq1: u32,
        seq2: u32,
        file_type: u32,
        hbins: u32,
        written: u64,
    ) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[..4].copy_from_slice(b"regf");
        b[4..8].copy_from_slice(&seq1.to_le_bytes());
        b[8..12].copy_from_slice(&seq2.to_le_bytes());
        b[12..20].copy_from_slice(&written.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..28].copy_from_slice(&5u32.to_le_bytes());
        b[28..32].copy_from_slice(&file_type.to_le_bytes());
        b[40..44].copy_from_slice(&hbins.to_le_bytes());
        let sum = checksum(&b);
        b[508..512].copy_from_slice(&sum.to_le_bytes());
        b
    }

    /// A dirty primary (sequence numbers 10 and 9) with one empty hive bin.
    pub(crate) fn primary() -> Vec<u8> {
        let mut p = base_block(BASE, 10, 9, 0, 4096, 100);
        let mut bin = vec![0u8; 4096];
        bin[..4].copy_from_slice(b"hbin");
        bin[8..12].copy_from_slice(&4096u32.to_le_bytes());
        p.extend(bin);
        p
    }

    /// A new-format log entry writing `pages` (offset in the hive bins, bytes), with its hashes.
    pub(crate) fn entry(seq: u32, hbins: u32, pages: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut e = vec![0u8; 40];
        e[..4].copy_from_slice(b"HvLE");
        e[12..16].copy_from_slice(&seq.to_le_bytes());
        e[16..20].copy_from_slice(&hbins.to_le_bytes());
        e[20..24].copy_from_slice(&(pages.len() as u32).to_le_bytes());
        for (offset, data) in pages {
            e.extend(offset.to_le_bytes());
            e.extend((data.len() as u32).to_le_bytes());
        }
        for (_, data) in pages {
            e.extend(data);
        }
        e.resize(e.len().div_ceil(512) * 512, 0);
        let size = e.len() as u32;
        e[4..8].copy_from_slice(&size.to_le_bytes());
        let h1 = marvin32(&e[40..], MARVIN_SEED);
        e[24..32].copy_from_slice(&h1.to_le_bytes());
        let h2 = marvin32(&e[..32], MARVIN_SEED);
        e[32..40].copy_from_slice(&h2.to_le_bytes());
        e
    }

    pub(crate) fn rehash_entry(e: &mut [u8]) {
        let h1 = marvin32(&e[40..], MARVIN_SEED);
        e[24..32].copy_from_slice(&h1.to_le_bytes());
        let h2 = marvin32(&e[..32], MARVIN_SEED);
        e[32..40].copy_from_slice(&h2.to_le_bytes());
    }

    pub(crate) fn new_log(name: &str, first: u32, entries: &[Vec<u8>]) -> LogFile {
        let mut data = base_block(LOG_BASE, first, first, 6, 4096, 200);
        for e in entries {
            data.extend(e);
        }
        LogFile {
            name: name.to_owned(),
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Read;

    use super::testing::{base_block, entry, new_log, primary, rehash_entry};

    fn page(fill: u8) -> Vec<u8> {
        vec![fill; 512]
    }

    fn at(bytes: &[u8], hbins_offset: usize) -> u8 {
        bytes[BASE + hbins_offset]
    }

    #[test]
    fn new_format_entries_in_sequence_until_one_is_not() {
        // entries 10 and 11, then an older one (5): logs reuse their space
        let log = new_log(
            "SYSTEM.LOG1",
            10,
            &[
                entry(10, 4096, &[(512, page(0xA))]),
                entry(11, 8192, &[(1024, page(0xB)), (4096, page(0xC))]),
                entry(5, 4096, &[(512, page(0xD))]),
            ],
        );
        let r = replay(primary(), &[log]);
        assert!(r.recovered);
        assert_eq!(r.last_sequence, Some(11));
        assert_eq!(
            (at(&r.bytes, 512), at(&r.bytes, 1024), at(&r.bytes, 4096)),
            (0xA, 0xB, 0xC)
        );
        // the hive grew to the last entry's hive bins data size, and its base block says so
        assert_eq!(r.bytes.len(), BASE + 4096 + 512);
        assert_eq!(u32_at(&r.bytes, 4), Some(11));
        assert_eq!(u32_at(&r.bytes, 8), Some(11));
        assert_eq!(u32_at(&r.bytes, 40), Some(8192));
        assert_eq!(u32_at(&r.bytes, 508), Some(checksum(&r.bytes)));
        assert!(
            r.messages[0].contains("applied 2 log entries (sequence numbers 10 to 11)"),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn a_damaged_entry_ends_the_log() {
        let mut bad = entry(11, 4096, &[(1024, page(0xB))]);
        bad[100] ^= 1; // its hash no longer matches
        let log = new_log(
            "SYSTEM.LOG1",
            10,
            &[
                entry(10, 4096, &[(512, page(0xA))]),
                bad,
                entry(12, 4096, &[(512, page(0xC))]),
            ],
        );
        let r = replay(primary(), &[log]);
        assert_eq!(r.last_sequence, Some(10));
        assert_eq!((at(&r.bytes, 512), at(&r.bytes, 1024)), (0xA, 0));
        let mut skipped = entry(10, 4096, &[(512, page(0xA))]);
        skipped[12..16].copy_from_slice(&12u32.to_le_bytes()); // out of sequence (hash 2 no longer matches either)
        assert!(invalid_entry(&skipped, 0, 10).is_some());
        // a header field (the flags) changed: the header's hash no longer matches
        let mut header = entry(10, 4096, &[(512, page(0xA))]);
        header[8] = 1;
        assert_eq!(
            invalid_entry(&header, 0, 10).as_deref(),
            Some("invalid hashes")
        );
        // a valid entry with the wrong sequence number
        let wrong = entry(11, 4096, &[(512, page(0xA))]);
        assert!(
            invalid_entry(&wrong, 0, 10)
                .unwrap()
                .contains("sequence number 11 where 10")
        );
        assert!(invalid_entry(&wrong, 0, 11).is_none());
    }

    #[test]
    fn dirty_pages_cannot_spill_into_the_next_entry() {
        let mut first = entry(10, 4096, &[(512, page(0xA))]);
        // The entry is 1024 bytes, and its page data begins at byte 48. Claiming 1024 bytes
        // would consume 48 bytes of the following entry. Rehashing makes the entry header and
        // its own bytes internally valid; the boundary check must still reject it.
        first[44..48].copy_from_slice(&1024u32.to_le_bytes());
        rehash_entry(&mut first);
        let second = entry(11, 4096, &[(1024, page(0xB))]);
        let log = new_log("SYSTEM.LOG1", 10, &[first, second]);
        let kept = entries(std::slice::from_ref(&log));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].sequence, Some(11));
        assert_eq!(kept[0].pages, [(1024, page(0xB))]);
        let r = replay(primary(), &[log]);
        assert!(!r.recovered, "{:?}", r.messages);
        assert_eq!((at(&r.bytes, 512), at(&r.bytes, 1024)), (0, 0));
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("past the end of the entry")),
            "{:?}",
            r.messages
        );
    }

    #[test]
    fn two_logs_the_earlier_first() {
        let log1 = new_log("SYSTEM.LOG1", 12, &[entry(12, 4096, &[(512, page(0xC))])]);
        let log2 = new_log(
            "SYSTEM.LOG2",
            10,
            &[
                entry(10, 4096, &[(512, page(0xA))]),
                entry(11, 4096, &[(1024, page(0xB))]),
            ],
        );
        let r = replay(primary(), &[log1.clone(), log2.clone()]);
        assert_eq!(r.logs_applied, ["SYSTEM.LOG2", "SYSTEM.LOG1"]);
        assert_eq!(r.last_sequence, Some(12));
        assert_eq!((at(&r.bytes, 512), at(&r.bytes, 1024)), (0xC, 0xB));
        // a second log that does not continue the first is not applied
        let later = new_log("SYSTEM.LOG1", 20, &[entry(20, 4096, &[(512, page(0xE))])]);
        let r = replay(primary(), &[later, log2]);
        assert_eq!(r.logs_applied, ["SYSTEM.LOG2"]);
        assert_eq!(at(&r.bytes, 512), 0xA);
    }

    #[test]
    fn logs_older_than_the_hive_are_not_used() {
        let log = new_log("SYSTEM.LOG1", 5, &[entry(5, 4096, &[(512, page(0xA))])]);
        let r = replay(primary(), &[log]);
        assert!(!r.recovered);
        assert!(
            r.messages[0].contains("older than the hive"),
            "{:?}",
            r.messages
        );
        // and a hive whose sequence numbers agree is not dirty
        let mut clean = primary();
        clean[8..12].copy_from_slice(&10u32.to_le_bytes());
        let sum = checksum(&clean);
        clean[508..512].copy_from_slice(&sum.to_le_bytes());
        assert!(!BaseBlock::new(&clean, true).dirty);
        assert!(BaseBlock::new(&primary(), true).dirty);
    }

    #[test]
    fn an_invalid_base_block_takes_the_log_with_the_latest_entries_and_its_base_block() {
        let mut p = primary();
        p[508] ^= 0xff;
        let log1 = new_log("SYSTEM.LOG1", 10, &[entry(10, 4096, &[(512, page(0xA))])]);
        let log2 = new_log("SYSTEM.LOG2", 11, &[entry(11, 4096, &[(1024, page(0xB))])]);
        let r = replay(p, &[log1, log2]);
        assert_eq!(r.logs_applied, ["SYSTEM.LOG2"]);
        assert_eq!((at(&r.bytes, 512), at(&r.bytes, 1024)), (0, 0xB));
        assert_eq!(u32_at(&r.bytes, 12), Some(200)); // the log's base block (its last written time)
        assert_eq!(u32_at(&r.bytes, 508), Some(checksum(&r.bytes)));
    }

    /// An old-format log: its base block, the dirty vector (`DIRT`, a bit per 512-byte sector of
    /// the hive bins), then the dirty sectors.
    /// A log entry with a byte of its pages changed after its hashes were computed.
    fn damaged(mut e: Vec<u8>) -> Vec<u8> {
        e[100] ^= 0xFF;
        e
    }

    #[test]
    fn a_log_with_no_entry_that_can_be_applied_is_not_used() {
        let log = new_log(
            "SYSTEM.LOG1",
            10,
            &[damaged(entry(10, 4096, &[(512, page(0xA))]))],
        );
        let r = replay(primary(), &[log]);
        assert!(!r.recovered, "{:?}", r.messages);
        assert_eq!(r.logs_applied, Vec::<String>::new());
        assert_eq!(r.last_sequence, None);
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("SYSTEM.LOG1: no log entry could be applied")),
            "{:?}",
            r.messages
        );
        // the hive is as it was: still dirty
        assert_eq!(r.bytes, primary());
    }

    #[test]
    fn the_other_log_is_used_when_the_earlier_one_has_no_entry_that_can_be_applied() {
        let log1 = new_log(
            "SYSTEM.LOG1",
            10,
            &[damaged(entry(10, 4096, &[(512, page(0xA))]))],
        );
        let log2 = new_log("SYSTEM.LOG2", 12, &[entry(12, 4096, &[(1024, page(0xB))])]);
        let r = replay(primary(), &[log1, log2]);
        assert!(r.recovered, "{:?}", r.messages);
        assert_eq!(r.logs_applied, ["SYSTEM.LOG2"]);
        assert_eq!(r.last_sequence, Some(12));
        assert_eq!((at(&r.bytes, 512), at(&r.bytes, 1024)), (0, 0xB));
    }

    #[test]
    fn a_dirty_page_past_the_hive_bins_is_not_written() {
        // correctly hashed, but its page is near 4 GiB in a hive of 4 KiB of hive bins
        let log = new_log(
            "SYSTEM.LOG1",
            10,
            &[entry(10, 4096, &[(0xFFFF_F000, page(0xA))])],
        );
        let r = replay(primary(), &[log]);
        assert!(!r.recovered);
        assert_eq!(r.bytes.len(), primary().len());
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("is past its hive bins data size")),
            "{:?}",
            r.messages
        );
        // and hive bins of more than 2 GiB end the log
        let log = new_log(
            "SYSTEM.LOG1",
            10,
            &[entry(10, 0xFFFF_F000, &[(0xFFFF_E000, page(0xA))])],
        );
        let r = replay(primary(), &[log]);
        assert!(!r.recovered);
        assert_eq!(r.bytes.len(), primary().len());
    }

    #[test]
    fn an_old_format_log_with_no_dirty_page_is_not_used() {
        let mut log = old_log("SYSTEM.LOG", 150, &[]);
        log.data.extend(page(0));
        let r = replay(primary(), &[log]);
        assert!(!r.recovered, "{:?}", r.messages);
        assert_eq!(r.logs_applied, Vec::<String>::new());
        assert!(
            r.messages
                .iter()
                .any(|m| m.contains("SYSTEM.LOG: no dirty page could be applied")),
            "{:?}",
            r.messages
        );
    }

    fn old_log(name: &str, written: u64, sectors: &[(usize, u8)]) -> LogFile {
        let hbins = 4096u32;
        let mut data = base_block(LOG_BASE, 10, 10, 1, hbins, written);
        data.extend(b"DIRT");
        let mut bitmap = vec![0u8; (hbins / 4096) as usize];
        for (s, _) in sectors {
            bitmap[s / 8] |= 1 << (s % 8);
        }
        data.extend(bitmap);
        data.resize(dirty_pages_start(hbins), 0);
        let mut sorted = sectors.to_vec();
        sorted.sort_unstable();
        for (_, fill) in sorted {
            data.extend(page(fill));
        }
        LogFile {
            name: name.to_owned(),
            data,
        }
    }

    #[test]
    fn old_format_logs_newer_than_the_hive() {
        let r = replay(
            primary(),
            &[old_log("SYSTEM.LOG", 150, &[(1, 0xA), (3, 0xB)])],
        );
        assert!(r.recovered);
        assert_eq!(
            (at(&r.bytes, 512), at(&r.bytes, 1536), at(&r.bytes, 1024)),
            (0xA, 0xB, 0)
        );
        assert!(
            r.messages[0].contains("applied 2 dirty pages (old format)"),
            "{:?}",
            r.messages
        );
        // of two, the newer; one older than the hive is not used
        let r = replay(
            primary(),
            &[
                old_log("SYSTEM.LOG1", 150, &[(1, 0xA)]),
                old_log("SYSTEM.LOG2", 160, &[(1, 0xB)]),
            ],
        );
        assert_eq!(at(&r.bytes, 512), 0xB);
        let r = replay(primary(), &[old_log("SYSTEM.LOG", 50, &[(1, 0xA)])]);
        assert!(!r.recovered);
    }

    #[test]
    fn marvin32_is_the_hash_windows_writes() {
        // the first entry of regipy's transactions_ntuser.dat.log1 (a test fixture)
        let gz = std::fs::File::open(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/regipy/transactions_ntuser.dat.log1.gz"
        ))
        .unwrap();
        let mut log = Vec::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_end(&mut log)
            .unwrap();
        let size = u32_at(&log, LOG_BASE + 4).unwrap() as usize;
        let e = &log[LOG_BASE..LOG_BASE + size];
        assert_eq!(marvin32(&e[..32], MARVIN_SEED), u64_at(e, 32).unwrap());
        assert_eq!(marvin32(&e[40..], MARVIN_SEED), u64_at(e, 24).unwrap());
        // every length's tail handling
        let lens: HashSet<u64> = (0..16)
            .map(|n| marvin32(&vec![7u8; n], MARVIN_SEED))
            .collect();
        assert_eq!(lens.len(), 16);
    }
}
