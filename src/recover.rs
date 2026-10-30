//! Keys and values recovered from more than the hive's free cells ([`Hive::deleted`]): from the
//! slack of cells in use (the bytes past their records, left from what the cells held before),
//! from the data past the hive bins, from the hive file as it was before its logs' replay, and
//! from the logs' entries (an entry's pages are a version of part of the hive). Each record says
//! how complete it is and where it was found; one found in several places is given once, with
//! each place.
//!
//! Slack and data past the hive bins are scanned as yarp's scanner scans them: at every even
//! offset, for a key or value record that looks like one Windows writes. A log entry's pages are
//! read over the hive as it is: a key whose path the hive no longer has, or a value it no longer
//! has or holds otherwise, is what the logs kept of an earlier version.

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::bytes::{i32_at, u16_at, u32_at, u64_at};
use crate::deleted::{DeletedKey, DeletedValue, plausible_key, plausible_value};
use crate::hive::{
    DATA_IN_VALUE, Hive, NK_FIXED, SEGMENT, VK_FIXED, key_name, read_data, value_name,
};
use crate::log::BASE;

/// How far a key's path is followed up through its parents.
const MAX_DEPTH: usize = 512;
/// How deep subkey lists are followed (an index root and its leaves).
const MAX_LIST_DEPTH: usize = 4;

/// Where a recovered key or value was found.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    /// A free cell of the hive.
    FreeCell,
    /// The slack of a cell in use: past the record it holds.
    CellSlack,
    /// The file past its hive bins.
    RemnantData,
    /// The hive file as it was before its transaction logs were replayed.
    BeforeReplay,
    /// An entry of a transaction log (its sequence number in a new-format log).
    LogEntry {
        /// The log's name.
        log: String,
        /// The entry's sequence number; `None` for an old-format log.
        sequence: Option<u32>,
    },
}

impl Source {
    /// `free_cell`, `cell_slack`, `remnant_data`, `before_replay`, or the log's name and the
    /// entry's sequence number (`SYSTEM.LOG1#1234`).
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Source::FreeCell => "free_cell".to_owned(),
            Source::CellSlack => "cell_slack".to_owned(),
            Source::RemnantData => "remnant_data".to_owned(),
            Source::BeforeReplay => "before_replay".to_owned(),
            Source::LogEntry { log, sequence } => match sequence {
                Some(n) => format!("{log}#{n}"),
                None => log.clone(),
            },
        }
    }

    /// Whether it is the hive as it was before the logs or a log entry.
    fn is_transaction_log(&self) -> bool {
        matches!(self, Source::BeforeReplay | Source::LogEntry { .. })
    }
}

/// How complete a recovered key or value is, and what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecoveredStatus {
    /// A deleted key with its whole path and every value and its data; or such a key's value.
    DeletedComplete,
    /// A deleted key whose path has `[unknown]` parts, or whose value list, values or data were
    /// lost to cells in use again; or a value of it, or a value whose data was lost.
    DeletedPartial,
    /// A deleted value no deleted key lists: its key is unknown.
    ResidualValueOnly,
    /// A key or value only the transaction logs hold (the hive before their replay, or their
    /// entries): neither the hive nor its free cells have it.
    TransactionLogRecovered,
}

impl RecoveredStatus {
    /// `deleted_complete`, `deleted_partial`, `residual_value_only`,
    /// `transaction_log_recovered`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            RecoveredStatus::DeletedComplete => "deleted_complete",
            RecoveredStatus::DeletedPartial => "deleted_partial",
            RecoveredStatus::ResidualValueOnly => "residual_value_only",
            RecoveredStatus::TransactionLogRecovered => "transaction_log_recovered",
        }
    }
}

/// A recovered value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredValue {
    /// Its name; empty for a default value.
    pub name: String,
    /// Its type's code.
    pub data_type: u32,
    /// The size of its data, as it records it.
    pub size: u32,
    /// Its data, as far as it could be read.
    pub data: Vec<u8>,
    /// Why its data couldn't all be read.
    pub problem: Option<String>,
    /// How complete it is, and what it is.
    pub status: RecoveredStatus,
    /// Where it was found.
    pub sources: Vec<Source>,
    /// Whether the logs' replay wrote its cells (a record in the hive's free cells or slack).
    pub replayed: bool,
}

/// A recovered key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredKey {
    /// Its path under the root; `[unknown]` stands for parents that couldn't be found.
    pub path: String,
    /// Whether every parent up to the root was found.
    pub path_complete: bool,
    /// Its name.
    pub name: String,
    /// When it was last written (FILETIME).
    pub last_written: u64,
    /// How complete it is, and what it is.
    pub status: RecoveredStatus,
    /// Whether a key at its path is in use in the hive: then this is an earlier version of it
    /// that the logs kept, and its values are those the hive no longer has or holds otherwise.
    pub in_use: bool,
    /// Its values that could be read.
    pub values: Vec<RecoveredValue>,
    /// Where it was found.
    pub sources: Vec<Source>,
    /// What of it was lost.
    pub problems: Vec<String>,
    /// Whether the logs' replay wrote its cell (a record in the hive's free cells or slack).
    pub replayed: bool,
}

/// Recovered keys, and values without a key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovered {
    /// Recovered keys, with their values.
    pub keys: Vec<RecoveredKey>,
    /// Recovered values whose key is unknown.
    pub values: Vec<RecoveredValue>,
}

/// Whether a value of type `code` is text (`REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`,
/// `REG_MULTI_SZ`).
fn is_text(code: u32) -> bool {
    matches!(code, 1 | 2 | 6 | 7)
}

/// Whether `data` starts as a registry record does.
fn is_record(data: &[u8]) -> bool {
    matches!(
        data.get(..2),
        Some(b"nk" | b"vk" | b"sk" | b"lf" | b"lh" | b"li" | b"ri" | b"db")
    )
}

/// A value's type and data, hashed.
fn digest(data_type: u32, data: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    data_type.hash(&mut h);
    data.hash(&mut h);
    h.finish()
}

/// What tells two recovered values apart: name, type and data.
fn value_id(v: &RecoveredValue) -> (String, u64) {
    (v.name.to_uppercase(), digest(v.data_type, &v.data))
}

/// Recovered records, each once.
#[derive(Default)]
struct Collector {
    found: Recovered,
    keys: HashMap<(String, u64, bool), usize>,
    values: HashMap<(String, u64), usize>,
}

/// `extra`'s sources added to `to`'s.
fn merge_sources(to: &mut Vec<Source>, extra: Vec<Source>) {
    for s in extra {
        if !to.contains(&s) {
            to.push(s);
        }
    }
}

/// `value` added to `values`, or its sources to the same value's.
fn merge_value(values: &mut Vec<RecoveredValue>, value: RecoveredValue) {
    let id = value_id(&value);
    match values.iter_mut().find(|v| value_id(v) == id) {
        Some(have) => {
            have.status = have.status.min(value.status);
            have.replayed |= value.replayed;
            merge_sources(&mut have.sources, value.sources);
        }
        None => values.push(value),
    }
}

impl Collector {
    fn key(&mut self, key: RecoveredKey) {
        let id = (key.path.to_uppercase(), key.last_written, key.in_use);
        let Some(&i) = self.keys.get(&id) else {
            self.keys.insert(id, self.found.keys.len());
            self.found.keys.push(key);
            return;
        };
        let have = &mut self.found.keys[i];
        // the most complete version, found in every place it was
        if key.status < have.status
            || (key.status == have.status && key.problems.len() < have.problems.len())
        {
            have.status = key.status;
            have.problems = key.problems;
            have.path_complete = key.path_complete;
        }
        have.replayed |= key.replayed;
        merge_sources(&mut have.sources, key.sources);
        for value in key.values {
            merge_value(&mut have.values, value);
        }
    }

    fn value(&mut self, value: RecoveredValue) {
        let id = value_id(&value);
        let Some(&i) = self.values.get(&id) else {
            self.values.insert(id, self.found.values.len());
            self.found.values.push(value);
            return;
        };
        let have = &mut self.found.values[i];
        have.status = have.status.min(value.status);
        have.replayed |= value.replayed;
        merge_sources(&mut have.sources, value.sources);
    }
}

/// A deleted value as a recovered one.
fn recovered_value(v: DeletedValue, status: RecoveredStatus, source: &Source) -> RecoveredValue {
    RecoveredValue {
        name: v.name,
        data_type: v.data_type,
        size: v.size,
        data: v.data,
        problem: v.problem,
        status,
        sources: vec![source.clone()],
        replayed: v.replayed,
    }
}

/// A deleted key as a recovered one, found in `source`.
fn recovered_key(k: DeletedKey, source: &Source) -> RecoveredKey {
    let logs = source.is_transaction_log();
    let value_status = |v: &DeletedValue| {
        if logs {
            RecoveredStatus::TransactionLogRecovered
        } else if k.path_complete && v.problem.is_none() {
            RecoveredStatus::DeletedComplete
        } else {
            RecoveredStatus::DeletedPartial
        }
    };
    let status = if logs {
        RecoveredStatus::TransactionLogRecovered
    } else if k.path_complete
        && k.problems.is_empty()
        && k.values.iter().all(|v| v.problem.is_none())
    {
        RecoveredStatus::DeletedComplete
    } else {
        RecoveredStatus::DeletedPartial
    };
    let values = k
        .values
        .into_iter()
        .map(|v| {
            let status = value_status(&v);
            recovered_value(v, status, source)
        })
        .collect();
    RecoveredKey {
        path: k.path,
        path_complete: k.path_complete,
        name: k.name,
        last_written: k.last_written,
        status,
        in_use: false,
        values,
        sources: vec![source.clone()],
        problems: k.problems,
        replayed: k.replayed,
    }
}

/// What the hive holds as it is: its keys' paths, its values' types and data, and which values
/// a cell belongs to (its record, or its data).
struct Index {
    paths: HashSet<String>,
    values: HashMap<(String, String), u64>,
    /// The values in use: their key's path and last-write time, and their record's offset.
    owners: Vec<(String, u64, u32)>,
    /// Cells (records and data) and the value they belong to, by offset.
    cells: Vec<(u32, usize)>,
    /// The keys' paths, by their records' offsets.
    offsets: HashMap<u32, String>,
}

impl Index {
    fn of(hive: &Hive) -> Self {
        let mut index = Index {
            paths: HashSet::new(),
            values: HashMap::new(),
            owners: Vec::new(),
            cells: Vec::new(),
            offsets: HashMap::new(),
        };
        for entry in hive.walk() {
            let path = entry.path.to_uppercase();
            for value in entry.key.values().0 {
                let read = read_data(hive, value.record(), true);
                index.values.insert(
                    (path.clone(), value.name().to_uppercase()),
                    digest(value.data_type(), &read.bytes),
                );
                let owner = index.owners.len();
                index
                    .owners
                    .push((entry.path.clone(), entry.key.last_written(), value.offset()));
                index.cells.push((value.offset(), owner));
                index.cells.extend(read.cells.iter().map(|&c| (c, owner)));
            }
            index.offsets.insert(entry.key.offset(), entry.path.clone());
            index.paths.insert(path);
        }
        index.cells.sort_unstable();
        index
    }

    /// The values whose cells are in `[from, to)` (offsets in the hive bins).
    fn owners_in(&self, from: u32, to: u32) -> impl Iterator<Item = usize> + '_ {
        let first = self.cells.partition_point(|&(c, _)| c < from);
        self.cells[first..]
            .iter()
            .take_while(move |&&(c, _)| c < to)
            .map(|&(_, owner)| owner)
    }
}

impl Hive {
    /// Every deleted key and value that can be recovered: from the free cells, the slack of
    /// cells in use, the data past the hive bins, the hive as it was before its logs' replay, and
    /// the entries of the logs it was opened with. Each is given once, with every place it was
    /// found and how complete it is.
    #[must_use]
    pub fn recover(&self) -> Recovered {
        let mut out = Collector::default();
        let deleted = self.deleted();
        let free_keys: HashSet<u32> = deleted.keys.iter().map(|k| k.offset).collect();
        for key in deleted.keys {
            out.key(recovered_key(key, &Source::FreeCell));
        }
        for value in deleted.values {
            out.value(recovered_value(
                value,
                RecoveredStatus::ResidualValueOnly,
                &Source::FreeCell,
            ));
        }
        let paths = self.paths();
        let mut regions: Vec<(usize, usize, Source)> = self
            .slack()
            .into_iter()
            .map(|(start, end)| (start, end, Source::CellSlack))
            .collect();
        let bins_end = BASE + self.header().hive_bins_data_size as usize;
        if self.bytes().len() > bins_end {
            regions.push((bins_end, self.bytes().len(), Source::RemnantData));
        }
        for (start, end, source) in regions {
            self.scan(start, end, &source, &paths, &free_keys, &mut out);
        }
        let index = Index::of(self);
        self.before_replay(&index, &mut out);
        self.log_versions(&index, &mut out);
        out.found
    }

    /// The records in `[start, end)` of the file at even offsets (slack, or data past the hive
    /// bins).
    fn scan(
        &self,
        start: usize,
        end: usize,
        source: &Source,
        paths: &HashMap<u32, String>,
        free_keys: &HashSet<u32>,
        out: &mut Collector,
    ) {
        let bytes = self.bytes();
        let end = end.min(bytes.len());
        let mut pos = start.next_multiple_of(2);
        let mut listed = HashSet::new();
        let mut values = Vec::new();
        while pos + 2 <= end {
            let rest = &bytes[pos..end];
            // a record found here is said to be in a cell 4 bytes before it
            let offset = u32::try_from(pos.saturating_sub(BASE + 4)).unwrap_or(u32::MAX);
            match rest.get(..2) {
                Some(b"nk") if plausible_key(rest) => {
                    let key = self.deleted_key(rest, offset, paths, free_keys, &mut listed);
                    out.key(recovered_key(key, source));
                    pos += (NK_FIXED + usize::from(u16_at(rest, 0x48).unwrap_or(0)))
                        .next_multiple_of(2);
                }
                Some(b"vk") if plausible_value(rest, bytes.len()) => {
                    values.push((rest, offset));
                    pos +=
                        (VK_FIXED + usize::from(u16_at(rest, 2).unwrap_or(0))).next_multiple_of(2);
                }
                _ => pos += 2,
            }
        }
        for (vk, offset) in values {
            if let Some(value) = self.deleted_value_record(vk, offset) {
                out.value(recovered_value(
                    value,
                    RecoveredStatus::ResidualValueOnly,
                    source,
                ));
            }
        }
    }

    /// The slack of the cells in use: where each starts and ends in the file (past the part of
    /// the cell its key, list, value, data, class name or security record takes).
    fn slack(&self) -> Vec<(usize, usize)> {
        let mut used: HashMap<u32, usize> = HashMap::new();
        let note = |used: &mut HashMap<u32, usize>, offset: u32, len: usize| {
            let at = used.entry(offset).or_insert(0);
            *at = (*at).max(len);
        };
        let mut lists = HashSet::new();
        for entry in self.walk() {
            let nk = entry.key.record();
            let field = |at| u32_at(nk, at).unwrap_or(u32::MAX);
            note(
                &mut used,
                entry.key.offset(),
                NK_FIXED + usize::from(u16_at(nk, 0x48).unwrap_or(0)),
            );
            if field(0x14) > 0 && field(0x14) != u32::MAX {
                self.note_list(field(0x1c), 0, &mut used, &mut lists);
            }
            if field(0x24) > 0 && field(0x24) != u32::MAX {
                note(&mut used, field(0x28), field(0x24) as usize * 4);
            }
            if field(0x30) != u32::MAX {
                note(
                    &mut used,
                    field(0x30),
                    usize::from(u16_at(nk, 0x4a).unwrap_or(0)),
                );
            }
            if let Some(sk) = self.cell(field(0x2c)).filter(|c| c.get(..2) == Some(b"sk")) {
                note(
                    &mut used,
                    field(0x2c),
                    0x14 + u32_at(sk, 0x10).unwrap_or(0) as usize,
                );
            }
            for value in entry.key.values().0 {
                let vk = value.record();
                note(
                    &mut used,
                    value.offset(),
                    VK_FIXED + usize::from(u16_at(vk, 2).unwrap_or(0)),
                );
                self.note_data(vk, &mut used);
            }
        }
        let mut regions: Vec<(usize, usize)> = used
            .into_iter()
            .filter(|&(offset, _)| self.in_use(offset))
            .filter_map(|(offset, len)| {
                let cell = self.cell(offset)?;
                let start = (BASE + offset as usize + 4 + len).next_multiple_of(2);
                let end = BASE + offset as usize + 4 + cell.len();
                (end >= start + 4).then_some((start, end))
            })
            .collect();
        regions.sort_unstable();
        regions
    }

    /// The part of a subkey list's cell (and of the lists an index root names) in use.
    fn note_list(
        &self,
        offset: u32,
        depth: usize,
        used: &mut HashMap<u32, usize>,
        seen: &mut HashSet<u32>,
    ) {
        if depth > MAX_LIST_DEPTH || !self.in_use(offset) || !seen.insert(offset) {
            return;
        }
        let Some(cell) = self.cell(offset) else {
            return;
        };
        let count = usize::from(u16_at(cell, 2).unwrap_or(0));
        let len = match cell.get(..2) {
            Some(b"lf" | b"lh") => 4 + count * 8,
            Some(b"li" | b"ri") => 4 + count * 4,
            _ => return,
        };
        let at = used.entry(offset).or_insert(0);
        *at = (*at).max(len);
        if cell.get(..2) == Some(b"ri") {
            for i in 0..count {
                if let Some(list) = u32_at(cell, 4 + i * 4) {
                    self.note_list(list, depth + 1, used, seen);
                }
            }
        }
    }

    /// The part of a value's data cells in use (one cell, or a big data record, its segment
    /// list and its segments).
    fn note_data(&self, vk: &[u8], used: &mut HashMap<u32, usize>) {
        let raw = u32_at(vk, 4).unwrap_or(0);
        let offset = u32_at(vk, 8).unwrap_or(u32::MAX);
        if raw & DATA_IN_VALUE != 0 || raw == 0 {
            return;
        }
        let mut note = |offset: u32, len: usize| {
            let at = used.entry(offset).or_insert(0);
            *at = (*at).max(len);
        };
        let len = raw as usize;
        let Some(cell) = self.cell(offset) else {
            return;
        };
        if len > SEGMENT && self.minor_version() >= 4 && cell.get(..2) == Some(b"db") {
            note(offset, 8);
            let count = usize::from(u16_at(cell, 2).unwrap_or(0));
            let list = u32_at(cell, 4).unwrap_or(u32::MAX);
            note(list, count * 4);
            let Some(segments) = self.cell(list) else {
                return;
            };
            let mut left = len;
            for i in 0..count {
                let Some(segment) = u32_at(segments, i * 4) else {
                    break;
                };
                note(segment, left.min(SEGMENT));
                left = left.saturating_sub(SEGMENT);
            }
        } else {
            note(offset, len);
        }
    }

    /// What the hive held before its logs' replay that it no longer holds: keys the replay
    /// removed, values it removed or changed, and deleted records it wrote over.
    fn before_replay(&self, index: &Index, out: &mut Collector) {
        let Some(before) = self
            .original()
            .and_then(|o| Hive::from_bytes(o.to_vec()).ok())
        else {
            return;
        };
        let source = Source::BeforeReplay;
        for entry in before.walk() {
            let upper = entry.path.to_uppercase();
            let in_use = index.paths.contains(&upper);
            let values: Vec<RecoveredValue> = entry
                .key
                .values()
                .0
                .iter()
                .filter_map(|value| {
                    let read = read_data(&before, value.record(), true);
                    let id = (upper.clone(), value.name().to_uppercase());
                    let same =
                        index.values.get(&id) == Some(&digest(value.data_type(), &read.bytes));
                    (!same).then(|| RecoveredValue {
                        name: value.name(),
                        data_type: value.data_type(),
                        size: value.size(),
                        data: read.bytes,
                        problem: read.problem,
                        status: RecoveredStatus::TransactionLogRecovered,
                        sources: vec![source.clone()],
                        replayed: false,
                    })
                })
                .collect();
            if in_use && values.is_empty() {
                continue;
            }
            out.key(RecoveredKey {
                path: entry.path,
                path_complete: true,
                name: entry.key.name(),
                last_written: entry.key.last_written(),
                status: RecoveredStatus::TransactionLogRecovered,
                in_use,
                values,
                sources: vec![source.clone()],
                problems: entry.problems,
                replayed: false,
            });
        }
        let gone = before.deleted();
        for key in gone.keys {
            out.key(recovered_key(key, &source));
        }
        for value in gone.values {
            out.value(recovered_value(
                value,
                RecoveredStatus::TransactionLogRecovered,
                &source,
            ));
        }
    }

    /// What each log entry held that the hive no longer holds: its pages written over the hive
    /// as it is, the keys and values in them read as they were then.
    fn log_versions(&self, index: &Index, out: &mut Collector) {
        if self.log_entries().is_empty() {
            return;
        }
        let mut buffer = self.bytes().to_vec();
        for entry in self.log_entries() {
            let mut saved = Vec::new();
            for (offset, page) in &entry.pages {
                let start = BASE + *offset as usize;
                let Some(old) = buffer.get(start..start + page.len()) else {
                    continue;
                };
                saved.push((start, old.to_vec()));
                buffer[start..start + page.len()].copy_from_slice(page);
            }
            let view = self.view(buffer);
            let version = Version {
                view: &view,
                hive: self,
                index,
                pages: entry
                    .pages
                    .iter()
                    .map(|(o, p)| (*o, o.saturating_add(u32::try_from(p.len()).unwrap_or(0))))
                    .collect(),
                source: Source::LogEntry {
                    log: entry.log.clone(),
                    sequence: entry.sequence,
                },
            };
            version.records(out);
            buffer = view.into_bytes();
            for (start, old) in saved.into_iter().rev() {
                buffer[start..start + old.len()].copy_from_slice(&old);
            }
        }
    }
}

/// A log entry's version of the hive: its pages written over the hive as it is.
struct Version<'a> {
    view: &'a Hive,
    hive: &'a Hive,
    index: &'a Index,
    /// The entry's pages: where each starts and ends in the hive bins.
    pages: Vec<(u32, u32)>,
    source: Source,
}

/// A value as a log entry holds it, and whether its data is the entry's.
struct ValueVersion {
    value: RecoveredValue,
    data_known: bool,
}

impl Version<'_> {
    /// Whether the cell at `offset` is as the entry holds it alongside a record whose cell is
    /// in use (`in_use`) or free: the entry wrote it, and it was then in use, or free, as the
    /// record was. A deleted record's cell reused within the entry holds something else.
    fn holds(&self, offset: u32, in_use: bool) -> bool {
        self.wrote(offset) && self.view.in_use(offset) == in_use
    }

    /// Whether the entry wrote the cell at `offset`, from its size to its end.
    fn wrote(&self, offset: u32) -> bool {
        let size = self
            .view
            .cell(offset)
            .map_or(4, |c| u32::try_from(c.len() + 4).unwrap_or(u32::MAX));
        let end = offset.saturating_add(size);
        self.pages
            .iter()
            .any(|&(start, stop)| start <= offset && end <= stop)
    }

    /// The keys and values the entry holds that the hive no longer has, or holds otherwise.
    fn records(&self, out: &mut Collector) {
        let view = self.view.bytes();
        let mut read_values = HashSet::new();
        let mut loose_values = Vec::new();
        for &(start, stop) in &self.pages {
            let end = (BASE + stop as usize).min(view.len());
            let mut pos = BASE + start as usize;
            while pos + 8 <= end {
                let size = i32_at(view, pos).unwrap_or(0).unsigned_abs() as usize;
                let o = (pos - BASE) as u32;
                // a cell as the hive has it holds nothing older
                let record = (size >= 8 && size.is_multiple_of(8))
                    .then(|| self.view.cell(o))
                    .flatten()
                    .filter(|_| {
                        self.hive.bytes().get(pos..pos + size) != view.get(pos..pos + size)
                    });
                let found = match record.and_then(|r| r.get(..2).map(|s| (r, s))) {
                    Some((nk, b"nk")) if plausible_key(nk) => {
                        self.key(o, nk, &mut read_values, out);
                        true
                    }
                    Some((vk, b"vk")) if plausible_value(vk, view.len()) => {
                        loose_values.push(o);
                        true
                    }
                    _ => false,
                };
                pos += if found { size } else { 8 };
            }
            // the values in use whose cells (record or data) the entry wrote, as they were
            for owner in self.index.owners_in(start.saturating_sub(4), stop) {
                let (path, written, vk_offset) = &self.index.owners[owner];
                if read_values.insert(*vk_offset) {
                    self.changed_value(path, *written, *vk_offset, out);
                }
            }
        }
        for o in loose_values {
            if read_values.contains(&o) {
                continue;
            }
            // a value without its key: only when its data is the entry's
            if let Some(v) = self.value(o).filter(|v| v.data_known) {
                out.value(v.value);
            }
        }
    }

    /// The key whose record (at `o`) the entry holds: a key the hive no longer has, or the
    /// values of one it has that it no longer holds as they were.
    fn key(&self, o: u32, nk: &[u8], read_values: &mut HashSet<u32>, out: &mut Collector) {
        let (path, path_complete) = self.path(o, nk);
        let upper = path.to_uppercase();
        let in_use = self.index.paths.contains(&upper);
        let mut problems = Vec::new();
        let mut values = Vec::new();
        let count = u32_at(nk, 0x24).unwrap_or(0) as usize;
        let list = u32_at(nk, 0x28).unwrap_or(u32::MAX);
        if count > 0 && list != u32::MAX {
            let in_use = self.view.in_use(o);
            match self.view.cell(list).filter(|_| self.holds(list, in_use)) {
                Some(cell) => {
                    for i in 0..count.min(cell.len() / 4) {
                        let Some(v) = u32_at(cell, i * 4) else {
                            break;
                        };
                        read_values.insert(v);
                        let Some(version) = self.value(v) else {
                            problems.push(format!("value 0x{v:x} can't be read"));
                            continue;
                        };
                        let id = (upper.clone(), version.value.name.to_uppercase());
                        let now = self.index.values.get(&id);
                        let same = if version.data_known {
                            now == Some(&digest(version.value.data_type, &version.value.data))
                        } else {
                            now.is_some()
                        };
                        if !in_use || !same {
                            values.push(version.value);
                        }
                    }
                }
                None if in_use => {}
                None => problems.push(format!(
                    "its value list 0x{list:x} is not in this log entry: its {count} values are unknown"
                )),
            }
        }
        if in_use && values.is_empty() {
            return;
        }
        out.key(RecoveredKey {
            path,
            path_complete,
            name: key_name(nk),
            last_written: u64_at(nk, 4).unwrap_or(0),
            status: RecoveredStatus::TransactionLogRecovered,
            in_use,
            values,
            sources: vec![self.source.clone()],
            problems,
            replayed: false,
        });
    }

    /// The entry's version of the value in use at `vk_offset` (of the key at `path`), when its
    /// data is the entry's and is not the value's as it is.
    fn changed_value(&self, path: &str, written: u64, vk_offset: u32, out: &mut Collector) {
        // the value then: its cell in use in the entry too
        if !self.view.in_use(vk_offset) {
            return;
        }
        let Some(version) = self.value(vk_offset).filter(|v| v.data_known) else {
            return;
        };
        let value = version.value;
        let id = (path.to_uppercase(), value.name.to_uppercase());
        if self.index.values.get(&id) == Some(&digest(value.data_type, &value.data)) {
            return;
        }
        let name = path.rsplit('\\').next().unwrap_or_default().to_owned();
        out.key(RecoveredKey {
            path: path.to_owned(),
            path_complete: true,
            name,
            last_written: written,
            status: RecoveredStatus::TransactionLogRecovered,
            in_use: true,
            values: vec![value],
            sources: vec![self.source.clone()],
            problems: Vec::new(),
            replayed: false,
        });
    }

    /// The value whose record is at `o`, as the entry holds it. Its data is the entry's when
    /// the entry wrote its data cells (or it is in the record itself); otherwise the cells may
    /// hold other data now, and it is left out.
    fn value(&self, o: u32) -> Option<ValueVersion> {
        let vk = self.view.cell(o).filter(|vk| {
            vk.get(..2) == Some(b"vk") && plausible_value(vk, self.view.bytes().len())
        })?;
        let read = read_data(self.view, vk, false);
        let in_use = self.view.in_use(o);
        let outside = read.cells.iter().find(|&&c| !self.holds(c, in_use));
        let (data, problem, data_known) = match outside {
            Some(&c) if self.wrote(c) => (
                Vec::new(),
                Some(format!(
                    "its data cell 0x{c:x} held something else then: its data is lost"
                )),
                false,
            ),
            Some(c) => (
                Vec::new(),
                Some(format!(
                    "its data cell 0x{c:x} is not in this log entry: its data then is unknown"
                )),
                false,
            ),
            // text that is a record (`nk`, `vk`, …): a cell used for something else then
            None if is_text(u32_at(vk, 0xc).unwrap_or(0)) && is_record(&read.bytes) => (
                Vec::new(),
                Some("its data cell held a registry record then: its data is lost".to_owned()),
                false,
            ),
            None => (read.bytes, read.problem, true),
        };
        Some(ValueVersion {
            value: RecoveredValue {
                name: value_name(vk),
                data_type: u32_at(vk, 0xc).unwrap_or(0),
                size: u32_at(vk, 4).unwrap_or(0) & !DATA_IN_VALUE,
                data,
                problem,
                status: RecoveredStatus::TransactionLogRecovered,
                sources: vec![self.source.clone()],
                replayed: false,
            },
            data_known,
        })
    }

    /// The path of the key whose record (at `o`) is `nk`: through the parents the entry holds,
    /// then the hive's key at a parent's offset (keys stay where they are); `[unknown]` where
    /// neither has one.
    fn path(&self, o: u32, nk: &[u8]) -> (String, bool) {
        if o == self.view.root_offset() {
            return (String::new(), true);
        }
        let mut names = vec![key_name(nk)];
        let mut seen = HashSet::new();
        let mut record = nk;
        loop {
            let parent = u32_at(record, 0x10).unwrap_or(u32::MAX);
            if parent == self.view.root_offset() {
                break;
            }
            if !self.wrote(parent) {
                if let Some(path) = self.index.offsets.get(&parent) {
                    names.push(path.clone());
                    break;
                }
                names.push("[unknown]".to_owned());
                names.reverse();
                return (names.join("\\"), false);
            }
            let next = self
                .view
                .cell(parent)
                .filter(|c| c.len() >= NK_FIXED && c.get(..2) == Some(b"nk"));
            match next {
                Some(p) if seen.insert(parent) && names.len() < MAX_DEPTH => {
                    names.push(key_name(p));
                    record = p;
                }
                _ => {
                    names.push("[unknown]".to_owned());
                    names.reverse();
                    return (names.join("\\"), false);
                }
            }
        }
        names.retain(|n| !n.is_empty());
        names.reverse();
        (names.join("\\"), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::checksum;
    use crate::log::testing::{base_block, entry, new_log};

    /// 2022-02-08T21:03:52Z.
    const WHEN: u64 = 132_888_278_320_000_000;
    /// Where the root key's cell is in the hive bins.
    const ROOT: u32 = 0x20;

    /// A key record.
    fn nk(name: &str, parent: u32, subkeys: (u32, u32), flags: u16) -> Vec<u8> {
        let mut nk = vec![0u8; NK_FIXED];
        nk[..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&flags.to_le_bytes());
        nk[4..12].copy_from_slice(&WHEN.to_le_bytes());
        nk[0x10..0x14].copy_from_slice(&parent.to_le_bytes());
        nk[0x14..0x18].copy_from_slice(&subkeys.0.to_le_bytes());
        nk[0x1c..0x20].copy_from_slice(&subkeys.1.to_le_bytes());
        for at in [0x28, 0x2c, 0x30] {
            nk[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        let len = u16::try_from(name.len()).unwrap_or(0);
        nk[0x48..0x4a].copy_from_slice(&len.to_le_bytes());
        nk.extend(name.as_bytes());
        nk
    }

    /// A hive bin whose root key has the subkeys `names`.
    fn bin(names: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[..4].copy_from_slice(b"hbin");
        b[8..12].copy_from_slice(&4096u32.to_le_bytes());
        let put = |b: &mut Vec<u8>, data: &[u8]| {
            let at = b.len();
            let size = (4 + data.len()).next_multiple_of(8);
            b.extend((-i32::try_from(size).unwrap_or(0)).to_le_bytes());
            b.extend(data);
            b.resize(at + size, 0);
            u32::try_from(at).unwrap_or(0)
        };
        let count = u32::try_from(names.len()).unwrap_or(0);
        let root = put(&mut b, &nk("ROOT", 0, (count, u32::MAX), 0x2c));
        let keys: Vec<u32> = names
            .iter()
            .map(|n| put(&mut b, &nk(n, ROOT, (0, u32::MAX), 0x20)))
            .collect();
        if !keys.is_empty() {
            let mut lf = b"lf".to_vec();
            lf.extend(u16::try_from(keys.len()).unwrap_or(0).to_le_bytes());
            for k in &keys {
                lf.extend(k.to_le_bytes());
                lf.extend([0; 4]);
            }
            let list = put(&mut b, &lf);
            let at = root as usize + 4 + 0x1c;
            b[at..at + 4].copy_from_slice(&list.to_le_bytes());
        }
        let free = 4096 - b.len();
        b.extend(i32::try_from(free).unwrap_or(0).to_le_bytes());
        b.resize(4096, 0);
        b
    }

    #[test]
    fn a_key_only_a_log_holds() {
        // a dirty hive whose log made a key (entry 10) and removed it (entry 11)
        let mut primary = base_block(BASE, 10, 9, 0, 4096, 100);
        primary[36..40].copy_from_slice(&ROOT.to_le_bytes());
        let sum = checksum(&primary);
        primary[508..512].copy_from_slice(&sum.to_le_bytes());
        primary.extend(bin(&[]));
        let log = new_log(
            "hive.LOG1",
            10,
            &[
                entry(10, 4096, &[(0, bin(&["Gone"]))]),
                entry(11, 4096, &[(0, bin(&[]))]),
            ],
        );
        let (hive, recovery) = Hive::open(primary, &[log]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(recovery.logs_applied, ["hive.LOG1"]);
        assert!(hive.key("Gone").is_none());
        let found = hive.recover();
        assert_eq!(found.keys.len(), 1);
        let gone = &found.keys[0];
        assert_eq!(
            (gone.path.as_str(), gone.path_complete, gone.in_use),
            ("Gone", true, false)
        );
        assert_eq!(gone.status, RecoveredStatus::TransactionLogRecovered);
        assert_eq!(
            gone.sources,
            [Source::LogEntry {
                log: "hive.LOG1".into(),
                sequence: Some(10)
            }]
        );
        assert_eq!(gone.sources[0].name(), "hive.LOG1#10");
        assert_eq!(gone.last_written, WHEN);
    }
}
