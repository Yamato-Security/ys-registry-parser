//! Deleted keys and values: when a key or value is deleted, Windows frees its cells, and their
//! bytes stay until the cells are used again. The free cells are scanned for key (`nk`) and value
//! (`vk`) records that look like ones Windows writes; a deleted key's path is rebuilt from its
//! parents (in use, or deleted too), and its values are read through its value list. A cell that
//! is in use again is not taken for the deleted record's: that part is reported as lost.

use std::collections::{HashMap, HashSet};

use crate::bytes::{i32_at, u16_at, u32_at, u64_at};
use crate::hive::{DATA_IN_VALUE, Hive, NK_FIXED, VK_FIXED, key_name, read_data, value_name};
use crate::log::BASE;

/// A name longer than this is not taken for one.
const MAX_NAME_CHARACTERS: usize = 1024;
/// Nor one with more NULs.
const MAX_NAME_NULS: usize = 5;
/// Nor a key that says it has more subkeys or values.
const MAX_COUNT: u32 = 65_536;
/// Nor one last written before 1970 or after 2100 (FILETIMEs).
const EARLIEST: u64 = 116_444_736_000_000_000;
const LATEST: u64 = 157_469_184_000_000_000;
/// How far a deleted key's path is followed up through deleted parents.
const MAX_DEPTH: usize = 512;

/// The deleted keys and values found in a hive's free cells.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deleted {
    /// Deleted keys, in the order of their cells.
    pub keys: Vec<DeletedKey>,
    /// Deleted values that no deleted key lists: their key is unknown.
    pub values: Vec<DeletedValue>,
}

/// A deleted key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedKey {
    /// Where its cell is in the hive bins.
    pub offset: u32,
    /// Its name.
    pub name: String,
    /// When it was last written (FILETIME).
    pub last_written: u64,
    /// Its path under the root, from its parents (in use, or deleted too); `[unknown]` stands
    /// for parents that couldn't be found.
    pub path: String,
    /// Whether every parent up to the root was found.
    pub path_complete: bool,
    /// Its values that could be read.
    pub values: Vec<DeletedValue>,
    /// What of it was lost: a value list or value whose cell is in use again or can't be read.
    pub problems: Vec<String>,
    /// Whether the transaction logs' replay wrote its cell.
    pub replayed: bool,
}

/// A deleted value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedValue {
    /// Where its cell is in the hive bins.
    pub offset: u32,
    /// Its name; empty for a default value.
    pub name: String,
    /// Its type's code.
    pub data_type: u32,
    /// The size of its data, as it records it.
    pub size: u32,
    /// Its data, as far as it could be read; empty when its cells are in use again.
    pub data: Vec<u8>,
    /// Why its data couldn't all be read.
    pub problem: Option<String>,
    /// Whether the transaction logs' replay wrote its cell or its data's.
    pub replayed: bool,
}

impl Hive {
    /// The deleted keys and values in the hive's free cells.
    #[must_use]
    pub fn deleted(&self) -> Deleted {
        let bytes = self.bytes();
        // where the records in free cells are: each cell, then the old cells in it (a free cell
        // takes in the free cells around it, whose headers stay)
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for (cell, size) in self.cells() {
            if size < 0 {
                continue;
            }
            let end = cell + size.unsigned_abs() as usize;
            let mut at = cell;
            while at + 8 <= end {
                let old = i32_at(bytes, at)
                    .map(|s| s.unsigned_abs() as usize)
                    .filter(|&s| s >= 8 && at + s <= end)
                    .unwrap_or(end - at);
                let record = &bytes[at + 4..at + old];
                let offset = u32::try_from(at - BASE).unwrap_or(u32::MAX);
                // past a record found: its own length (a free cell holds more after its first)
                let found = match record.get(..2) {
                    Some(b"nk") if plausible_key(record) => {
                        keys.push(offset);
                        NK_FIXED + usize::from(u16_at(record, 0x48).unwrap_or(0))
                    }
                    Some(b"vk") if plausible_value(record, bytes.len()) => {
                        values.push(offset);
                        VK_FIXED + usize::from(u16_at(record, 2).unwrap_or(0))
                    }
                    _ => 0,
                };
                at += (4 + found).next_multiple_of(8);
            }
        }
        let paths: HashMap<u32, String> = self
            .walk()
            .map(|entry| (entry.key.offset(), entry.path))
            .collect();
        let deleted_keys: HashSet<u32> = keys.iter().copied().collect();
        let mut listed = HashSet::new();
        let keys: Vec<DeletedKey> = keys
            .into_iter()
            .filter_map(|offset| {
                let nk = self.cell(offset)?;
                let (path, path_complete) = self.deleted_path(offset, &paths, &deleted_keys);
                let mut key = DeletedKey {
                    offset,
                    name: key_name(nk),
                    last_written: u64_at(nk, 4).unwrap_or(0),
                    path,
                    path_complete,
                    values: Vec::new(),
                    problems: Vec::new(),
                    replayed: self.replayed(offset),
                };
                self.deleted_values(nk, &mut key, &mut listed);
                Some(key)
            })
            .collect();
        let values = values
            .into_iter()
            .filter(|offset| !listed.contains(offset))
            .filter_map(|offset| self.deleted_value(offset))
            .collect();
        Deleted { keys, values }
    }

    /// The path of the deleted key at `offset`, from its parents, and whether all were found.
    fn deleted_path(
        &self,
        offset: u32,
        paths: &HashMap<u32, String>,
        deleted: &HashSet<u32>,
    ) -> (String, bool) {
        let mut names = Vec::new();
        let mut at = offset;
        let mut seen = HashSet::new();
        while let Some(nk) = self.cell(at) {
            names.push(key_name(nk));
            let parent = u32_at(nk, 0x10).unwrap_or(u32::MAX);
            if let Some(path) = paths.get(&parent) {
                if !path.is_empty() {
                    names.push(path.clone());
                }
                names.reverse();
                return (names.join("\\"), true);
            }
            if !deleted.contains(&parent) || !seen.insert(parent) || names.len() > MAX_DEPTH {
                break;
            }
            at = parent;
        }
        names.push("[unknown]".to_owned());
        names.reverse();
        (names.join("\\"), false)
    }

    /// The values of the deleted key whose record is `nk`, through its value list; the values
    /// read are added to `listed`.
    fn deleted_values(&self, nk: &[u8], key: &mut DeletedKey, listed: &mut HashSet<u32>) {
        let count = u32_at(nk, 0x24).unwrap_or(0) as usize;
        let list = u32_at(nk, 0x28).unwrap_or(u32::MAX);
        if count == 0 || list == u32::MAX {
            return;
        }
        if self.in_use(list) {
            key.problems.push(format!(
                "its value list 0x{list:x} is in use again: its {count} values are lost"
            ));
            return;
        }
        let Some(cell) = self.cell(list) else {
            key.problems
                .push(format!("its value list 0x{list:x} can't be read"));
            return;
        };
        for i in 0..count.min(cell.len() / 4) {
            let Some(offset) = u32_at(cell, i * 4) else {
                break;
            };
            if self.in_use(offset) {
                key.problems
                    .push(format!("value 0x{offset:x} is in use again"));
                continue;
            }
            match self.deleted_value(offset) {
                Some(value) => {
                    listed.insert(offset);
                    key.values.push(value);
                }
                None => key
                    .problems
                    .push(format!("value 0x{offset:x} is no longer a value")),
            }
        }
    }

    /// The deleted value at `offset`, when its cell holds a value record.
    fn deleted_value(&self, offset: u32) -> Option<DeletedValue> {
        let vk = self
            .cell(offset)
            .filter(|vk| vk.get(..2) == Some(b"vk") && plausible_value(vk, self.bytes().len()))?;
        let read = read_data(self, vk);
        let replayed = self.replayed(offset) || read.cells.iter().any(|&c| self.replayed(c));
        let reused = read.cells.iter().find(|&&c| self.in_use(c));
        let (data, problem) = match reused {
            Some(c) => (
                Vec::new(),
                Some(format!("its data cell 0x{c:x} is in use again")),
            ),
            None => (read.bytes, read.problem),
        };
        Some(DeletedValue {
            offset,
            name: value_name(vk),
            data_type: u32_at(vk, 0xc).unwrap_or(0),
            size: u32_at(vk, 4).unwrap_or(0) & !DATA_IN_VALUE,
            data,
            problem,
            replayed,
        })
    }
}

/// Whether a name looks like one Windows writes.
fn plausible_name(name: &str) -> bool {
    name.chars().count() <= MAX_NAME_CHARACTERS
        && !name.contains('\u{fffd}')
        && name.matches('\0').count() <= MAX_NAME_NULS
}

/// Whether an `nk` record looks like one Windows writes.
fn plausible_key(nk: &[u8]) -> bool {
    let len = usize::from(u16_at(nk, 0x48).unwrap_or(0));
    nk.len() >= NK_FIXED
        && len > 0
        && NK_FIXED + len <= nk.len()
        && u64_at(nk, 4).is_some_and(|t| (EARLIEST..=LATEST).contains(&t))
        && u32_at(nk, 0x14).is_some_and(|n| n <= MAX_COUNT)
        && u32_at(nk, 0x24).is_some_and(|n| n <= MAX_COUNT)
        && plausible_name(&key_name(nk))
}

/// Whether a `vk` record looks like one Windows writes, in a hive of `hive_len` bytes.
fn plausible_value(vk: &[u8], hive_len: usize) -> bool {
    let len = usize::from(u16_at(vk, 2).unwrap_or(0));
    let raw = u32_at(vk, 4).unwrap_or(0);
    let offset = u32_at(vk, 8).unwrap_or(u32::MAX);
    let data_fits = if raw & DATA_IN_VALUE != 0 {
        raw & !DATA_IN_VALUE <= 4
    } else {
        raw == 0 || (offset.is_multiple_of(8) && (raw as usize) < hive_len)
    };
    vk.len() >= VK_FIXED
        && VK_FIXED + len <= vk.len()
        && data_fits
        && plausible_name(&value_name(vk))
}
