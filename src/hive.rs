//! A hive: its base block, and the keys and values of its hive bins. Every offset, count and
//! length is checked against the file. A list, key or value that can't be read is a problem
//! reported with what could be read, never a panic: a damaged subkey doesn't hide its siblings,
//! and a list that leads back to a key already read is read once.

use std::collections::HashSet;

use crate::bytes::{i32_at, name, u16_at, u32_at, u64_at};
use crate::data::ValueType;
use crate::log::{self, BASE, HBIN_ALIGNMENT, LogFile, Recovery};

/// Big data segments hold this much (the rest of their cell is padding).
const SEGMENT: usize = 16_344;
/// How deep subkey lists may nest (an `ri` list holds `li`, `lf` or `lh` lists).
const MAX_LIST_DEPTH: usize = 4;
/// A key node's fixed part, before its name.
pub(crate) const NK_FIXED: usize = 0x4c;
/// A value's fixed part, before its name.
pub(crate) const VK_FIXED: usize = 0x14;
/// The root key's flag.
const KEY_HIVE_ENTRY: u16 = 0x4;
/// A key name of one byte per character.
const KEY_COMP_NAME: u16 = 0x20;
/// A value name of one byte per character.
const VALUE_COMP_NAME: u16 = 0x1;
/// A value whose data is in the value itself (up to 4 bytes).
pub(crate) const DATA_IN_VALUE: u32 = 0x8000_0000;

/// A file that is not a hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// What a hive's base block records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The sequence number written before a change.
    pub primary_sequence: u32,
    /// The sequence number written after it: the two differ when Windows hadn't finished.
    pub secondary_sequence: u32,
    /// When the hive was last written (FILETIME).
    pub last_written: u64,
    /// The format's major version (1).
    pub major_version: u32,
    /// Its minor version (3 to 6; big data from 4).
    pub minor_version: u32,
    /// 0 for a hive (transaction logs are 1, 2 or 6).
    pub file_type: u32,
    /// Where the root key is.
    pub root_offset: u32,
    /// The size of the hive bins.
    pub hive_bins_data_size: u32,
    /// The checksum of the base block's first 508 bytes is right.
    pub checksum_valid: bool,
    /// The end of the hive's path as Windows recorded it (`\??\C:\Windows\System32\config\SYSTEM`,
    /// at most 31 characters).
    pub file_name: String,
}

impl Header {
    fn read(b: &[u8]) -> Self {
        let units = crate::bytes::utf16_units(b.get(0x30..0x70).unwrap_or_default());
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        Self {
            primary_sequence: u32_at(b, 4).unwrap_or(0),
            secondary_sequence: u32_at(b, 8).unwrap_or(0),
            last_written: u64_at(b, 12).unwrap_or(0),
            major_version: u32_at(b, 20).unwrap_or(0),
            minor_version: u32_at(b, 24).unwrap_or(0),
            file_type: u32_at(b, 28).unwrap_or(0),
            root_offset: u32_at(b, 36).unwrap_or(0),
            hive_bins_data_size: u32_at(b, 40).unwrap_or(0),
            checksum_valid: u32_at(b, 508) == Some(log::checksum(b)),
            file_name: String::from_utf16_lossy(&units[..end]),
        }
    }

    /// The last component of [`Header::file_name`] (`SYSTEM`, `ntuser.dat`).
    #[must_use]
    pub fn name(&self) -> &str {
        self.file_name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
    }

    /// Whether Windows hadn't finished writing the hive: its sequence numbers differ, or its
    /// checksum is wrong.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.primary_sequence != self.secondary_sequence || !self.checksum_valid
    }
}

/// Where a key or value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// In use in the hive as it is.
    Allocated,
    /// In use, from the transaction logs: the replay changed its cells.
    Replayed,
    /// In a free cell: deleted, its bytes left until the cell is used again.
    Deleted,
}

/// An open hive.
#[derive(Debug, Clone)]
pub struct Hive {
    bytes: Vec<u8>,
    /// The file as it was, when its logs changed it: what a cell is compared with.
    original: Option<Vec<u8>>,
    header: Header,
    root: u32,
}

impl Hive {
    /// Open a hive. A dirty one gets `logs` replayed over it; without logs it is read as it is,
    /// and [`Recovery::dirty`] says so.
    ///
    /// # Errors
    /// When the file is not a hive and no log gives it a base block, or it has no root key.
    pub fn open(primary: Vec<u8>, logs: &[LogFile]) -> Result<(Self, Recovery), Error> {
        let base = log::BaseBlock::new(&primary, true);
        let mut recovery = Recovery {
            dirty: base.dirty,
            ..Recovery::default()
        };
        let (bytes, original) = if base.dirty && !logs.is_empty() {
            let original = primary.clone();
            let r = log::replay(primary, logs);
            recovery.recovered = r.recovered;
            recovery.logs_applied = r.logs_applied;
            recovery.last_sequence = r.last_sequence;
            recovery.messages = r.messages;
            let original = r.recovered.then_some(original);
            (r.bytes, original)
        } else {
            (primary, None)
        };
        Ok((Self::read(bytes, original)?, recovery))
    }

    /// A hive read as it is, without its logs.
    ///
    /// # Errors
    /// When it is not a hive, or has no root key.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::read(bytes, None)
    }

    fn read(bytes: Vec<u8>, original: Option<Vec<u8>>) -> Result<Self, Error> {
        if bytes.len() < BASE || bytes.get(..4) != Some(b"regf") {
            return Err(Error("not a registry hive (no regf signature)".to_owned()));
        }
        let header = Header::read(&bytes);
        let mut hive = Self {
            root: header.root_offset,
            bytes,
            original,
            header,
        };
        if hive.key_at(hive.root).is_none() {
            // the base block's root is not a key: the key flagged as the hive's root
            hive.root = hive
                .find_root()
                .ok_or_else(|| Error("the hive has no root key".to_owned()))?;
        }
        Ok(hive)
    }

    /// The base block (after any log replay).
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The hive's bytes (after any log replay).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The root key.
    #[must_use]
    pub fn root(&self) -> Option<Key<'_>> {
        self.key_at(self.root)
    }

    /// The key at `path` under the root (`ControlSet001\Control`, names in any case), found
    /// among the subkeys that can be read.
    #[must_use]
    pub fn key(&self, path: &str) -> Option<Key<'_>> {
        let mut key = self.root()?;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            key = key.subkey(part)?;
        }
        Some(key)
    }

    /// Every key, depth first in list order, each once, with its path under the root (empty
    /// for the root itself).
    #[must_use]
    pub fn walk(&self) -> Walk<'_> {
        match self.root() {
            Some(root) => self.walk_from(root, String::new()),
            None => Walk {
                stack: Vec::new(),
                seen: HashSet::new(),
            },
        }
    }

    /// Every key from `key` (at `path`) down, as [`Hive::walk`].
    #[must_use]
    pub fn walk_from<'h>(&'h self, key: Key<'h>, path: String) -> Walk<'h> {
        Walk {
            seen: HashSet::from([key.offset]),
            stack: vec![(key, path)],
        }
    }

    pub(crate) fn minor_version(&self) -> u32 {
        self.header.minor_version
    }

    /// The data of the cell at `offset` (after its size), in use or free, as far as the file
    /// goes; `None` for an offset that is not a cell's.
    pub(crate) fn cell(&self, offset: u32) -> Option<&[u8]> {
        if !offset.is_multiple_of(8) {
            return None;
        }
        let start = BASE.checked_add(offset as usize)?;
        let size = i32_at(&self.bytes, start)?.unsigned_abs() as usize;
        if size < 8 {
            return None;
        }
        let end = start.checked_add(size)?.min(self.bytes.len());
        self.bytes.get(start + 4..end)
    }

    /// Whether the cell at `offset` is in use (its size is negative).
    pub(crate) fn in_use(&self, offset: u32) -> bool {
        i32_at(&self.bytes, BASE + offset as usize).is_some_and(|s| s < 0)
    }

    pub(crate) fn key_at(&self, offset: u32) -> Option<Key<'_>> {
        let nk = self.cell(offset)?;
        (nk.len() >= NK_FIXED && nk.get(..2) == Some(b"nk")).then_some(Key {
            hive: self,
            offset,
            nk,
        })
    }

    fn value_at(&self, offset: u32) -> Option<Value<'_>> {
        let vk = self.cell(offset)?;
        (vk.len() >= VK_FIXED && vk.get(..2) == Some(b"vk")).then_some(Value {
            hive: self,
            offset,
            vk,
        })
    }

    /// Whether the logs' replay changed the cell at `offset`, or put it past the end of the
    /// file as it was.
    pub(crate) fn replayed(&self, offset: u32) -> bool {
        let Some(original) = &self.original else {
            return false;
        };
        let start = BASE + offset as usize;
        let size = i32_at(&self.bytes, start).map_or(0, |s| s.unsigned_abs() as usize);
        let end = start.saturating_add(size.max(4)).min(self.bytes.len());
        original.get(start..end) != self.bytes.get(start..end)
    }

    /// The hive bins: where each starts and ends in the file.
    pub(crate) fn bins(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut bin = BASE;
        while self.bytes.get(bin..bin + 4) == Some(b"hbin") {
            let Some(size) = u32_at(&self.bytes, bin + 8).map(|s| s as usize) else {
                break;
            };
            if size < HBIN_ALIGNMENT as usize || !size.is_multiple_of(HBIN_ALIGNMENT as usize) {
                break;
            }
            let end = (bin + size).min(self.bytes.len());
            out.push((bin, end));
            bin += size;
        }
        out
    }

    /// The cells of the hive bins: where each starts in the file, and its size (negative in
    /// use, positive free).
    pub(crate) fn cells(&self) -> Vec<(usize, i32)> {
        let mut out = Vec::new();
        for (bin, end) in self.bins() {
            let mut cell = bin + 32;
            while cell + 8 <= end {
                let Some(size) = i32_at(&self.bytes, cell) else {
                    break;
                };
                let len = size.unsigned_abs() as usize;
                if len < 8 || !len.is_multiple_of(8) || cell + len > end {
                    break;
                }
                out.push((cell, size));
                cell += len;
            }
        }
        out
    }

    /// The key flagged as the hive's root (`KEY_HIVE_ENTRY`), in use.
    fn find_root(&self) -> Option<u32> {
        self.cells().into_iter().find_map(|(cell, size)| {
            let flags = u16_at(&self.bytes, cell + 6)?;
            (size < 0
                && self.bytes.get(cell + 4..cell + 6) == Some(b"nk")
                && flags & KEY_HIVE_ENTRY != 0)
                .then(|| u32::try_from(cell - BASE).ok())?
        })
    }
}

/// A key and its path, as [`Hive::walk`] gives them, with what keeps some of its subkeys from
/// being read.
#[derive(Debug, Clone)]
pub struct KeyEntry<'h> {
    /// The key.
    pub key: Key<'h>,
    /// Its path under the root (`ControlSet001\Services`); empty for the root.
    pub path: String,
    /// Subkeys or lists that can't be read, and keys listed again.
    pub problems: Vec<String>,
}

/// The keys of a hive, depth first: see [`Hive::walk`].
#[derive(Debug, Clone)]
pub struct Walk<'h> {
    stack: Vec<(Key<'h>, String)>,
    seen: HashSet<u32>,
}

impl<'h> Iterator for Walk<'h> {
    type Item = KeyEntry<'h>;

    fn next(&mut self) -> Option<KeyEntry<'h>> {
        let (key, path) = self.stack.pop()?;
        let (subkeys, mut problems) = key.subkeys();
        let mut children = Vec::new();
        for sub in subkeys {
            let name = sub.name();
            if !self.seen.insert(sub.offset) {
                problems.push(format!("subkey {name} is listed again (a loop)"));
                continue;
            }
            let child = if path.is_empty() {
                name
            } else {
                format!("{path}\\{name}")
            };
            children.push((sub, child));
        }
        // last first, so that they come out in list order
        self.stack.extend(children.into_iter().rev());
        Some(KeyEntry {
            key,
            path,
            problems,
        })
    }
}

/// A key.
#[derive(Debug, Clone, Copy)]
pub struct Key<'h> {
    hive: &'h Hive,
    offset: u32,
    nk: &'h [u8],
}

impl<'h> Key<'h> {
    /// Where its cell is in the hive bins.
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Its name.
    #[must_use]
    pub fn name(&self) -> String {
        key_name(self.nk)
    }

    /// When it was last written (FILETIME): when it, or its list of values or subkeys, last
    /// changed.
    #[must_use]
    pub fn last_written(&self) -> u64 {
        u64_at(self.nk, 4).unwrap_or(0)
    }

    /// Its flags (`KEY_HIVE_ENTRY` 0x4 for the root, `KEY_COMP_NAME` 0x20, ...).
    #[must_use]
    pub fn flags(&self) -> u16 {
        u16_at(self.nk, 2).unwrap_or(0)
    }

    /// Where its parent's cell is.
    #[must_use]
    pub fn parent(&self) -> u32 {
        u32_at(self.nk, 0x10).unwrap_or(u32::MAX)
    }

    /// How many subkeys it says it has.
    #[must_use]
    pub fn subkey_count(&self) -> u32 {
        u32_at(self.nk, 0x14).unwrap_or(0)
    }

    /// How many values it says it has.
    #[must_use]
    pub fn value_count(&self) -> u32 {
        u32_at(self.nk, 0x24).unwrap_or(0)
    }

    /// Its class name, when it has one.
    #[must_use]
    pub fn class_name(&self) -> Option<String> {
        let offset = u32_at(self.nk, 0x30).filter(|&o| o != u32::MAX)?;
        let len = usize::from(u16_at(self.nk, 0x4a)?);
        let cell = self.hive.cell(offset)?;
        Some(name(cell.get(..len)?, false))
    }

    /// Where it came from: in use, or from the transaction logs.
    #[must_use]
    pub fn status(&self) -> Status {
        if self.hive.replayed(self.offset) {
            Status::Replayed
        } else {
            Status::Allocated
        }
    }

    /// Its subkeys that can be read, each once, and what keeps the others from being read.
    #[must_use]
    pub fn subkeys(&self) -> (Vec<Key<'h>>, Vec<String>) {
        let count = self.subkey_count() as usize;
        let list = u32_at(self.nk, 0x1c).unwrap_or(u32::MAX);
        let mut problems = Vec::new();
        if count == 0 || list == u32::MAX {
            return (Vec::new(), problems);
        }
        let mut offsets = Vec::new();
        self.list(list, 0, &mut HashSet::new(), &mut offsets, &mut problems);
        if offsets.len() != count {
            problems.push(format!(
                "its lists hold {} subkeys, it says it has {count}",
                offsets.len()
            ));
        }
        let mut seen = HashSet::new();
        let mut keys = Vec::new();
        for o in offsets {
            if o == self.offset || !seen.insert(o) {
                problems.push(format!("subkey 0x{o:x} is listed twice"));
            } else if let Some(key) = self.hive.key_at(o) {
                keys.push(key);
            } else {
                problems.push(format!("subkey 0x{o:x} is not a key"));
            }
        }
        (keys, problems)
    }

    /// The key offsets of a subkey list: `lf` and `lh` (offset and hash), `li` (offsets), or an
    /// `ri` list of those.
    fn list(
        &self,
        offset: u32,
        depth: usize,
        seen: &mut HashSet<u32>,
        out: &mut Vec<u32>,
        problems: &mut Vec<String>,
    ) {
        if depth > MAX_LIST_DEPTH {
            problems.push(format!("subkey list 0x{offset:x} is nested too deep"));
            return;
        }
        if !seen.insert(offset) {
            problems.push(format!("subkey list 0x{offset:x} is listed again"));
            return;
        }
        let Some(cell) = self.hive.cell(offset) else {
            problems.push(format!("subkey list 0x{offset:x} can't be read"));
            return;
        };
        let (stride, nested) = match cell.get(..2) {
            Some(b"lf" | b"lh") => (8, false),
            Some(b"li") => (4, false),
            Some(b"ri") => (4, true),
            _ => {
                problems.push(format!("cell 0x{offset:x} is not a subkey list"));
                return;
            }
        };
        let count = usize::from(u16_at(cell, 2).unwrap_or(0));
        let room = cell.len().saturating_sub(4) / stride;
        if room < count {
            problems.push(format!(
                "subkey list 0x{offset:x} is cut short ({room} of {count} entries)"
            ));
        }
        for i in 0..count.min(room) {
            let Some(o) = u32_at(cell, 4 + i * stride) else {
                break;
            };
            if nested {
                self.list(o, depth + 1, seen, out, problems);
            } else {
                out.push(o);
            }
        }
    }

    /// The subkey named `name`, in any case.
    #[must_use]
    pub fn subkey(&self, name: &str) -> Option<Key<'h>> {
        let wanted = name.to_uppercase();
        self.subkeys()
            .0
            .into_iter()
            .find(|k| k.name().to_uppercase() == wanted)
    }

    /// Its values that can be read, each once, and what keeps the others from being read.
    #[must_use]
    pub fn values(&self) -> (Vec<Value<'h>>, Vec<String>) {
        let count = self.value_count() as usize;
        let list = u32_at(self.nk, 0x28).unwrap_or(u32::MAX);
        if count == 0 || list == u32::MAX {
            return (Vec::new(), Vec::new());
        }
        let Some(cell) = self.hive.cell(list) else {
            return (
                Vec::new(),
                vec![format!("value list 0x{list:x} can't be read")],
            );
        };
        let mut problems = Vec::new();
        let room = cell.len() / 4;
        if room < count {
            problems.push(format!(
                "value list 0x{list:x} is cut short ({room} of {count} values)"
            ));
        }
        let mut seen = HashSet::new();
        let mut values = Vec::new();
        for i in 0..count.min(room) {
            let Some(o) = u32_at(cell, i * 4) else {
                break;
            };
            if !seen.insert(o) {
                problems.push(format!("value 0x{o:x} is listed twice"));
            } else if let Some(value) = self.hive.value_at(o) {
                values.push(value);
            } else {
                problems.push(format!("value 0x{o:x} is not a value"));
            }
        }
        (values, problems)
    }

    /// The value named `name`, in any case (`""`: the default value).
    #[must_use]
    pub fn value(&self, name: &str) -> Option<Value<'h>> {
        let wanted = name.to_uppercase();
        self.values()
            .0
            .into_iter()
            .find(|v| v.name().to_uppercase() == wanted)
    }
}

/// A value.
#[derive(Debug, Clone, Copy)]
pub struct Value<'h> {
    hive: &'h Hive,
    offset: u32,
    vk: &'h [u8],
}

impl Value<'_> {
    /// Where its cell is in the hive bins.
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Its name; empty for the key's default value.
    #[must_use]
    pub fn name(&self) -> String {
        value_name(self.vk)
    }

    /// Its type's code (`REG_SZ` is 1).
    #[must_use]
    pub fn data_type(&self) -> u32 {
        u32_at(self.vk, 0xc).unwrap_or(0)
    }

    /// Its type.
    #[must_use]
    pub fn value_type(&self) -> ValueType {
        ValueType::from_code(self.data_type())
    }

    /// The size of its data, as it records it.
    #[must_use]
    pub fn size(&self) -> u32 {
        u32_at(self.vk, 4).unwrap_or(0) & !DATA_IN_VALUE
    }

    /// Its data, and what keeps the rest from being read (a cell that can't be read, data cut
    /// short): the bytes read are kept.
    #[must_use]
    pub fn read_data(&self) -> (Vec<u8>, Option<String>) {
        let read = read_data(self.hive, self.vk);
        (read.bytes, read.problem)
    }

    /// Its data.
    ///
    /// # Errors
    /// When it can't all be read: why.
    pub fn data(&self) -> Result<Vec<u8>, String> {
        match self.read_data() {
            (bytes, None) => Ok(bytes),
            (_, Some(problem)) => Err(problem),
        }
    }

    /// Where it came from: in use, or from the transaction logs (its cell or its data's).
    #[must_use]
    pub fn status(&self) -> Status {
        let changed = self.hive.replayed(self.offset)
            || read_data(self.hive, self.vk)
                .cells
                .iter()
                .any(|&c| self.hive.replayed(c));
        if changed {
            Status::Replayed
        } else {
            Status::Allocated
        }
    }
}

/// A key name from its `nk` record.
pub(crate) fn key_name(nk: &[u8]) -> String {
    let len = usize::from(u16_at(nk, 0x48).unwrap_or(0));
    let raw = nk.get(NK_FIXED..NK_FIXED + len).unwrap_or_default();
    name(raw, u16_at(nk, 2).unwrap_or(0) & KEY_COMP_NAME != 0)
}

/// A value name from its `vk` record.
pub(crate) fn value_name(vk: &[u8]) -> String {
    let len = usize::from(u16_at(vk, 2).unwrap_or(0));
    let raw = vk.get(VK_FIXED..VK_FIXED + len).unwrap_or_default();
    name(raw, u16_at(vk, 0x10).unwrap_or(0) & VALUE_COMP_NAME != 0)
}

/// A value's data as read.
pub(crate) struct DataRead {
    pub(crate) bytes: Vec<u8>,
    pub(crate) problem: Option<String>,
    /// The cells it was read from.
    pub(crate) cells: Vec<u32>,
}

/// The data of the value whose record is `vk`: in the value itself, in a cell, or in the
/// segments of a big data (`db`) record. Cells are read in use or free.
pub(crate) fn read_data(hive: &Hive, vk: &[u8]) -> DataRead {
    let raw = u32_at(vk, 4).unwrap_or(0);
    let offset = u32_at(vk, 8).unwrap_or(u32::MAX);
    let mut read = DataRead {
        bytes: Vec::new(),
        problem: None,
        cells: Vec::new(),
    };
    if raw & DATA_IN_VALUE != 0 {
        let len = (raw & !DATA_IN_VALUE) as usize;
        read.bytes = offset.to_le_bytes()[..len.min(4)].to_vec();
        if len > 4 {
            read.problem = Some(format!(
                "{len} bytes of data in the value itself, where 4 fit"
            ));
        }
        return read;
    }
    let len = raw as usize;
    if len == 0 {
        return read;
    }
    let Some(cell) = hive.cell(offset) else {
        read.problem = Some(format!("its data cell 0x{offset:x} can't be read"));
        return read;
    };
    read.cells.push(offset);
    if len > SEGMENT && hive.minor_version() >= 4 && cell.get(..2) == Some(b"db") {
        let count = usize::from(u16_at(cell, 2).unwrap_or(0));
        let list_offset = u32_at(cell, 4).unwrap_or(u32::MAX);
        let Some(list) = hive.cell(list_offset) else {
            read.problem = Some(format!(
                "its big data segment list 0x{list_offset:x} can't be read"
            ));
            return read;
        };
        read.cells.push(list_offset);
        for i in 0..count.min(list.len() / 4) {
            let Some(segment_offset) = u32_at(list, i * 4) else {
                break;
            };
            let Some(segment) = hive.cell(segment_offset) else {
                break;
            };
            read.cells.push(segment_offset);
            let take = (len - read.bytes.len()).min(SEGMENT).min(segment.len());
            read.bytes.extend_from_slice(&segment[..take]);
            if read.bytes.len() == len {
                break;
            }
        }
    } else {
        read.bytes = cell[..len.min(cell.len())].to_vec();
    }
    if read.bytes.len() < len {
        read.problem = Some(format!(
            "its data is cut short ({} of {len} bytes)",
            read.bytes.len()
        ));
    }
    read
}
