// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! The Open and Save As dialogs' history in `NTUSER.DAT` (`ComDlg32`): the files a user opened
//! or saved through the common dialogs, by extension, and the programs that showed the dialogs
//! with the folders they used.
//!
//! Under `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`:
//!
//! - `OpenSavePidlMRU` (Windows Vista and later): a subkey per extension (`docx`), and `*` for
//!   every extension, each with numbered values in the order of its `MRUListEx`. A value is the
//!   file's shell item list, from the desktop down.
//! - `LastVisitedPidlMRU` and `LastVisitedPidlMRULegacy`: numbered values in `MRUListEx` order. A
//!   value is a program's file name (UTF-16, up to its NUL), then the shell item list of the
//!   folder it last used the dialog in.
//! - `CIDSizeMRU`: numbered values in `MRUListEx` order. A value is a program's file name, then
//!   the dialog's size and position (not read).
//! - `FirstFolder`: numbered values in `MRUListEx` order. A value is a program's path, then a
//!   folder's path (empty when there is none), both UTF-16 up to their NUL.
//! - `OpenSaveMRU` (Windows 2000 and XP): as `OpenSavePidlMRU`, with lettered values (`a`, `b`,
//!   …) in the order of the key's `MRUList` (a string of their letters, the most recent first).
//!   A value is the file's path (`REG_SZ`).
//! - `LastVisitedMRU` (Windows 2000 and XP): lettered values in `MRUList` order. A value is a
//!   program's file name, then the folder's path, both UTF-16 up to their NUL.
//!
//! Times: a key's last-write time changes when one of its items moves to the front of its list.
//! It dates the most recent entry of that key (position 0) only.
//!
//! Shell item lists are kept as their bytes: decode them with a shell item parser (they are the
//! same as a link's target ID list).

use crate::bytes::{u16_at, utf16_units};
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use crate::ntuser::{mru_items, mru_list_items};

/// Where the common dialogs keep their history, under the hive's root.
pub const COMDLG32: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32";

/// A list of the common dialogs' history: a key under [`COMDLG32`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DialogList {
    /// `OpenSavePidlMRU`: files opened or saved, as shell item lists, by extension.
    OpenSavePidlMru,
    /// `LastVisitedPidlMRU`: programs and the folder each last used, as a shell item list.
    LastVisitedPidlMru,
    /// `LastVisitedPidlMRULegacy`: the same, for programs that use the older dialogs.
    LastVisitedPidlMruLegacy,
    /// `CIDSizeMRU`: programs that showed a dialog.
    CidSizeMru,
    /// `FirstFolder`: programs and a folder's path.
    FirstFolder,
    /// `OpenSaveMRU` (Windows 2000 and XP): files opened or saved, as paths, by extension.
    OpenSaveMru,
    /// `LastVisitedMRU` (Windows 2000 and XP): programs and the folder each last used, as a path.
    LastVisitedMru,
}

impl DialogList {
    /// Every list, in the order [`dialogs`] reads them.
    pub const ALL: [DialogList; 7] = [
        DialogList::OpenSavePidlMru,
        DialogList::LastVisitedPidlMru,
        DialogList::LastVisitedPidlMruLegacy,
        DialogList::CidSizeMru,
        DialogList::FirstFolder,
        DialogList::OpenSaveMru,
        DialogList::LastVisitedMru,
    ];

    /// Its key's name: `OpenSavePidlMRU`, …
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            DialogList::OpenSavePidlMru => "OpenSavePidlMRU",
            DialogList::LastVisitedPidlMru => "LastVisitedPidlMRU",
            DialogList::LastVisitedPidlMruLegacy => "LastVisitedPidlMRULegacy",
            DialogList::CidSizeMru => "CIDSizeMRU",
            DialogList::FirstFolder => "FirstFolder",
            DialogList::OpenSaveMru => "OpenSaveMRU",
            DialogList::LastVisitedMru => "LastVisitedMRU",
        }
    }

    /// Whether it has a subkey per extension.
    fn by_extension(self) -> bool {
        matches!(self, DialogList::OpenSavePidlMru | DialogList::OpenSaveMru)
    }

    /// Whether its values are lettered, in `MRUList` order (else numbered, in `MRUListEx`
    /// order).
    fn lettered(self) -> bool {
        matches!(self, DialogList::OpenSaveMru | DialogList::LastVisitedMru)
    }
}

/// One entry of a common dialog list: a value of its key or of an extension's subkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogEntry {
    /// The list it is in.
    pub list: DialogList,
    /// The extension subkey it is in (`docx`, `*` for every extension), for `OpenSavePidlMRU`
    /// and `OpenSaveMRU`; `None` for a value of the list's own key.
    pub extension: Option<String>,
    /// The key it is in, under the hive's root.
    pub key_path: String,
    /// When the key was last written (FILETIME): when its most recent entry (`mru_position` 0)
    /// was used.
    pub key_last_written: u64,
    /// Its place in the key's `MRUListEx` or `MRUList` (0: the most recent); `None` when the
    /// list doesn't have it.
    pub mru_position: Option<u32>,
    /// The value's name: a number (`MRUListEx`) or a letter (`MRUList`).
    pub value_name: String,
    /// The program that showed the dialog (`LastVisited…`, `CIDSizeMRU`, `FirstFolder`).
    pub program: Option<String>,
    /// A path the value holds as text: the file (`OpenSaveMRU`) or the folder (`LastVisitedMRU`,
    /// `FirstFolder`).
    pub path: Option<String>,
    /// The shell item list (`OpenSavePidlMRU`: the file; `LastVisitedPidlMRU…`: the folder), up
    /// to and with its terminating size of 0 when it has one.
    pub shell_items: Option<Vec<u8>>,
    /// The value's data, when it doesn't decode (see `problems`).
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the value or the key's list.
    pub replayed: bool,
    /// What keeps it from being read, or puts it out of its list.
    pub problems: Vec<String>,
}

/// The entries of every common dialog list in `hive`, in the order of [`DialogList::ALL`]; in
/// each list, its own key's entries, then each extension's, in list order; and what keeps keys
/// from being read (each starting with the key's path). `None` when the hive has no
/// [`COMDLG32`] key.
#[must_use]
pub fn dialogs(hive: &Hive) -> Option<(Vec<DialogEntry>, Vec<String>)> {
    let comdlg32 = hive.key(COMDLG32)?;
    let mut entries = Vec::new();
    let mut problems = Vec::new();
    for list in DialogList::ALL {
        let Some(key) = comdlg32.subkey(list.name()) else {
            continue;
        };
        let path = format!(r"{COMDLG32}\{}", list.name());
        read_key(list, &key, &path, None, &mut entries, &mut problems);
        if list.by_extension() {
            let (subkeys, why) = key.subkeys();
            problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
            for subkey in &subkeys {
                let name = subkey.name();
                let sub_path = format!(r"{path}\{name}");
                read_key(
                    list,
                    subkey,
                    &sub_path,
                    Some(name),
                    &mut entries,
                    &mut problems,
                );
            }
        }
    }
    Some((entries, problems))
}

/// The entries of one key of `list`, in list order.
fn read_key(
    list: DialogList,
    key: &Key,
    path: &str,
    extension: Option<String>,
    entries: &mut Vec<DialogEntry>,
    problems: &mut Vec<String>,
) {
    let template = DialogEntry {
        list,
        extension,
        key_path: path.to_owned(),
        key_last_written: key.last_written(),
        mru_position: None,
        value_name: String::new(),
        program: None,
        path: None,
        shell_items: None,
        data_raw: None,
        replayed: false,
        problems: Vec::new(),
    };
    // each value in list order: its position, name, the value, and why it is out of the list
    let (items, list_replayed, why) = if list.lettered() {
        let (items, replayed, why) = mru_list_items(key, &[]);
        let items: Vec<_> = items
            .into_iter()
            .map(|m| (m.position, m.letter.to_string(), m.value, m.problem))
            .collect();
        (items, replayed, why)
    } else {
        let (items, replayed, why) = mru_items(key, &[]);
        let items: Vec<_> = items
            .into_iter()
            .map(|m| (m.position, m.n.to_string(), m.value, m.problem))
            .collect();
        (items, replayed, why)
    };
    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
    for (position, name, value, problem) in items {
        let mut entry = DialogEntry {
            mru_position: position,
            value_name: name,
            replayed: list_replayed,
            ..template.clone()
        };
        if let Some(value) = value {
            decode_value(&mut entry, &value);
        }
        if let Some(problem) = problem {
            entry.problems.insert(0, problem);
        }
        entries.push(entry);
    }
}

/// `entry`'s fields from its `value`, as its list stores them.
fn decode_value(entry: &mut DialogEntry, value: &Value) {
    let (bytes, read_problem) = value.read_data();
    entry.replayed |= value.status() == Status::Replayed;
    let mut problems: Vec<String> = read_problem.into_iter().collect();
    let kind = value.value_type();
    let wanted = if entry.list == DialogList::OpenSaveMru {
        ValueType::Sz
    } else {
        ValueType::Binary
    };
    if kind != wanted && !(wanted == ValueType::Sz && kind == ValueType::ExpandSz) {
        problems.push(format!("is {}, not {}", kind.name(), wanted.name()));
    }
    match entry.list {
        DialogList::OpenSavePidlMru => {
            problems.extend(item_list_problem(&bytes));
            entry.shell_items = Some(bytes.clone());
        }
        DialogList::LastVisitedPidlMru | DialogList::LastVisitedPidlMruLegacy => {
            match text(&bytes, 0, "its program's name") {
                Ok((program, lossy, rest)) => {
                    problems.extend(lossy);
                    entry.program = Some(program);
                    let items = &bytes[rest..];
                    if items.is_empty() {
                        problems.push("no shell item list after the program's name".to_owned());
                    } else {
                        problems.extend(item_list_problem(items));
                        entry.shell_items = Some(items.to_vec());
                    }
                }
                Err(why) => problems.push(why),
            }
        }
        DialogList::CidSizeMru => match text(&bytes, 0, "its program's name") {
            Ok((program, lossy, _)) => {
                problems.extend(lossy);
                entry.program = Some(program);
            }
            Err(why) => problems.push(why),
        },
        DialogList::FirstFolder | DialogList::LastVisitedMru => {
            match text(&bytes, 0, "its program's name") {
                Ok((program, lossy, rest)) => {
                    problems.extend(lossy);
                    entry.program = Some(program);
                    if bytes[rest..].iter().any(|&b| b != 0) {
                        match text(&bytes, rest, "its folder's path") {
                            Ok((folder, lossy, _)) => {
                                problems.extend(lossy);
                                entry.path = Some(folder);
                            }
                            Err(why) => problems.push(why),
                        }
                    }
                }
                Err(why) => problems.push(why),
            }
        }
        // read as REG_SZ whatever its type says
        DialogList::OpenSaveMru => match decode(1, &bytes) {
            Data::Text { value, lossy } => {
                if lossy {
                    problems.push("its path is not valid UTF-16: decoded lossily".to_owned());
                }
                entry.path = Some(value);
            }
            _ => problems.push("its path can't be read".to_owned()),
        },
    }
    if !problems.is_empty() {
        entry.data_raw = Some(bytes);
    }
    entry.problems = problems;
}

/// The UTF-16 string at `at` in `bytes` (`what` it is), up to its NUL: the string, a problem
/// when it decodes lossily, and where what follows its NUL starts.
fn text(bytes: &[u8], at: usize, what: &str) -> Result<(String, Option<String>, usize), String> {
    let units = utf16_units(bytes.get(at..).unwrap_or_default());
    let Some(end) = units.iter().position(|&u| u == 0) else {
        return Err(format!("{what} has no NUL: the data is cut short"));
    };
    let name = &units[..end];
    let lossy = String::from_utf16(name)
        .is_err()
        .then(|| format!("{what} is not valid UTF-16: decoded lossily"));
    Ok((String::from_utf16_lossy(name), lossy, at + (end + 1) * 2))
}

/// What is wrong with a shell item list's layout: each item starts with its size (2 bytes, the
/// size included) and a size of 0 ends the list. An item cut short, a list without its end, and
/// bytes other than 0 after it are problems; `None` when it is whole.
#[must_use]
pub fn item_list_problem(list: &[u8]) -> Option<String> {
    let mut at = 0;
    while let Some(size) = u16_at(list, at).map(usize::from) {
        if size == 0 {
            let rest = &list[at + 2..];
            return rest
                .iter()
                .any(|&b| b != 0)
                .then(|| format!("{} bytes after the end of its shell item list", rest.len()));
        }
        if size < 2 {
            return Some(format!(
                "its shell item at offset {at} has a size of {size}"
            ));
        }
        if at + size > list.len() {
            return Some(format!(
                "its shell item at offset {at} of {size} bytes is cut short"
            ));
        }
        at += size;
    }
    Some("its shell item list has no end (a size of 0)".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shell item list of items with `sizes` (each filled with its size), ended.
    fn list(sizes: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        for &size in sizes {
            out.extend(size.to_le_bytes());
            out.extend(std::iter::repeat_n(size as u8, usize::from(size) - 2));
        }
        out.extend([0, 0]);
        out
    }

    #[test]
    fn shell_item_list_layouts() {
        assert_eq!(item_list_problem(&list(&[20, 25, 3])), None);
        assert_eq!(item_list_problem(&list(&[])), None);
        // zeros after the end are padding; other bytes aren't
        let mut padded = list(&[20]);
        padded.extend([0, 0, 0]);
        assert_eq!(item_list_problem(&padded), None);
        padded.push(7);
        assert_eq!(
            item_list_problem(&padded).as_deref(),
            Some("4 bytes after the end of its shell item list")
        );
        let whole = list(&[20, 30]);
        assert_eq!(
            item_list_problem(&whole[..40]).as_deref(),
            Some("its shell item at offset 20 of 30 bytes is cut short")
        );
        assert_eq!(
            item_list_problem(&whole[..50]).as_deref(),
            Some("its shell item list has no end (a size of 0)")
        );
        assert_eq!(
            item_list_problem(&[]).as_deref(),
            Some("its shell item list has no end (a size of 0)")
        );
        assert_eq!(
            item_list_problem(&[1, 0, 0, 0]).as_deref(),
            Some("its shell item at offset 0 has a size of 1")
        );
        // an odd last byte is no size
        assert_eq!(
            item_list_problem(&[20]).as_deref(),
            Some("its shell item list has no end (a size of 0)")
        );
    }

    #[test]
    fn strings_up_to_their_nul() {
        let mut bytes: Vec<u8> = "ab".encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes.extend([0, 0, 9]);
        assert_eq!(text(&bytes, 0, "x"), Ok(("ab".to_owned(), None, 6)));
        assert_eq!(
            text(&bytes, 6, "x"),
            Err("x has no NUL: the data is cut short".to_owned())
        );
        assert_eq!(
            text(&bytes, 60, "x").map(|t| t.2),
            Err("x has no NUL: the data is cut short".to_owned())
        );
        let lone = [0x00, 0xd8, 0, 0];
        assert_eq!(
            text(&lone, 0, "its program's name"),
            Ok((
                "\u{fffd}".to_owned(),
                Some("its program's name is not valid UTF-16: decoded lossily".to_owned()),
                4
            ))
        );
        assert_eq!(DialogList::CidSizeMru.name(), "CIDSizeMRU");
        assert!(DialogList::OpenSaveMru.lettered() && DialogList::OpenSaveMru.by_extension());
        assert!(!DialogList::FirstFolder.lettered() && !DialogList::FirstFolder.by_extension());
    }
}
