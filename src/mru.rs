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

//! Most-recently-used lists in `NTUSER.DAT`: what a user typed into the Run dialog, Explorer's
//! address bar and search box and Internet Explorer's address bar, the files Paint and `WordPad`
//! opened last, and Windows XP's search terms.
//!
//! Each list is a key of values, the most recent first:
//!
//! - `RunMRU` (`Explorer\RunMRU`): lettered values (`a`, `b`, …) in the order of the key's
//!   `MRUList` (a string of their letters); each a command, ending with `\1`.
//! - `TypedPaths` (`Explorer\TypedPaths`): `url1` (the most recent), `url2`, …: paths typed into
//!   Explorer's address bar.
//! - `WordWheelQuery` (`Explorer\WordWheelQuery`): numbered values in the order of the key's
//!   `MRUListEx`; each a search term (UTF-16 in `REG_BINARY`).
//! - `TypedURLs` (`Internet Explorer\TypedURLs`): `url1`, `url2`, …: addresses typed into
//!   Internet Explorer's address bar. `TypedURLsTime` (Windows 8 and later) has a value of the
//!   same name for each, the FILETIME it was typed.
//! - `Paint` and `Wordpad` (`Applets\<program>\Recent File List`): `File1` (the most recent),
//!   `File2`, …
//! - `ACMru` (`Search Assistant\ACMru`, Windows XP): a subkey per kind of search (`5603`: file
//!   names, `5604`: words or phrases in files, `5647`: computers and people, `5001`: the
//!   Internet), each with `000` (the most recent), `001`, …
//!
//! Times: a key's last-write time changes when its list is rewritten, so it dates the most recent
//! entry of the list only. `TypedURLsTime` dates each address.

use crate::bytes::{u64_at, utf16_units};
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use crate::ntuser::{mru_items, mru_list_items};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Where Explorer's lists are, under the hive's root.
const EXPLORER: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer";
/// Where `TypedURLs` and `TypedURLsTime` are, under the hive's root.
const INTERNET_EXPLORER: &str = r"Software\Microsoft\Internet Explorer";
/// Where the programs' recent file lists are, under the hive's root.
const APPLETS: &str = r"Software\Microsoft\Windows\CurrentVersion\Applets";

/// A most-recently-used list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MruList {
    /// Commands typed into the Run dialog.
    RunMru,
    /// Paths typed into Explorer's address bar.
    TypedPaths,
    /// Terms searched for in Explorer.
    WordWheelQuery,
    /// Addresses typed into Internet Explorer's address bar.
    TypedUrls,
    /// Files Paint opened last.
    Paint,
    /// Files `WordPad` opened last.
    Wordpad,
    /// Windows XP's search terms.
    AcMru,
}

impl MruList {
    /// Every list, in the order [`mru_lists`] reads them.
    pub const ALL: [MruList; 7] = [
        MruList::RunMru,
        MruList::TypedPaths,
        MruList::WordWheelQuery,
        MruList::TypedUrls,
        MruList::Paint,
        MruList::Wordpad,
        MruList::AcMru,
    ];

    /// Its name: `RunMRU`, `TypedPaths`, `WordWheelQuery`, `TypedURLs`, `Paint`, `Wordpad`,
    /// `ACMru`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            MruList::RunMru => "RunMRU",
            MruList::TypedPaths => "TypedPaths",
            MruList::WordWheelQuery => "WordWheelQuery",
            MruList::TypedUrls => "TypedURLs",
            MruList::Paint => "Paint",
            MruList::Wordpad => "Wordpad",
            MruList::AcMru => "ACMru",
        }
    }

    /// Its key, under the hive's root.
    #[must_use]
    pub fn key_path(self) -> String {
        match self {
            MruList::RunMru | MruList::TypedPaths | MruList::WordWheelQuery => {
                format!(r"{EXPLORER}\{}", self.name())
            }
            MruList::TypedUrls => format!(r"{INTERNET_EXPLORER}\TypedURLs"),
            MruList::Paint | MruList::Wordpad => {
                format!(r"{APPLETS}\{}\Recent File List", self.name())
            }
            MruList::AcMru => r"Software\Microsoft\Search Assistant\ACMru".to_owned(),
        }
    }
}

/// What a Windows XP search's `ACMru` subkey holds, by its name: `files` (`5603`: file and
/// folder names), `file_contents` (`5604`: words or phrases in files), `computers` (`5647`:
/// computers and people), `internet` (`5001`).
#[must_use]
pub fn acmru_search(subkey: &str) -> Option<&'static str> {
    match subkey {
        "5603" => Some("files"),
        "5604" => Some("file_contents"),
        "5647" => Some("computers"),
        "5001" => Some("internet"),
        _ => None,
    }
}

/// One entry of a most-recently-used list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MruEntry {
    /// The list it is in.
    pub list: MruList,
    /// The subkey it is in, for `ACMru` (`5603`, …; see [`acmru_search`]).
    pub subkey: Option<String>,
    /// The key it is in, under the hive's root.
    pub key_path: String,
    /// When the key was last written (FILETIME): when its most recent entry (`mru_position` 0)
    /// was added or used.
    pub key_last_written: u64,
    /// Its place in the list (0: the most recent): from `MRUList` or `MRUListEx`, or from the
    /// value's number (`url1`, `File1` and `000` are 0); `None` when the list doesn't have it.
    pub mru_position: Option<u32>,
    /// The value's name: `a`, `0`, `url1`, `File1`, `000`, …
    pub value_name: String,
    /// What the value holds: the command (`RunMRU`, without its `\1`), path, search term or
    /// address.
    pub value: Option<String>,
    /// When the address was typed (FILETIME), from `TypedURLsTime`.
    pub typed_time: Option<u64>,
    /// The value's data, when it doesn't decode (see `problems`).
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the value or the key's list.
    pub replayed: bool,
    /// What keeps it from being read, or puts it out of its list.
    pub problems: Vec<String>,
}

/// The entries of every list in `hive`, in the order of [`MruList::ALL`], each in its list's
/// order; and what keeps keys from being read (each starting with the key's path). `None` when
/// the hive has none of the lists' keys.
#[must_use]
pub fn mru_lists(hive: &Hive) -> Option<(Vec<MruEntry>, Vec<String>)> {
    let mut found = false;
    let mut entries = Vec::new();
    let mut problems = Vec::new();
    for list in MruList::ALL {
        let path = list.key_path();
        let Some(key) = hive.key(&path) else {
            continue;
        };
        found = true;
        if list == MruList::AcMru {
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
        } else {
            read_key(list, &key, &path, None, &mut entries, &mut problems);
        }
    }
    if let Some(times) = hive.key(&format!(r"{INTERNET_EXPLORER}\TypedURLsTime")) {
        found = true;
        typed_times(&times, &mut entries, &mut problems);
    }
    found.then_some((entries, problems))
}

/// Each value of a key, in list order: its position, name, the value, and why it is out of the
/// list.
type Ordered<'h> = Vec<(Option<u32>, String, Option<Value<'h>>, Option<String>)>;

/// The entries of one key of `list`, in list order.
fn read_key(
    list: MruList,
    key: &Key,
    path: &str,
    subkey: Option<String>,
    entries: &mut Vec<MruEntry>,
    problems: &mut Vec<String>,
) {
    let (items, list_replayed, why): (Ordered, bool, Vec<String>) = match list {
        MruList::RunMru => {
            let (items, replayed, why) = mru_list_items(key, &[]);
            let items = items
                .into_iter()
                .map(|m| (m.position, m.letter.to_string(), m.value, m.problem))
                .collect();
            (items, replayed, why)
        }
        MruList::WordWheelQuery => {
            let (items, replayed, why) = mru_items(key, &[]);
            let items = items
                .into_iter()
                .map(|m| (m.position, m.n.to_string(), m.value, m.problem))
                .collect();
            (items, replayed, why)
        }
        MruList::TypedPaths | MruList::TypedUrls => {
            let (items, why) = by_number(key, "url", 1, None);
            (items, false, why)
        }
        MruList::Paint | MruList::Wordpad => {
            let (items, why) = by_number(key, "File", 1, None);
            (items, false, why)
        }
        MruList::AcMru => {
            let (items, why) = by_number(key, "", 0, Some(3));
            (items, false, why)
        }
    };
    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
    let template = MruEntry {
        list,
        subkey,
        key_path: path.to_owned(),
        key_last_written: key.last_written(),
        mru_position: None,
        value_name: String::new(),
        value: None,
        typed_time: None,
        data_raw: None,
        replayed: list_replayed,
        problems: Vec::new(),
    };
    for (position, name, value, problem) in items {
        let mut entry = MruEntry {
            mru_position: position,
            value_name: name,
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

/// The values of `key` named `<prefix><number>` (`url1`, `File1`; with `width`, the number
/// zero-padded to it: `000`), by their numbers, the first (`first`) the most recent: their
/// positions and names, and what is wrong with the key's values. Other values are problems.
fn by_number<'h>(
    key: &Key<'h>,
    prefix: &str,
    first: u32,
    width: Option<usize>,
) -> (Ordered<'h>, Vec<String>) {
    let (values, mut problems) = key.values();
    let mut numbered: Vec<(u32, Value<'h>)> = Vec::new();
    for value in values {
        let name = value.name();
        let number = name
            .get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .and_then(|_| name.get(prefix.len()..))
            .and_then(|digits| {
                let n = digits.parse::<u32>().ok()?;
                let canonical = match width {
                    Some(width) => format!("{n:0width$}"),
                    None => n.to_string(),
                };
                (canonical == digits && n >= first).then_some(n)
            });
        match number {
            Some(n) if numbered.iter().any(|(m, _)| *m == n) => {
                problems.push(format!("value {name:?} is present more than once"));
            }
            Some(n) => numbered.push((n, value)),
            None => problems.push(format!(
                "value {name:?} is not a numbered item ({prefix}{})",
                match width {
                    Some(width) => format!("{first:0width$}"),
                    None => first.to_string(),
                }
            )),
        }
    }
    numbered.sort_by_key(|(n, _)| *n);
    let items = numbered
        .into_iter()
        .map(|(n, value)| (Some(n - first), value.name(), Some(value), None))
        .collect();
    (items, problems)
}

/// `entry`'s value, as its list stores it.
fn decode_value(entry: &mut MruEntry, value: &Value) {
    let (bytes, read_problem) = value.read_data();
    entry.replayed |= value.status() == Status::Replayed;
    let mut problems: Vec<String> = read_problem.into_iter().collect();
    let kind = value.value_type();
    let text = if entry.list == MruList::WordWheelQuery {
        if kind != ValueType::Binary {
            problems.push(format!("is {}, not REG_BINARY", kind.name()));
        }
        if !bytes.len().is_multiple_of(2) {
            problems
                .push("its term has an odd byte count: the UTF-16 data is cut short".to_owned());
        }
        let units = utf16_units(&bytes);
        if let Some(end) = units.iter().position(|&u| u == 0) {
            if units[end + 1..].iter().any(|&u| u != 0) {
                problems.push("its term has characters past its NUL".to_owned());
            }
            if String::from_utf16(&units[..end]).is_err() {
                problems.push("its term is not valid UTF-16: decoded lossily".to_owned());
            }
            Some(String::from_utf16_lossy(&units[..end]))
        } else {
            problems.push("its term has no NUL: the data is cut short".to_owned());
            None
        }
    } else {
        if !matches!(kind, ValueType::Sz | ValueType::ExpandSz) {
            problems.push(format!("is {}, not REG_SZ", kind.name()));
        }
        // read as REG_SZ whatever its type says
        match decode(1, &bytes) {
            Data::Text { value, lossy } => {
                if lossy {
                    problems.push("its text is not valid UTF-16: decoded lossily".to_owned());
                }
                Some(value)
            }
            _ => None,
        }
    };
    entry.value = text.map(|text| match entry.list {
        // the Run dialog ends each command with \1
        MruList::RunMru => match text.strip_suffix(r"\1") {
            Some(command) => command.to_owned(),
            None => text,
        },
        _ => text,
    });
    if !problems.is_empty() {
        entry.data_raw = Some(bytes);
    }
    entry.problems = problems;
}

/// `TypedURLsTime`'s FILETIMEs, put on the `TypedURLs` entries of the same names; a time
/// without its address is an entry of its own.
fn typed_times(times: &Key, entries: &mut Vec<MruEntry>, problems: &mut Vec<String>) {
    let path = format!(r"{INTERNET_EXPLORER}\TypedURLsTime");
    let (items, why) = by_number(times, "url", 1, None);
    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
    let urls: HashMap<String, usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.list == MruList::TypedUrls)
        .map(|(i, e)| (e.value_name.to_ascii_lowercase(), i))
        .collect();
    for (position, name, value, _) in items {
        let Some(value) = value else {
            continue;
        };
        let (bytes, read_problem) = value.read_data();
        let problem = read_problem
            .or_else(|| {
                (value.value_type() != ValueType::Binary)
                    .then(|| format!("is {}, not REG_BINARY", value.value_type().name()))
            })
            .or_else(|| {
                (bytes.len() != 8)
                    .then(|| format!("{} bytes, not the 8 of a FILETIME", bytes.len()))
            });
        let hex = bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        });
        let i = if let Some(&i) = urls.get(&name.to_ascii_lowercase()) {
            i
        } else {
            entries.push(MruEntry {
                list: MruList::TypedUrls,
                subkey: None,
                key_path: path.clone(),
                key_last_written: times.last_written(),
                mru_position: position,
                value_name: name.clone(),
                value: None,
                typed_time: None,
                data_raw: None,
                replayed: false,
                problems: vec![format!("TypedURLs has no {name}: only its time is there")],
            });
            entries.len() - 1
        };
        let entry = &mut entries[i];
        entry.replayed |= value.status() == Status::Replayed;
        match problem {
            Some(why) => entry.problems.push(format!("TypedURLsTime: {why} ({hex})")),
            None => entry.typed_time = u64_at(&bytes, 0).filter(|&t| t != 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_keys() {
        assert_eq!(MruList::RunMru.name(), "RunMRU");
        assert_eq!(
            MruList::Wordpad.key_path(),
            r"Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List"
        );
        assert_eq!(
            MruList::TypedUrls.key_path(),
            r"Software\Microsoft\Internet Explorer\TypedURLs"
        );
        assert_eq!(
            MruList::WordWheelQuery.key_path(),
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
        );
        assert_eq!(acmru_search("5603"), Some("files"));
        assert_eq!(acmru_search("9999"), None);
    }
}
