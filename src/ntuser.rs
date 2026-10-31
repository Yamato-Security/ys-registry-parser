//! `NTUSER.DAT` hives: Explorer's recent documents (`RecentDocs`, in the order of its
//! `MRUListEx`), and the name of the profile a hive belongs to.
//!
//! A `RecentDocs` value is the item's name (UTF-16, up to its NUL), then a shell item list
//! whose first item is the file entry of the shortcut Windows made in the `Recent` folder: an
//! 8.3 or ANSI name, and in its `0xBEEF0004` extension block the long name. An `MRUListEx` is
//! the values' numbers, 4 bytes each, the most recent first, ending with `0xFFFFFFFF`.

use crate::bytes::{u16_at, u32_at, utf16_units};
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use std::collections::HashSet;

/// Where Explorer keeps the recent documents, under the hive's root.
pub const RECENT_DOCS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";
/// Where Explorer keeps the profile's folders, under the hive's root.
const SHELL_FOLDERS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";
/// The end of an `MRUListEx`.
const MRU_END: u32 = u32::MAX;
/// The signature of a file entry's extension block.
const BEEF0004: u32 = 0xbeef_0004;

/// An `MRUListEx` value's bytes: the numbers of the values, most recent first, without the
/// end marker.
///
/// # Errors
/// When its size is not a multiple of 4 or it has no end marker; the numbers read are given
/// with the error.
pub fn mru_list_ex(bytes: &[u8]) -> Result<Vec<u32>, (Vec<u32>, String)> {
    let mut list = Vec::new();
    for (i, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let n = u32::from_le_bytes(*chunk);
        if n == MRU_END {
            let rest = bytes.len() - (i + 1) * 4;
            return if rest == 0 || bytes[(i + 1) * 4..].iter().all(|&b| b == 0) {
                Ok(list)
            } else {
                Err((list, format!("{rest} bytes past its end marker")))
            };
        }
        list.push(n);
    }
    let why = if bytes.len().is_multiple_of(4) {
        "it has no end marker (0xFFFFFFFF)".to_owned()
    } else {
        format!("{} bytes are not a list of 4-byte numbers", bytes.len())
    };
    Err((list, why))
}

/// A `RecentDocs` value's data: the item's name, the name of its shortcut in the `Recent`
/// folder, and what keeps either from being read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecentDocData {
    /// The item's name: a file's or a folder's.
    pub name: Option<String>,
    /// The name of the shortcut (`report.docx.lnk`): the long name of the shell item's
    /// extension block, else its short name.
    pub link_name: Option<String>,
    /// What keeps them from being read.
    pub problems: Vec<String>,
}

/// A `RecentDocs` value's bytes, decoded.
#[must_use]
pub fn recent_doc_data(bytes: &[u8]) -> RecentDocData {
    let mut data = RecentDocData::default();
    let units = utf16_units(bytes);
    let Some(end) = units.iter().position(|&u| u == 0) else {
        data.problems
            .push("its name has no NUL: the data is cut short".to_owned());
        data.name = Some(String::from_utf16_lossy(&units));
        return data;
    };
    let name = &units[..end];
    if String::from_utf16(name).is_err() {
        data.problems
            .push("its name is not valid UTF-16: decoded lossily".to_owned());
    }
    data.name = Some(String::from_utf16_lossy(name));
    let items = &bytes[(end + 1) * 2..];
    if items.len() < 2 || u16_at(items, 0) == Some(0) {
        return data;
    }
    match link_name(items) {
        Ok((name, problems)) => {
            data.link_name = name;
            data.problems.extend(problems);
        }
        Err(why) => data.problems.push(why),
    }
    data
}

/// The name in the first shell item of `items`, a file entry: its long name, else its short
/// one.
fn link_name(items: &[u8]) -> Result<(Option<String>, Vec<String>), String> {
    let size = usize::from(u16_at(items, 0).unwrap_or(0));
    let item = items
        .get(..size)
        .filter(|_| size >= 14)
        .ok_or_else(|| format!("its shell item of {size} bytes is cut short or too small"))?;
    let kind = item[2];
    if kind & 0x70 != 0x30 {
        return Err(format!(
            "its shell item is of type 0x{kind:02x}, not a file entry"
        ));
    }
    // the primary name: UTF-16 when the type says so, else ANSI; then 2-byte aligned
    let mut problems = Vec::new();
    let (short, after) = if kind == 0xb1 || kind & 0x04 != 0 {
        let units = utf16_units(&item[14..]);
        let Some(end) = units.iter().position(|&u| u == 0) else {
            return Err("its shell item's UTF-16 name has no NUL: it is cut short".to_owned());
        };
        let name = &units[..end];
        if String::from_utf16(name).is_err() {
            problems.push("its shell item's name is not valid UTF-16: decoded lossily".to_owned());
        }
        (String::from_utf16_lossy(name), 14 + (end + 1) * 2)
    } else {
        let Some(end) = item[14..].iter().position(|&b| b == 0) else {
            return Err("its shell item's ANSI name has no NUL: it is cut short".to_owned());
        };
        let ansi: String = item[14..14 + end].iter().map(|&b| char::from(b)).collect();
        (ansi, (14 + end + 1).next_multiple_of(2))
    };
    let (long, long_problems) = long_name(item, after);
    problems.extend(long_problems);
    let name = long.filter(|name| !name.is_empty()).unwrap_or(short);
    Ok(((!name.is_empty()).then_some(name), problems))
}

/// The long name in a file entry's `0xBEEF0004` extension block after `start`, and malformed
/// extension blocks. Other extension blocks may come before it.
fn long_name(item: &[u8], start: usize) -> (Option<String>, Vec<String>) {
    if item.get(start..).is_none() {
        return (None, Vec::new());
    }
    let mut problems = Vec::new();
    let mut block_at = start;
    while let Some(size) = u16_at(item, block_at).map(usize::from) {
        if size == 0 {
            break;
        }
        let Some(end) = block_at.checked_add(size) else {
            problems.push(format!(
                "its extension block of {size} bytes has an invalid size"
            ));
            break;
        };
        let Some(block) = item.get(block_at..end) else {
            problems.push(format!("its extension block of {size} bytes is cut short"));
            break;
        };
        if size < 8 {
            problems.push(format!("its extension block is only {size} bytes"));
            break;
        }
        if u32_at(block, 4) != Some(BEEF0004) {
            block_at = end;
            continue;
        }
        let version = u16_at(block, 2).unwrap_or(0);
        if version < 3 {
            problems.push(format!(
                "its 0xBEEF0004 extension block has unsupported version {version}"
            ));
            block_at = end;
            continue;
        }
        // creation and access times and the version identifier; from version 7 a file reference
        // and more; the long string size; from version 9 and 8, 4 bytes each
        let mut name_at = if version >= 7 { 36 } else { 18 } + 2;
        if version >= 9 {
            name_at += 4;
        }
        if version >= 8 {
            name_at += 4;
        }
        // the last 2 bytes are the block's version offset
        let Some(name_bytes) = size.checked_sub(2).and_then(|end| block.get(name_at..end)) else {
            problems.push(format!(
                "its version {version} 0xBEEF0004 extension block is cut short"
            ));
            block_at = end;
            continue;
        };
        let units = utf16_units(name_bytes);
        let Some(end) = units.iter().position(|&u| u == 0) else {
            problems.push(format!(
                "its version {version} 0xBEEF0004 long name has no NUL"
            ));
            block_at = end;
            continue;
        };
        let name = &units[..end];
        if String::from_utf16(name).is_err() {
            problems
                .push("its 0xBEEF0004 long name is not valid UTF-16: decoded lossily".to_owned());
        }
        return (Some(String::from_utf16_lossy(name)), problems);
    }
    (None, problems)
}

/// The recent documents of one key: `RecentDocs` itself (every type), or one of its subkeys
/// (one extension, `Folder`, …).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecentDocs {
    /// `None` for `RecentDocs` itself; the subkey's name (`.docx`, `Folder`) for the others.
    pub extension: Option<String>,
    /// When the key was last written (FILETIME): when its most recent item was opened.
    pub last_written: u64,
    /// Its items: in the order of `MRUListEx`, then those it doesn't list.
    pub items: Vec<RecentDoc>,
    /// What keeps the key's list from being read (`MRUListEx` missing or damaged, values that
    /// can't be read).
    pub problems: Vec<String>,
}

/// One recent document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecentDoc {
    /// Its place in `MRUListEx` (0: the most recent); `None` when the list doesn't name it.
    pub mru_position: Option<u32>,
    /// The number of its value (the value's name).
    pub value_index: u32,
    /// The item's name.
    pub name: Option<String>,
    /// The name of its shortcut in the `Recent` folder.
    pub link_name: Option<String>,
    /// Its bytes, when they don't decode.
    pub raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote its value or the key's `MRUListEx`.
    pub replayed: bool,
    /// What keeps it from being read.
    pub problems: Vec<String>,
}

/// The recent documents of `hive`: `RecentDocs` and each of its subkeys, and what keeps
/// subkeys from being read; `None` when the hive has no `RecentDocs` key.
#[must_use]
pub fn recent_docs(hive: &Hive) -> Option<(Vec<RecentDocs>, Vec<String>)> {
    let key = hive.key(RECENT_DOCS)?;
    let (subkeys, problems) = key.subkeys();
    let mut lists = vec![recent_docs_of(&key, None)];
    lists.extend(subkeys.iter().map(|k| recent_docs_of(k, Some(k.name()))));
    Some((lists, problems))
}

/// The recent documents of one key.
fn recent_docs_of(key: &Key, extension: Option<String>) -> RecentDocs {
    let (values, mut problems) = key.values();
    let mut order: Option<(Vec<u32>, bool)> = None;
    let mut numbered: Vec<(u32, &Value)> = Vec::new();
    for value in &values {
        let name = value.name();
        if name.eq_ignore_ascii_case("MRUListEx") {
            let (bytes, problem) = value.read_data();
            let mut list = match mru_list_ex(&bytes) {
                Ok(list) => list,
                Err((list, why)) => {
                    problems.push(format!("MRUListEx: {why}"));
                    list
                }
            };
            if let Some(why) = problem {
                problems.push(format!("MRUListEx: {why}"));
            }
            if value.value_type() != ValueType::Binary {
                problems.push(format!(
                    "MRUListEx: is {}, not REG_BINARY",
                    value.value_type().name()
                ));
            }
            let mut seen = HashSet::new();
            list.retain(|n| {
                let first = seen.insert(*n);
                if !first {
                    problems.push(format!("MRUListEx: {n} is listed twice"));
                }
                first
            });
            if order.is_some() {
                problems.push("MRUListEx is present more than once".to_owned());
            } else {
                order = Some((list, value.status() == Status::Replayed));
            }
        } else if let Ok(n) = name.parse::<u32>()
            && n.to_string() == name
        {
            if numbered.iter().any(|(other, _)| *other == n) {
                problems.push(format!("numbered value {n} is present more than once"));
            }
            numbered.push((n, value));
        } else {
            problems.push(format!("value {name:?} is not a numbered item"));
        }
    }
    let (order, list_replayed) = order.unwrap_or_else(|| {
        if !numbered.is_empty() {
            problems.push("it has no MRUListEx: its items' order is unknown".to_owned());
        }
        (Vec::new(), false)
    });
    let order_set: HashSet<u32> = order.iter().copied().collect();
    let mut used: HashSet<usize> = HashSet::new();
    let mut items = Vec::new();
    for (position, &n) in order.iter().enumerate() {
        let position = u32::try_from(position).ok();
        match numbered
            .iter()
            .enumerate()
            .find(|(at, (m, _))| *m == n && !used.contains(at))
        {
            Some((at, (_, value))) => {
                used.insert(at);
                items.push(item(value, n, position, list_replayed));
            }
            None => items.push(RecentDoc {
                mru_position: position,
                value_index: n,
                replayed: list_replayed,
                problems: vec![format!("MRUListEx lists value {n}, which is not there")],
                ..RecentDoc::default()
            }),
        }
    }
    for (at, (n, value)) in numbered.iter().enumerate() {
        if !used.contains(&at) {
            let mut doc = item(value, *n, None, list_replayed);
            let problem = if order_set.contains(n) {
                format!("another value named {n} already occupies its MRUListEx position")
            } else {
                "MRUListEx doesn't list it".to_owned()
            };
            doc.problems.insert(0, problem);
            items.push(doc);
        }
    }
    RecentDocs {
        extension,
        last_written: key.last_written(),
        items,
        problems,
    }
}

/// The recent document in value `n`.
fn item(value: &Value, n: u32, position: Option<u32>, list_replayed: bool) -> RecentDoc {
    let (bytes, problem) = value.read_data();
    let data = recent_doc_data(&bytes);
    let mut problems = Vec::new();
    if value.value_type() != ValueType::Binary {
        problems.push(format!("is {}, not REG_BINARY", value.value_type().name()));
    }
    problems.extend(problem);
    problems.extend(data.problems);
    RecentDoc {
        mru_position: position,
        value_index: n,
        name: data.name,
        link_name: data.link_name,
        raw: (!problems.is_empty()).then_some(bytes),
        replayed: list_replayed || value.status() == Status::Replayed,
        problems,
    }
}

/// The name of the profile folder an `NTUSER.DAT` belongs to (`alice` for `C:\Users\alice`),
/// from the paths of its shell folders (`Local AppData` first: it is never redirected).
#[must_use]
pub fn profile_name(hive: &Hive) -> Option<String> {
    let key = hive.key(SHELL_FOLDERS)?;
    let values = key.values().0;
    let path = |value: &Value| match decode(value.data_type(), &value.data().ok()?) {
        Data::Text { value, .. } => profile_in(&value),
        _ => None,
    };
    let named = |name: &str| {
        values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case(name))
            .and_then(path)
    };
    named("Local AppData")
        .or_else(|| named("AppData"))
        .or_else(|| values.iter().find_map(path))
}

/// The SID of the user a `UsrClass.dat` belongs to, from its root key's name
/// (`S-1-5-21-…_Classes`, as Windows creates it).
#[must_use]
pub fn classes_sid(hive: &Hive) -> Option<String> {
    let name = hive.root()?.name();
    let cut = name.len().checked_sub("_Classes".len())?;
    let (sid, suffix) = (name.get(..cut)?, name.get(cut..)?);
    let digits = sid.strip_prefix("S-1-")?;
    (suffix.eq_ignore_ascii_case("_Classes")
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
    .then(|| sid.to_owned())
}

/// The profile folder's name in a path under `Users` or `Documents and Settings`.
fn profile_in(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('\\').collect();
    let at = parts.iter().position(|p| {
        p.eq_ignore_ascii_case("Users") || p.eq_ignore_ascii_case("Documents and Settings")
    })?;
    // `C:\Users\alice\…`: right under the drive
    (at == 1 && parts[0].ends_with(':'))
        .then(|| parts.get(at + 1).filter(|n| !n.is_empty()))
        .flatten()
        .map(|n| (*n).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn mru(list: &[u32]) -> Vec<u8> {
        list.iter().flat_map(|n| n.to_le_bytes()).collect()
    }

    #[test]
    fn mru_lists() {
        assert_eq!(mru_list_ex(&mru(&[2, 0, 1, MRU_END])), Ok(vec![2, 0, 1]));
        assert_eq!(mru_list_ex(&mru(&[MRU_END])), Ok(Vec::new()));
        assert_eq!(mru_list_ex(&mru(&[1, MRU_END, 0])), Ok(vec![1]));
        assert_eq!(
            mru_list_ex(&mru(&[1, 2])),
            Err((vec![1, 2], "it has no end marker (0xFFFFFFFF)".to_owned()))
        );
        assert_eq!(
            mru_list_ex(&[1, 0, 0, 0, 5]),
            Err((
                vec![1],
                "5 bytes are not a list of 4-byte numbers".to_owned()
            ))
        );
        assert_eq!(
            mru_list_ex(&mru(&[1, MRU_END, 7])),
            Err((vec![1], "4 bytes past its end marker".to_owned()))
        );
    }

    /// A file entry shell item for `short` with a version 9 extension block for `long`.
    fn file_entry(short: &str, long: &str) -> Vec<u8> {
        let mut item = vec![0u8; 14];
        item[2] = 0x32;
        item.extend_from_slice(short.as_bytes());
        item.push(0);
        if item.len() % 2 == 1 {
            item.push(0);
        }
        let mut block = Vec::new();
        block.extend_from_slice(&[0, 0, 9, 0]);
        block.extend_from_slice(&BEEF0004.to_le_bytes());
        block.extend_from_slice(&[0; 38]);
        block.extend_from_slice(&utf16(long));
        block.extend_from_slice(&[0, 0]);
        let offset = u16::try_from(item.len()).unwrap_or(0);
        block.extend_from_slice(&offset.to_le_bytes());
        let size = u16::try_from(block.len()).unwrap_or(0);
        block[..2].copy_from_slice(&size.to_le_bytes());
        item.extend_from_slice(&block);
        let size = u16::try_from(item.len()).unwrap_or(0);
        item[..2].copy_from_slice(&size.to_le_bytes());
        item.extend_from_slice(&[0, 0]);
        item
    }

    #[test]
    fn recent_doc_values() {
        let mut bytes = utf16("報告書.docx\0");
        bytes.extend(file_entry("~1.LNK", "報告書.docx.lnk"));
        assert_eq!(
            recent_doc_data(&bytes),
            RecentDocData {
                name: Some("報告書.docx".into()),
                link_name: Some("報告書.docx.lnk".into()),
                problems: Vec::new(),
            }
        );
        // no extension block: the short name
        let mut bytes = utf16("a.txt\0");
        let mut item = file_entry("A.LNK", "x");
        item.truncate(14 + 6);
        item[..2].copy_from_slice(&20u16.to_le_bytes());
        bytes.extend(item);
        assert_eq!(recent_doc_data(&bytes).link_name.as_deref(), Some("A.LNK"));
        // the name alone, and a name cut short
        assert_eq!(
            recent_doc_data(&utf16("b.txt\0")).name.as_deref(),
            Some("b.txt")
        );
        let cut = recent_doc_data(&utf16("c.tx"));
        assert_eq!(cut.name.as_deref(), Some("c.tx"));
        assert_eq!(cut.problems, ["its name has no NUL: the data is cut short"]);
        // not a file entry
        let mut bytes = utf16("d\0");
        bytes.extend_from_slice(&[14, 0, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            recent_doc_data(&bytes).problems,
            ["its shell item is of type 0x1f, not a file entry"]
        );
    }

    #[test]
    fn recent_doc_unicode_file_entries() {
        let mut item = vec![0u8; 14];
        item[2] = 0xb1;
        item.extend(utf16("café.lnk\0"));
        let size = u16::try_from(item.len()).unwrap_or(0);
        item[..2].copy_from_slice(&size.to_le_bytes());
        item.extend_from_slice(&[0, 0]);
        let mut bytes = utf16("café.txt\0");
        bytes.extend(item);
        assert_eq!(
            recent_doc_data(&bytes),
            RecentDocData {
                name: Some("café.txt".into()),
                link_name: Some("café.lnk".into()),
                problems: Vec::new(),
            }
        );

        let mut item = vec![0u8; 14];
        item[2] = 0xb1;
        item.extend_from_slice(&0xd800u16.to_le_bytes());
        item.extend_from_slice(&[0, 0]);
        let size = u16::try_from(item.len()).unwrap_or(0);
        item[..2].copy_from_slice(&size.to_le_bytes());
        let mut bytes = utf16("bad.txt\0");
        bytes.extend(item);
        let data = recent_doc_data(&bytes);
        assert_eq!(data.link_name.as_deref(), Some("�"));
        assert_eq!(
            data.problems,
            ["its shell item's name is not valid UTF-16: decoded lossily"]
        );
    }

    #[test]
    fn recent_doc_extension_blocks_and_cut_names() {
        let mut item = file_entry("SHORT.LNK", "Long name.lnk");
        let block_at = item
            .windows(4)
            .position(|bytes| bytes == BEEF0004.to_le_bytes())
            .and_then(|at| at.checked_sub(4))
            .unwrap_or(0);
        item.splice(block_at..block_at, [8, 0, 3, 0, 1, 2, 3, 4]);
        let item_size = u16::try_from(item.len() - 2).unwrap_or(0);
        item[..2].copy_from_slice(&item_size.to_le_bytes());
        let mut bytes = utf16("long.txt\0");
        bytes.extend(item);
        assert_eq!(
            recent_doc_data(&bytes).link_name.as_deref(),
            Some("Long name.lnk")
        );

        let mut invalid = file_entry("SHORT.LNK", "x");
        let name_at = invalid
            .windows(4)
            .position(|bytes| bytes == BEEF0004.to_le_bytes())
            .map_or(0, |at| at + 42);
        invalid[name_at..name_at + 2].copy_from_slice(&0xd800u16.to_le_bytes());
        let mut bytes = utf16("invalid.txt\0");
        bytes.extend(invalid);
        let data = recent_doc_data(&bytes);
        assert_eq!(data.link_name.as_deref(), Some("�"));
        assert_eq!(
            data.problems,
            ["its 0xBEEF0004 long name is not valid UTF-16: decoded lossily"]
        );

        let mut cut = vec![14, 0, 0x32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        cut.extend_from_slice(b"BROKEN");
        let cut_size = u16::try_from(cut.len()).unwrap_or(0);
        cut[..2].copy_from_slice(&cut_size.to_le_bytes());
        let mut bytes = utf16("cut.txt\0");
        bytes.extend(cut);
        assert_eq!(
            recent_doc_data(&bytes).problems,
            ["its shell item's ANSI name has no NUL: it is cut short"]
        );
    }

    #[test]
    fn profiles() {
        assert_eq!(
            profile_in(r"C:\Users\alice\AppData\Local").as_deref(),
            Some("alice")
        );
        assert_eq!(
            profile_in(r"C:\Documents and Settings\bob\Desktop").as_deref(),
            Some("bob")
        );
        assert_eq!(profile_in(r"\\server\Users\carol\Desktop"), None);
        assert_eq!(
            profile_in(r"C:\Windows\system32\config\systemprofile\Desktop"),
            None
        );
    }
}
