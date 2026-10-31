//! `NTUSER.DAT` hives: Explorer's recent documents (`RecentDocs`, in the order of its
//! `MRUListEx`), the programs and shortcuts a user started from Explorer (`UserAssist`), and the
//! name of the profile a hive belongs to.
//!
//! A `RecentDocs` value is the item's name (UTF-16, up to its NUL), then a shell item list
//! whose first item is the file entry of the shortcut Windows made in the `Recent` folder: an
//! 8.3 or ANSI name, and in its `0xBEEF0004` extension block the long name. An `MRUListEx` is
//! the values' numbers, 4 bytes each, the most recent first, ending with `0xFFFFFFFF`.
//!
//! `UserAssist` has a `{GUID}` key per kind of item (programs, shortcuts, …), each with its
//! format's `Version` and a `Count` key: a value per item, its name in ROT13, a program's name
//! starting with a known folder's GUID (`{1AC14E77-…}\cmd.exe`: `System32`). Version 5 (Windows 7
//! and later) data is 72 bytes: a session number, the run count, the focus count and time (ms),
//! and from offset `0x3C` the FILETIME of the last run. Version 3 (Windows 2000 to Vista) is 16
//! bytes: a session number, the run count plus 5, and the FILETIME of the last run.

use crate::bytes::{u16_at, u32_at, u64_at, utf16_units};
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
/// Where Explorer keeps `UserAssist`, under the hive's root.
pub const USER_ASSIST: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

/// The kinds of `UserAssist` keys, by their GUIDs.
const USER_ASSIST_KINDS: [(&str, &str); 4] = [
    ("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", "executable"),
    ("{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}", "shortcut"),
    ("{75048700-EF1F-11D0-9888-006097DEACF9}", "active_desktop"),
    ("{5E6AB780-7743-11CF-A12B-00AA004AE837}", "internet_toolbar"),
];

/// Known folders: their GUIDs (`KNOWNFOLDERID`) and default paths, as Microsoft documents them.
const KNOWN_FOLDERS: [(&str, &str); 48] = [
    (
        "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}",
        r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs",
    ),
    (
        "{0762D272-C50A-4BB0-A382-697DCD729B80}",
        r"%SystemDrive%\Users",
    ),
    (
        "{1777F761-68AD-4D8A-87BD-30B759FA33DD}",
        r"%USERPROFILE%\Favorites",
    ),
    (
        "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}",
        r"%USERPROFILE%\Videos",
    ),
    (
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}",
        r"%windir%\system32",
    ),
    ("{2400183A-6185-49FB-A2D8-4A392A602BA3}", r"%PUBLIC%\Videos"),
    ("{3214FAB5-9757-4298-BB61-92A9DEAA44FF}", r"%PUBLIC%\Music"),
    (
        "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
        r"%USERPROFILE%\Pictures",
    ),
    (
        "{374DE290-123F-4565-9164-39C4925E467B}",
        r"%USERPROFILE%\Downloads",
    ),
    (
        "{3D644C9B-1FB8-4F30-9B45-F670235F79C0}",
        r"%PUBLIC%\Downloads",
    ),
    ("{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}", r"%APPDATA%"),
    (
        "{4BD8D571-6D19-48D3-BE97-422220080E43}",
        r"%USERPROFILE%\Music",
    ),
    (
        "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}",
        r"%USERPROFILE%\Saved Games",
    ),
    (
        "{52A4F021-7B75-48A9-9F6B-4B87A210BC8F}",
        r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch",
    ),
    (
        "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}",
        r"%LOCALAPPDATA%\Programs",
    ),
    ("{5E6C858F-0E22-4760-9AFE-EA3317B67173}", r"%USERPROFILE%"),
    (
        "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}",
        r"%APPDATA%\Microsoft\Windows\Start Menu",
    ),
    (
        "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}",
        r"%ALLUSERSPROFILE%",
    ),
    (
        "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}",
        r"%ProgramFiles%\Common Files",
    ),
    ("{6D809377-6AF0-444B-8957-A3773F02200E}", r"%ProgramFiles%"),
    (
        "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}",
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Administrative Tools",
    ),
    (
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}",
        r"%ProgramFiles(x86)%",
    ),
    (
        "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}",
        r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\StartUp",
    ),
    (
        "{8983036C-27C0-404B-8F08-102D10DCFD74}",
        r"%APPDATA%\Microsoft\Windows\SendTo",
    ),
    (
        "{8AD10C31-2ADB-4296-A8F7-E4701232C972}",
        r"%windir%\Resources",
    ),
    ("{905E63B6-C1BF-494E-B29C-65B732D3D21A}", r"%ProgramFiles%"),
    (
        "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}",
        r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned",
    ),
    (
        "{A4115719-D62E-491D-AA7C-E74B8BE3B067}",
        r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu",
    ),
    (
        "{A520A1A4-1780-4FF6-BD18-167343C5AF16}",
        r"%USERPROFILE%\AppData\LocalLow",
    ),
    (
        "{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}",
        r"%USERPROFILE%\OneDrive",
    ),
    (
        "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}",
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs",
    ),
    (
        "{AE50C081-EBD2-438A-8655-8A092E34987A}",
        r"%APPDATA%\Microsoft\Windows\Recent",
    ),
    (
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
        r"%USERPROFILE%\Desktop",
    ),
    (
        "{B97D20BB-F46A-4C97-BA10-5E3608430854}",
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp",
    ),
    (
        "{BCB5256F-79F6-4CEE-B725-DC34E402FD46}",
        r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts",
    ),
    (
        "{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}",
        r"%LOCALAPPDATA%\Programs\Common",
    ),
    (
        "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}",
        r"%USERPROFILE%\Links",
    ),
    (
        "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}",
        r"%PUBLIC%\Desktop",
    ),
    (
        "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}",
        r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Administrative Tools",
    ),
    (
        "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}",
        r"%windir%\SysWOW64",
    ),
    (
        "{DE974D24-D9C6-4D3E-BF91-F4455120B917}",
        r"%ProgramFiles(x86)%\Common Files",
    ),
    ("{DFDF76A2-C82A-4D63-906A-5644AC457385}", r"%PUBLIC%"),
    (
        "{ED4824AF-DCE4-45A8-81E2-FC7965083634}",
        r"%PUBLIC%\Documents",
    ),
    ("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", r"%LOCALAPPDATA%"),
    ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", r"%windir%"),
    (
        "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}",
        r"%ProgramFiles%\Common Files",
    ),
    ("{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}", r"%windir%\Fonts"),
    (
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
        r"%USERPROFILE%\Documents",
    ),
];

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

/// The default path of the known folder `guid` (`{1AC14E77-…}`, in any case).
#[must_use]
pub fn known_folder_path(guid: &str) -> Option<&'static str> {
    KNOWN_FOLDERS
        .iter()
        .find(|(g, _)| g.eq_ignore_ascii_case(guid))
        .map(|(_, path)| *path)
}

/// `text` with its ASCII letters rotated by 13, as `UserAssist` writes its value names.
#[must_use]
pub fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => char::from((c as u8 - b'a' + 13) % 26 + b'a'),
            'A'..='Z' => char::from((c as u8 - b'A' + 13) % 26 + b'A'),
            _ => c,
        })
        .collect()
}

/// The path a decoded `UserAssist` name gives: its known folder GUID replaced by the folder's
/// default path, or a version 3 name's part after its `UEME_…:` prefix; `None` when it is no
/// path (an app id like `Microsoft.Windows.Explorer`, `UEME_UISCUT`).
#[must_use]
pub fn user_assist_path(name: &str) -> Option<String> {
    let path = if name.starts_with("UEME_") {
        name.split_once(':')?.1.to_owned()
    } else {
        match name.split_once('\\') {
            Some((first, rest)) => match known_folder_path(first) {
                Some(folder) => format!(r"{folder}\{rest}"),
                None => name.to_owned(),
            },
            None => known_folder_path(name).map_or_else(|| name.to_owned(), str::to_owned),
        }
    };
    (path.contains('\\') || path.contains('%')).then_some(path)
}

/// A `UserAssist` value's data, decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserAssistData {
    /// 5 (72 bytes: Windows 7 and later) or 3 (16 bytes: Windows 2000 to Vista).
    pub format: u32,
    /// The session it was last written in.
    pub session_id: u32,
    /// The run count as stored: version 3 adds 5 (see [`UserAssistData::run_count`]).
    pub stored_count: u32,
    /// How many times it had the focus (version 5).
    pub focus_count: Option<u32>,
    /// How long it had the focus, in milliseconds (version 5).
    pub focus_time_ms: Option<u32>,
    /// When it last ran (FILETIME); `None` when 0.
    pub last_run: Option<u64>,
}

impl UserAssistData {
    /// How many times it ran.
    ///
    /// # Errors
    /// When a version 3 count is under 5, where Windows starts it.
    pub fn run_count(&self) -> Result<u32, String> {
        if self.format == 3 {
            self.stored_count.checked_sub(5).ok_or_else(|| {
                format!(
                    "version 3 run count {} is under 5, where Windows starts it",
                    self.stored_count
                )
            })
        } else {
            Ok(self.stored_count)
        }
    }
}

/// A `UserAssist` value's bytes, decoded by their size.
///
/// # Errors
/// When they are neither 72 (version 5) nor 16 (version 3) bytes.
pub fn user_assist_data(bytes: &[u8]) -> Result<UserAssistData, String> {
    let word = |at| u32_at(bytes, at).unwrap_or(0);
    let time = |at| u64_at(bytes, at).filter(|&t| t != 0);
    match bytes.len() {
        72 => Ok(UserAssistData {
            format: 5,
            session_id: word(0),
            stored_count: word(4),
            focus_count: Some(word(8)),
            focus_time_ms: Some(word(12)),
            last_run: time(0x3c),
        }),
        16 => Ok(UserAssistData {
            format: 3,
            session_id: word(0),
            stored_count: word(4),
            focus_count: None,
            focus_time_ms: None,
            last_run: time(8),
        }),
        n => Err(format!(
            "{n} bytes: neither 72 (version 5) nor 16 (version 3)"
        )),
    }
}

/// One item of `UserAssist`: a program or shortcut a user started from Explorer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserAssistEntry {
    /// Its `{GUID}` key's name.
    pub guid: String,
    /// What the key holds: `executable`, `shortcut` (Windows 7 and later), `active_desktop`,
    /// `internet_toolbar` (earlier), or `other`.
    pub kind: &'static str,
    /// The `{GUID}` key's `Version`.
    pub version: Option<u32>,
    /// The value's name as written (ROT13).
    pub name_rot13: String,
    /// The name decoded.
    pub name: String,
    /// The path it names ([`user_assist_path`]).
    pub path: Option<String>,
    /// The data's format: 5 or 3, by its size.
    pub format: Option<u32>,
    /// The session it was last written in.
    pub session_id: Option<u32>,
    /// How many times it ran.
    pub run_count: Option<u32>,
    /// How many times it had the focus.
    pub focus_count: Option<u32>,
    /// How long it had the focus, in milliseconds.
    pub focus_time_ms: Option<u32>,
    /// When it last ran (FILETIME).
    pub last_run: Option<u64>,
    /// The value's bytes, when they don't decode.
    pub data_raw: Option<Vec<u8>>,
    /// When its `Count` key was last written (FILETIME).
    pub last_written: u64,
    /// Whether the transaction logs' replay wrote its value or its `Count` key.
    pub replayed: bool,
    /// What couldn't be read, and what doesn't match.
    pub problems: Vec<String>,
}

/// The items of `UserAssist` in `hive`, each `{GUID}` key's `Count` values in order, without the
/// session entries (`UEME_CTLSESSION`, `UEME_CTLCUACount:ctor`); with them what keeps keys from
/// being read. `None` when the hive has no `UserAssist` key.
#[must_use]
pub fn user_assist(hive: &Hive) -> Option<(Vec<UserAssistEntry>, Vec<String>)> {
    let key = hive.key(USER_ASSIST)?;
    let (guids, mut problems) = key.subkeys();
    if user_assist_settings(hive).no_encrypt == Some(1) {
        problems.push(
            r"UserAssist\Settings NoEncrypt is 1: names written while it was set are not ROT13, and decode wrongly"
                .to_owned(),
        );
    }
    let mut entries = Vec::new();
    for guid_key in &guids {
        let guid = guid_key.name();
        if guid.eq_ignore_ascii_case("Settings") {
            continue;
        }
        let (values, why) = guid_key.values();
        problems.extend(why.into_iter().map(|w| format!("{guid}: {w}")));
        let version = match values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case("Version"))
            .map(crate::system::number)
        {
            Some(Ok(n)) => Some(n),
            Some(Err(why)) => {
                problems.push(format!("{guid}: Version: {why}"));
                None
            }
            None => None,
        };
        let (subkeys, why) = guid_key.subkeys();
        problems.extend(why.into_iter().map(|w| format!("{guid}: {w}")));
        let Some(count) = subkeys
            .iter()
            .find(|k| k.name().eq_ignore_ascii_case("Count"))
        else {
            continue;
        };
        let (values, why) = count.values();
        problems.extend(why.into_iter().map(|w| format!(r"{guid}\Count: {w}")));
        let kind = USER_ASSIST_KINDS
            .iter()
            .find(|(g, _)| g.eq_ignore_ascii_case(&guid))
            .map_or("other", |(_, kind)| *kind);
        for value in &values {
            let name = rot13(&value.name());
            if name.starts_with("UEME_CTL") {
                continue;
            }
            entries.push(user_assist_entry(count, value, &guid, kind, version, name));
        }
    }
    Some((entries, problems))
}

/// One `Count` value's item.
fn user_assist_entry(
    count: &Key,
    value: &Value,
    guid: &str,
    kind: &'static str,
    version: Option<u32>,
    name: String,
) -> UserAssistEntry {
    let mut entry = UserAssistEntry {
        guid: guid.to_owned(),
        kind,
        version,
        name_rot13: value.name(),
        path: user_assist_path(&name),
        name,
        last_written: count.last_written(),
        replayed: count.status() == Status::Replayed || value.status() == Status::Replayed,
        ..UserAssistEntry::default()
    };
    let (bytes, why) = value.read_data();
    entry.problems.extend(why);
    if value.value_type() != ValueType::Binary {
        entry
            .problems
            .push(format!("is {}, not REG_BINARY", value.value_type().name()));
    }
    match user_assist_data(&bytes) {
        Ok(data) => {
            if let Some(v) = version.filter(|&v| v != data.format) {
                entry.problems.push(format!(
                    "{} bytes (version {}), but the key's Version is {v}",
                    bytes.len(),
                    data.format
                ));
            }
            entry.format = Some(data.format);
            entry.session_id = Some(data.session_id);
            match data.run_count() {
                Ok(n) => entry.run_count = Some(n),
                Err(why) => entry.problems.push(why),
            }
            entry.focus_count = data.focus_count;
            entry.focus_time_ms = data.focus_time_ms;
            entry.last_run = data.last_run;
        }
        Err(why) => entry.problems.push(why),
    }
    if !entry.problems.is_empty() {
        entry.data_raw = Some(bytes);
    }
    entry
}

/// The settings that turn `UserAssist` off or change how it is written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserAssistSettings {
    /// `Explorer\Advanced` `Start_TrackProgs`: 0 turns tracking off.
    pub start_track_progs: Option<u32>,
    /// `Policies\Explorer` `NoInstrumentation`: 1 turns tracking off.
    pub no_instrumentation: Option<u32>,
    /// `UserAssist\Settings` `NoLog`: 1 turns tracking off.
    pub no_log: Option<u32>,
    /// `UserAssist\Settings` `NoEncrypt`: 1 writes names without ROT13.
    pub no_encrypt: Option<u32>,
}

impl UserAssistSettings {
    /// Why `UserAssist` isn't kept: each setting that turns it off.
    #[must_use]
    pub fn tracking_off(&self) -> Vec<&'static str> {
        [
            (
                self.start_track_progs == Some(0),
                r"Explorer\Advanced Start_TrackProgs is 0",
            ),
            (
                self.no_instrumentation == Some(1),
                r"Policies\Explorer NoInstrumentation is 1",
            ),
            (self.no_log == Some(1), r"UserAssist\Settings NoLog is 1"),
        ]
        .into_iter()
        .filter_map(|(set, why)| set.then_some(why))
        .collect()
    }
}

/// The `UserAssist` settings of `hive` (numbers that aren't `REG_DWORD`s are left out).
#[must_use]
pub fn user_assist_settings(hive: &Hive) -> UserAssistSettings {
    let current = r"Software\Microsoft\Windows\CurrentVersion";
    let dword = |path: &str, name: &str| {
        crate::system::number(&hive.key(&format!(r"{current}\{path}"))?.value(name)?).ok()
    };
    UserAssistSettings {
        start_track_progs: dword(r"Explorer\Advanced", "Start_TrackProgs"),
        no_instrumentation: dword(r"Policies\Explorer", "NoInstrumentation"),
        no_log: dword(r"Explorer\UserAssist\Settings", "NoLog"),
        no_encrypt: dword(r"Explorer\UserAssist\Settings", "NoEncrypt"),
    }
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

    #[test]
    fn rot13_names_and_known_folders() {
        assert_eq!(
            rot13(r"{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr"),
            r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe"
        );
        assert_eq!(rot13(&rot13("UEME_CTLSESSION 1.0")), "UEME_CTLSESSION 1.0");
        assert_eq!(
            user_assist_path(r"{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}\cmd.exe").as_deref(),
            Some(r"%windir%\system32\cmd.exe")
        );
        assert_eq!(
            user_assist_path(r"{00000000-0000-0000-0000-000000000000}\a.exe").as_deref(),
            Some(r"{00000000-0000-0000-0000-000000000000}\a.exe")
        );
        assert_eq!(
            user_assist_path(r"C:\Tools\a.exe").as_deref(),
            Some(r"C:\Tools\a.exe")
        );
        assert_eq!(
            user_assist_path(r"UEME_RUNPATH:C:\WINDOWS\system32\notepad.exe").as_deref(),
            Some(r"C:\WINDOWS\system32\notepad.exe")
        );
        assert_eq!(user_assist_path("UEME_UISCUT"), None);
        assert_eq!(user_assist_path("Microsoft.Windows.Explorer"), None);
        assert_eq!(
            known_folder_path("{6D809377-6AF0-444B-8957-A3773F02200E}"),
            Some("%ProgramFiles%")
        );
    }

    #[test]
    fn user_assist_data_of_both_versions() {
        let mut v5 = [0u8; 72];
        v5[..4].copy_from_slice(&3u32.to_le_bytes());
        v5[4..8].copy_from_slice(&7u32.to_le_bytes());
        v5[8..12].copy_from_slice(&9u32.to_le_bytes());
        v5[12..16].copy_from_slice(&65_000u32.to_le_bytes());
        v5[0x3c..0x44].copy_from_slice(&132_888_278_320_000_000u64.to_le_bytes());
        let data = user_assist_data(&v5).unwrap_or_default();
        assert_eq!(
            (
                data.format,
                data.session_id,
                data.run_count(),
                data.focus_count,
                data.focus_time_ms,
                data.last_run
            ),
            (
                5,
                3,
                Ok(7),
                Some(9),
                Some(65_000),
                Some(132_888_278_320_000_000)
            )
        );
        let mut v3 = [0u8; 16];
        v3[4..8].copy_from_slice(&12u32.to_le_bytes());
        let data = user_assist_data(&v3).unwrap_or_default();
        // version 3 counts from 5; a time of 0 is none
        assert_eq!(
            (
                data.format,
                data.run_count(),
                data.focus_count,
                data.last_run
            ),
            (3, Ok(7), None, None)
        );
        v3[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            user_assist_data(&v3).unwrap_or_default().run_count(),
            Err("version 3 run count 2 is under 5, where Windows starts it".to_owned())
        );
        assert_eq!(
            user_assist_data(&v5[..20]),
            Err("20 bytes: neither 72 (version 5) nor 16 (version 3)".to_owned())
        );
    }
}
