//! Shell item lists as Explorer keeps them for pinned and cached programs (`Taskband`'s
//! `Favorites`, `ProgramsCache`), the property stores in packaged app items, and the link
//! (`.lnk`) data of `FavoritesResolve`: as much as is needed for a path and an application ID,
//! every size checked. What isn't understood is reported, never guessed at.
//!
//! A shell item list is a sequence of items, each starting with its size (2 bytes), ended by an
//! item of size 0. An item's type is its third byte: a root folder (`0x1F`, a GUID), a volume
//! (`0x2F`, a drive letter), a file entry (`0x30`–`0x3F`: a short name and extension blocks,
//! `0xBEEF0004` with the long name, `0xBEEF001D` with the application's ID, `0xBEEF001E` with how
//! it was pinned), or a packaged app (`0x00` with the signature `APPS` at offset 6, then
//! serialized property storages). The formats are Joachim Metz's libfwsi documentation and
//! Microsoft's MS-PROPSTORE and MS-SHLLINK.

use crate::bytes::{u16_at, u32_at, utf16_units};
use crate::software::guid;

/// The extension block with an application user model ID.
const BEEF001D: u32 = 0xbeef_001d;
/// The extension block with how an item was pinned.
const BEEF001E: u32 = 0xbeef_001e;
/// The signature of a packaged app's shell item, at offset 6.
const APPS: &[u8; 4] = b"APPS";
/// A serialized property storage's version: `1SPS`.
const SPS: u32 = 0x5350_5331;
/// The property set of `System.AppUserModel.*`, whose property 5 is the ID.
const APP_USER_MODEL: &str = "{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}";
/// `VT_LPWSTR`: a counted UTF-16 string.
const VT_LPWSTR: u16 = 0x1f;
/// Shell folders of root folder items, by their class IDs.
const SHELL_FOLDERS: [(&str, &str); 12] = [
    ("{1F3427C8-5C10-4210-AA03-2EE45287D668}", "User Pinned"),
    ("{4234D49B-0245-4DF3-B780-3893943456E1}", "Applications"),
    ("{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "My Computer"),
    ("{59031A47-3F72-44A7-89C5-5595FE6B30EE}", "Users Files"),
    ("{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", "Network"),
    (
        "{208D2C60-3AEA-1069-A2D7-08002B30309D}",
        "My Network Places",
    ),
    ("{21EC2020-3AEA-1069-A2DD-08002B30309D}", "Control Panel"),
    ("{26EE0668-A00A-44D7-9371-BEB064C98683}", "Control Panel"),
    ("{450D8FBA-AD25-11D0-98A8-0800361B1103}", "My Documents"),
    ("{645FF040-5081-101B-9F08-00AA002F954E}", "Recycle Bin"),
    (
        "{871C5380-42A0-1069-A2EA-08002B30309D}",
        "Internet Explorer",
    ),
    ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop"),
];

/// What a shell item list gives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ItemList {
    /// The items' names joined with `\`; `None` when an item isn't understood.
    pub path: Option<String>,
    /// The application user model ID of a file entry's `0xBEEF001D` block, or of a packaged
    /// app's property store.
    pub app_id: Option<String>,
    /// A file entry's `0xBEEF001E` block: `UserPinned`, `SystemPinned`, ….
    pub pin_type: Option<String>,
    /// What isn't understood or is cut short.
    pub problems: Vec<String>,
}

/// The shell item list `bytes` (ended by an item of size 0, or by the bytes' end).
pub(crate) fn item_list(bytes: &[u8]) -> ItemList {
    let mut list = ItemList::default();
    let mut names = Vec::new();
    let mut understood = true;
    let mut at = 0;
    let mut n = 0;
    while let Some(size) = u16_at(bytes, at).map(usize::from) {
        if size == 0 {
            break;
        }
        n += 1;
        let Some(item) = bytes.get(at..at + size).filter(|_| size >= 3) else {
            list.problems.push(format!(
                "shell item {n}: {size} bytes, past the data's {} or too small",
                bytes.len()
            ));
            understood = false;
            break;
        };
        match item_name(item, &mut list) {
            Ok(name) => names.push(name),
            Err(why) => {
                list.problems.push(format!("shell item {n}: {why}"));
                understood = false;
            }
        }
        at += size;
    }
    if understood && !names.is_empty() {
        list.path = Some(names.join("\\"));
    }
    list
}

/// The name of one shell item; its application ID and pin type go to `list`.
fn item_name(item: &[u8], list: &mut ItemList) -> Result<String, String> {
    let kind = item[2];
    if kind == 0x1f {
        let id = item
            .get(4..20)
            .map(guid)
            .ok_or("a root folder item without its class ID")?;
        return Ok(SHELL_FOLDERS
            .iter()
            .find(|(g, _)| g.eq_ignore_ascii_case(&id))
            .map_or(id, |(_, name)| (*name).to_owned()));
    }
    if kind & 0x70 == 0x20 {
        let name = ansi(item.get(3..).unwrap_or_default());
        return if name.is_empty() {
            Err(format!("a volume item (0x{kind:02x}) without a name"))
        } else {
            Ok(name)
        };
    }
    if kind & 0x70 == 0x30 {
        return file_entry(item, list);
    }
    if kind == 0 && item.get(6..10) == Some(APPS) {
        let id = app_user_model_id(item)
            .ok_or("a packaged app item without an application user model ID")?;
        list.app_id = Some(id.clone());
        return Ok(id);
    }
    Err(format!("of type 0x{kind:02x}, not decoded"))
}

/// A file entry's long name (else its short name), with its extension blocks' application ID
/// and pin type.
fn file_entry(item: &[u8], list: &mut ItemList) -> Result<String, String> {
    let kind = item[2];
    if item.len() < 14 {
        return Err(format!("a file entry of {} bytes, too small", item.len()));
    }
    // the primary name: UTF-16 when the type says so, else ANSI; then 2-byte aligned
    let (short, after) = if kind & 0x04 != 0 {
        let units = utf16_units(&item[14..]);
        let end = units
            .iter()
            .position(|&u| u == 0)
            .ok_or("a file entry's UTF-16 name without its NUL")?;
        (String::from_utf16_lossy(&units[..end]), 14 + (end + 1) * 2)
    } else {
        let end = item[14..]
            .iter()
            .position(|&b| b == 0)
            .ok_or("a file entry's name without its NUL")?;
        (
            ansi(&item[14..14 + end]),
            (14 + end + 1).next_multiple_of(2),
        )
    };
    let (long, problems) = crate::ntuser::long_name(item, after);
    list.problems.extend(problems);
    let mut block_at = after;
    while let Some(size) = u16_at(item, block_at).map(usize::from) {
        let Some(block) = item.get(block_at..block_at + size).filter(|_| size >= 10) else {
            break;
        };
        match u32_at(block, 4) {
            Some(BEEF001D) => list.app_id = block_string(block),
            Some(BEEF001E) => list.pin_type = block_string(block),
            _ => {}
        }
        block_at += size;
    }
    let name = long.filter(|l| !l.is_empty()).unwrap_or(short);
    if name.is_empty() {
        Err("a file entry without a name".to_owned())
    } else {
        Ok(name)
    }
}

/// The UTF-16 string of a `0xBEEF001D` or `0xBEEF001E` block: after its 8-byte header and a
/// 2-byte field, up to its NUL.
fn block_string(block: &[u8]) -> Option<String> {
    let units = utf16_units(block.get(10..)?);
    let end = units.iter().position(|&u| u == 0)?;
    Some(String::from_utf16_lossy(&units[..end])).filter(|s| !s.is_empty())
}

/// Bytes as one-byte characters (Windows' ANSI names are Latin-1 here, as in key names).
fn ansi(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..end].iter().map(|&b| char::from(b)).collect()
}

/// The application user model ID in a packaged app item's property storages: property 5 of the
/// `System.AppUserModel` set, a `VT_LPWSTR`. The storages are found by their `1SPS` version
/// field, past the item's 10-byte header.
fn app_user_model_id(item: &[u8]) -> Option<String> {
    let start = (10..item.len().saturating_sub(8)).find(|&at| {
        u32_at(item, at + 4) == Some(SPS) && u32_at(item, at).is_some_and(|s| s >= 24)
    })?;
    let mut at = start;
    while let Some(size) = u32_at(item, at).map(|s| s as usize) {
        if size < 24 || u32_at(item, at + 4) != Some(SPS) {
            break;
        }
        let storage = item.get(at..at.checked_add(size)?)?;
        if guid(&storage[8..24]) == APP_USER_MODEL
            && let Some(id) = string_property(storage, 5)
        {
            return Some(id);
        }
        at += size;
    }
    None
}

/// Property `id` of an integer-named storage, when it is a `VT_LPWSTR`.
fn string_property(storage: &[u8], id: u32) -> Option<String> {
    let mut at = 24;
    while let Some(size) = u32_at(storage, at).map(|s| s as usize) {
        if size < 13 {
            break;
        }
        let value = storage.get(at..at.checked_add(size)?)?;
        if u32_at(value, 4) == Some(id) && u16_at(value, 9) == Some(VT_LPWSTR) {
            let chars = u32_at(value, 13)? as usize;
            let text = value.get(17..17usize.checked_add(chars.checked_mul(2)?)?)?;
            let units = utf16_units(text);
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            return Some(String::from_utf16_lossy(&units[..end]));
        }
        at += size;
    }
    None
}

/// What a shell link (`.lnk` data) points at: the path its `LinkInfo` gives (its local base
/// path, the Unicode one when there is one, and common path suffix; or its network share's name
/// and the suffix), else its target ID list's path; and its target ID list's application ID
/// (a packaged app's link has only that list). `Err` when the data isn't a shell link or its
/// structures are cut short.
pub(crate) fn link(link: &[u8]) -> Result<ItemList, String> {
    if u32_at(link, 0) != Some(0x4c) || link.get(4..20) != Some(&LINK_CLSID) {
        return Err("not shell link data (no 0x4C header with the shell link class ID)".to_owned());
    }
    if link.len() < 0x4c {
        return Err("its shell link header is cut short".to_owned());
    }
    let flags = u32_at(link, 0x14).unwrap_or(0);
    let mut at = 0x4c;
    let mut target = ItemList::default();
    if flags & 0x01 != 0 {
        let size = usize::from(u16_at(link, at).ok_or("its target ID list is cut short")?);
        let list = link
            .get(at + 2..at + 2 + size)
            .ok_or_else(|| format!("its target ID list of {size} bytes is cut short"))?;
        target = item_list(list);
        at += 2 + size;
    }
    if flags & 0x02 != 0 {
        let size = u32_at(link, at).ok_or("its LinkInfo is cut short")? as usize;
        let info = link
            .get(at..at.checked_add(size).ok_or("its LinkInfo size overflows")?)
            .filter(|_| size >= 0x1c)
            .ok_or_else(|| format!("its LinkInfo of {size} bytes is cut short or too small"))?;
        if let Some(path) = link_info_path(info) {
            target.path = Some(path);
            target.problems.clear();
        }
    }
    if target.path.is_none() && target.problems.is_empty() {
        target
            .problems
            .push("neither its LinkInfo nor its target ID list gives a path".to_owned());
    }
    Ok(target)
}

/// The path of a `LinkInfo` structure.
fn link_info_path(info: &[u8]) -> Option<String> {
    let header = u32_at(info, 4).unwrap_or(0) as usize;
    let info_flags = u32_at(info, 8).unwrap_or(0);
    if (header != 0x1c && header < 0x24) || header > info.len() {
        return None;
    }
    let offset = |at: usize| {
        u32_at(info, at)
            .map(|o| o as usize)
            .filter(|&o| o >= header && o < info.len())
    };
    let ansi_at = |at: usize| offset(at).and_then(|o| info.get(o..)).map(ansi);
    let unicode_at = |at: usize| {
        offset(at).and_then(|o| info.get(o..)).map(|b| {
            let units = utf16_units(b);
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            String::from_utf16_lossy(&units[..end])
        })
    };
    let wide = header >= 0x24;
    let suffix = if wide { unicode_at(0x20) } else { None }
        .or_else(|| ansi_at(0x18))
        .unwrap_or_default();
    let base = if info_flags & 0x01 != 0 {
        if wide { unicode_at(0x1c) } else { None }.or_else(|| ansi_at(0x10))
    } else if info_flags & 0x02 != 0 {
        // CommonNetworkRelativeLink: its net name's offset at 8
        offset(0x14)
            .and_then(|o| info.get(o..))
            .and_then(|net| Some(ansi(net.get(u32_at(net, 8)? as usize..)?)))
    } else {
        None
    };
    let base = base.filter(|b| !b.is_empty())?;
    // MS-SHLLINK 2.3 appends CommonPathSuffix to LocalBasePath verbatim.
    // A network share name, unlike LocalBasePath, needs a separator before a relative suffix.
    if info_flags & 0x01 != 0 {
        return Some(format!("{base}{suffix}"));
    }
    Some(if suffix.is_empty() {
        base
    } else if base.ends_with('\\') || suffix.starts_with('\\') {
        format!("{base}{suffix}")
    } else {
        format!("{base}\\{suffix}")
    })
}

/// The shell link class ID, `{00021401-0000-0000-C000-000000000046}`, as stored.
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// A shell item of `kind` with `body` after its 3-byte header.
    fn item(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut b = vec![0, 0, kind];
        b.extend_from_slice(body);
        let size = u16::try_from(b.len()).unwrap_or(0);
        b[..2].copy_from_slice(&size.to_le_bytes());
        b
    }

    fn root(id: [u8; 16]) -> Vec<u8> {
        let mut body = vec![0x80];
        body.extend_from_slice(&id);
        item(0x1f, &body)
    }

    /// A file entry named `short` with an extension block of `signature` holding `text`.
    fn file(short: &str, signature: u32, text: &str) -> Vec<u8> {
        let mut body = vec![0u8; 11];
        body.extend_from_slice(short.as_bytes());
        body.push(0);
        if body.len().is_multiple_of(2) {
            body.push(0);
        }
        let mut block = vec![0, 0, 0, 0];
        block.extend_from_slice(&signature.to_le_bytes());
        block.extend_from_slice(&[2, 0]);
        block.extend(utf16z(text));
        block.extend_from_slice(&[0, 0]);
        let size = u16::try_from(block.len()).unwrap_or(0);
        block[..2].copy_from_slice(&size.to_le_bytes());
        body.extend(block);
        item(0x32, &body)
    }

    #[test]
    fn item_lists() {
        // {1F3427C8-5C10-4210-AA03-2EE45287D668}: User Pinned
        let pinned = [
            0xc8, 0x27, 0x34, 0x1f, 0x10, 0x5c, 0x10, 0x42, 0xaa, 0x03, 0x2e, 0xe4, 0x52, 0x87,
            0xd6, 0x68,
        ];
        let mut bytes = root(pinned);
        bytes.extend(file("TOOL.LNK", BEEF001D, "Example.Tool"));
        bytes.extend(file("x", BEEF001E, "UserPinned"));
        bytes.extend([0, 0]);
        let list = item_list(&bytes);
        assert_eq!(list.path.as_deref(), Some(r"User Pinned\TOOL.LNK\x"));
        assert_eq!(list.app_id.as_deref(), Some("Example.Tool"));
        assert_eq!(list.pin_type.as_deref(), Some("UserPinned"));
        assert_eq!(list.problems, Vec::<String>::new());
        // an unknown type: no path; cut short
        let mut bytes = root([0; 16]);
        bytes.extend(item(0x71, &[1, 2, 3]));
        let list = item_list(&bytes);
        assert_eq!(list.path, None);
        assert_eq!(list.problems, ["shell item 2: of type 0x71, not decoded"]);
        let list = item_list(&[40, 0, 0x1f, 0]);
        assert_eq!(list.path, None);
        assert_eq!(list.problems.len(), 1);
        assert_eq!(
            item_list(&root([0; 16])).path.as_deref(),
            Some("{00000000-0000-0000-0000-000000000000}")
        );
        assert_eq!(
            item_list(&item(0x2f, b"C:\\\0")).path.as_deref(),
            Some("C:\\")
        );
        assert_eq!(item_list(&[]).path, None);
    }

    #[test]
    fn packaged_apps() {
        let id = "Contoso.App_abc!App";
        let mut value = Vec::new();
        let chars = u32::try_from(id.encode_utf16().count() + 1).unwrap_or(0);
        value.extend_from_slice(&[0; 4]);
        value.extend_from_slice(&5u32.to_le_bytes());
        value.push(0);
        value.extend_from_slice(&VT_LPWSTR.to_le_bytes());
        value.extend_from_slice(&[0, 0]);
        value.extend_from_slice(&chars.to_le_bytes());
        value.extend(utf16z(id));
        let size = u32::try_from(value.len()).unwrap_or(0);
        value[..4].copy_from_slice(&size.to_le_bytes());
        let mut storage = vec![0, 0, 0, 0];
        storage.extend_from_slice(&SPS.to_le_bytes());
        storage.extend_from_slice(&[
            0x55, 0x28, 0x4c, 0x9f, 0x79, 0x9f, 0x39, 0x4b, 0xa8, 0xd0, 0xe1, 0xd4, 0x2d, 0xe1,
            0xd5, 0xf3,
        ]);
        storage.extend(value);
        storage.extend_from_slice(&[0; 4]);
        let size = u32::try_from(storage.len()).unwrap_or(0);
        storage[..4].copy_from_slice(&size.to_le_bytes());
        let mut body = vec![0, 0, 0];
        body.extend_from_slice(APPS);
        body.extend_from_slice(&[0; 6]);
        body.extend(storage);
        let list = item_list(&item(0, &body));
        assert_eq!(list.path.as_deref(), Some(id));
        assert_eq!(list.app_id.as_deref(), Some(id));
        // without a property store
        let list = item_list(&item(0, b"\0\0\0APPS\0\0"));
        assert_eq!(list.path, None);
    }

    proptest::proptest! {
        /// Shell item lists, packaged app items and links of any bytes: read as far as they go.
        #[test]
        fn arbitrary_bytes(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600)) {
            let _ = item_list(&bytes);
            let _ = link(&bytes);
            let mut header = vec![0x4c, 0, 0, 0];
            header.extend_from_slice(&LINK_CLSID);
            header.extend_from_slice(&bytes);
            let _ = link(&header);
            let mut apps = vec![0, 0, 0, 0, 0, 0];
            apps.extend_from_slice(APPS);
            apps.extend_from_slice(&bytes);
            let _ = app_user_model_id(&apps);
            let _ = item_list(&apps);
        }
    }

    #[test]
    fn truncated_shortcut_headers_are_rejected() {
        let mut header = vec![0x4c, 0, 0, 0];
        header.extend_from_slice(&LINK_CLSID);
        assert!(link(&header).is_err());
    }

    #[test]
    fn link_info_concatenates_local_path_and_rejects_header_offsets() {
        let mut info = vec![0u8; 0x1c];
        info[4] = 0x1c;
        info[8] = 1;
        info[0x10] = 0x1c;
        info.extend_from_slice(b"C:\\Tools\0");
        info[0x18] = u8::try_from(info.len()).unwrap_or(0);
        info.extend_from_slice(b"\\agent.exe\0");
        assert_eq!(
            link_info_path(&info).as_deref(),
            Some(r"C:\Tools\agent.exe")
        );
        info[0x10] = 4; // points into LinkInfoHeaderSize, not string data
        assert_eq!(link_info_path(&info), None);
    }

    #[test]
    fn links() {
        let mut data = vec![0u8; 0x4c];
        data[0] = 0x4c;
        data[4..20].copy_from_slice(&LINK_CLSID);
        data[0x14] = 0x02;
        let mut info = vec![0u8; 0x1c];
        info[4] = 0x1c;
        info[8] = 0x01;
        info[0x10] = 0x1c;
        info.extend_from_slice(b"C:\\Users\\a\\x.lnk\0");
        info[0x18] = u8::try_from(info.len()).unwrap_or(0);
        info.push(0);
        let size = u32::try_from(info.len()).unwrap_or(0);
        info[..4].copy_from_slice(&size.to_le_bytes());
        data.extend(info);
        assert_eq!(
            link(&data).map(|l| l.path),
            Ok(Some(r"C:\Users\a\x.lnk".to_owned()))
        );
        assert!(link(&data[..0x50]).is_err());
        assert!(link(b"not a link").is_err());
        // no LinkInfo, no target ID list
        data[0x14] = 0;
        let target = link(&data).unwrap_or_default();
        assert_eq!(target.path, None);
        assert_eq!(target.problems.len(), 1);
    }
}
