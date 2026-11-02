//! Traces third-party tools leave in a user's `NTUSER.DAT` ([`ntuser`]): what the user ran,
//! archived, extracted, opened and synced. One [`AppTrace`] per tool, list entry, account or
//! setting:
//!
//! - **Sysinternals** (`Software\Sysinternals\<tool>`): each tool whose licence the user
//!   accepted (`EulaAccepted`). The key is made when the tool first runs as that user, so when it
//!   holds only `EulaAccepted` its last-write time is that first run ([`AppTrace::first_used`]).
//!   Tools that keep settings there (Process Explorer, Autoruns, …) rewrite the key later.
//! - **WinRAR** (`Software\WinRAR`): the archives opened (`ArcHistory`), and the archive names and
//!   extraction folders typed in its dialogs (`DialogEditHistory\ArcName`, `ExtrPath`), each a
//!   value named by its position (`0` the most recent).
//! - **7-Zip** (`Software\7-Zip`): the archives made (`Compression\ArcHistory`), the extraction
//!   folders (`Extraction\PathHistory`), and the folders browsed and copied to in its file manager
//!   (`FM\FolderHistory`, `FM\CopyHistory`), each a `REG_BINARY` list of UTF-16 strings, the most
//!   recent first; and the folders its panels last showed (`FM\PanelPath0`, `PanelPath1`).
//! - **WinZip** (`Software\Nico Mak Computing\WinZip`): the archives on its File menu
//!   (`filemenu`: `filemenu1`, …), the extraction folders (`extract`: `extract1`, …) and its
//!   recent archives (`mru\archives`).
//! - **OneDrive** (`Software\Microsoft\OneDrive\Accounts\<account>`): each account (`Personal`,
//!   `Business1`, …) with its e-mail address (`UserEmail`) and local folder (`UserFolder`), and its
//!   synced libraries and folders (`ScopeIdToMountPointPathCache`, `Tenants\<tenant>`).
//! - **Adobe Acrobat and Reader** (`Software\Adobe\{Acrobat Reader,Adobe Acrobat}\<version>\AVGeneral`):
//!   the files and folders opened last (`cRecentFiles\c<N>`, `cRecentFolders\c<N>`: `c1` the most
//!   recent), each path as Adobe writes it (`/C/Users/…`).
//! - **TeamViewer** (`Software\TeamViewer`, and an older version's `Version<N>`) and
//!   **CCleaner** (`Software\Piriform\CCleaner`): every value they keep there (TeamViewer's
//!   account and user names, its file transfer folders; CCleaner's settings and `UpdateKey`).
//!
//! A list's positions are given from 0, the most recent.

use std::fmt::Write as _;

use crate::bytes::utf16_units;
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};

/// The tool a trace comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum App {
    /// A Sysinternals tool.
    Sysinternals,
    /// WinRAR.
    WinRar,
    /// 7-Zip.
    SevenZip,
    /// WinZip.
    WinZip,
    /// Microsoft OneDrive.
    OneDrive,
    /// Adobe Acrobat Reader.
    AdobeReader,
    /// Adobe Acrobat.
    AdobeAcrobat,
    /// TeamViewer.
    TeamViewer,
    /// CCleaner.
    CCleaner,
}

impl App {
    /// `Sysinternals`, `WinRAR`, `7-Zip`, `WinZip`, `OneDrive`, `Adobe Acrobat Reader`,
    /// `Adobe Acrobat`, `TeamViewer` or `CCleaner`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            App::Sysinternals => "Sysinternals",
            App::WinRar => "WinRAR",
            App::SevenZip => "7-Zip",
            App::WinZip => "WinZip",
            App::OneDrive => "OneDrive",
            App::AdobeReader => "Adobe Acrobat Reader",
            App::AdobeAcrobat => "Adobe Acrobat",
            App::TeamViewer => "TeamViewer",
            App::CCleaner => "CCleaner",
        }
    }
}

/// One trace: a tool, a list entry, an account or a setting. Empty strings are left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTrace {
    /// The tool.
    pub app: App,
    /// What it is: a Sysinternals tool's name, a list's name (`ArcHistory`, `ExtrPath`,
    /// `FolderHistory`, `filemenu`, `cRecentFiles`, …), a OneDrive account (`Personal`,
    /// `Business1`) or its synced folders' key, or a setting's name.
    pub item: String,
    /// Its position in a list: 0 is the most recent.
    pub mru_position: Option<u32>,
    /// A file or folder: an archive, an extraction folder, a OneDrive folder, a document.
    pub path: Option<String>,
    /// Other data, as text: `EulaAccepted`, a OneDrive account's e-mail address or a synced
    /// library's id, a setting's value (a number in decimal, a list's item).
    pub value: Option<String>,
    /// When a Sysinternals tool first ran as the user: its key's last-write time, when the key
    /// holds only `EulaAccepted` (FILETIME).
    pub first_used: Option<u64>,
    /// More, as names and values: an Adobe document's `Version` (Adobe's) and the values beside
    /// its path; a OneDrive account's `DisplayName`, `UserCID`, …
    pub details: Vec<(String, String)>,
    /// The key it comes from, under the hive's root, with the names as they are written.
    pub key_path: String,
    /// When that key was last written (FILETIME).
    pub key_last_written: u64,
    /// The value it comes from (`None` for a key: a Sysinternals tool, an Adobe document, a
    /// OneDrive account).
    pub value_name: Option<String>,
    /// The value's bytes, when they don't decode as what they should be.
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote its key or value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl AppTrace {
    fn new(app: App, item: &str, key: &Key, key_path: &str) -> Self {
        AppTrace {
            app,
            item: item.to_owned(),
            mru_position: None,
            path: None,
            value: None,
            first_used: None,
            details: Vec::new(),
            key_path: key_path.to_owned(),
            key_last_written: key.last_written(),
            value_name: None,
            data_raw: None,
            replayed: key.status() == Status::Replayed,
            problems: Vec::new(),
        }
    }

    /// The trace of `value`, of the key at `key_path`.
    fn of_value(app: App, item: &str, key: &Key, key_path: &str, value: &Value) -> Self {
        let mut trace = AppTrace::new(app, item, key, key_path);
        trace.value_name = Some(value.name());
        trace.replayed |= value.status() == Status::Replayed;
        trace
    }
}

/// The traces of a user's `NTUSER.DAT`, and what kept parts of it from being read: Sysinternals,
/// WinRAR, 7-Zip, WinZip, OneDrive, Adobe Acrobat and Reader, TeamViewer and CCleaner, in that
/// order.
#[must_use]
pub fn ntuser(hive: &Hive) -> (Vec<AppTrace>, Vec<String>) {
    let mut f = Found::new(hive);
    sysinternals(&mut f);
    winrar(&mut f);
    seven_zip(&mut f);
    winzip(&mut f);
    onedrive(&mut f);
    adobe(&mut f);
    settings(&mut f, App::TeamViewer, r"Software\TeamViewer", true);
    settings(&mut f, App::CCleaner, r"Software\Piriform\CCleaner", false);
    (f.records, f.problems)
}

/// The records found so far, and what kept parts of the hive from being read.
struct Found<'h> {
    hive: &'h Hive,
    records: Vec<AppTrace>,
    problems: Vec<String>,
}

impl<'h> Found<'h> {
    fn new(hive: &'h Hive) -> Self {
        Found {
            hive,
            records: Vec::new(),
            problems: Vec::new(),
        }
    }

    /// The key at `path` (names in any case), with its path as written.
    fn key(&self, path: &str) -> Option<(Key<'h>, String)> {
        let mut key = self.hive.root()?;
        let mut written = String::new();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            key = key.subkey(part)?;
            if !written.is_empty() {
                written.push('\\');
            }
            written.push_str(&key.name());
        }
        Some((key, written))
    }

    /// The subkey `name` of `key` (at `path`), with its path.
    fn subkey(key: &Key<'h>, path: &str, name: &str) -> Option<(Key<'h>, String)> {
        let sub = key.subkey(name)?;
        let at = format!(r"{path}\{}", sub.name());
        Some((sub, at))
    }

    /// The subkeys of `key` (at `path`) with their paths.
    fn subkeys(&mut self, key: &Key<'h>, path: &str) -> Vec<(Key<'h>, String)> {
        let (keys, why) = key.subkeys();
        self.problems
            .extend(why.into_iter().map(|w| format!(r"{path}: {w}")));
        keys.into_iter()
            .map(|k| {
                let p = format!(r"{path}\{}", k.name());
                (k, p)
            })
            .collect()
    }

    /// The values of `key` (at `path`).
    fn values(&mut self, key: &Key<'h>, path: &str) -> Vec<Value<'h>> {
        let (values, why) = key.values();
        self.problems
            .extend(why.into_iter().map(|w| format!(r"{path}: {w}")));
        values
    }
}

/// A value's data as text: a string, a number in decimal, a list's items joined with `; `.
/// With the bytes when they are not text or not valid UTF-16, and what is wrong.
fn text_of(value: &Value) -> (Option<String>, Option<Vec<u8>>, Option<String>) {
    let (bytes, why) = value.read_data();
    let (text, lossy) = match decode(value.data_type(), &bytes) {
        Data::Text { value, lossy } => (Some(value), lossy),
        Data::MultiText { values, lossy } => (Some(values.join("; ")), lossy),
        Data::Number(n) => (Some(n.to_string()), false),
        _ if bytes.is_empty() => (None, false),
        Data::Malformed(bad) => return (None, Some(bytes), Some(why.unwrap_or(bad))),
        Data::Bytes | Data::Undecoded => {
            let hex = bytes.iter().fold(String::new(), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            });
            return (Some(hex), None, why);
        }
    };
    let why = why.or_else(|| lossy.then(|| "is not valid UTF-16: decoded lossily".to_owned()));
    let raw = why.is_some().then_some(bytes);
    (text.filter(|t| !t.is_empty()), raw, why)
}

/// The value named `name` of `values`, in any case.
fn find<'v, 'h>(values: &'v [Value<'h>], name: &str) -> Option<&'v Value<'h>> {
    values.iter().find(|v| v.name().eq_ignore_ascii_case(name))
}

/// The position a list's value name gives: `3` for `3` (from 0), `2` for `filemenu3` or `c3`
/// (from 1).
fn position(name: &str) -> Option<u32> {
    let digits = name.len() - name.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 || digits > 9 {
        return None;
    }
    let n: u32 = name[name.len() - digits..].parse().ok()?;
    if digits == name.len() {
        Some(n)
    } else {
        n.checked_sub(1)
    }
}

/// Each Sysinternals tool's key.
fn sysinternals(f: &mut Found) {
    let Some((tools, at)) = f.key(r"Software\Sysinternals") else {
        return;
    };
    for (tool, path) in f.subkeys(&tools, &at) {
        let values = f.values(&tool, &path);
        let mut trace = AppTrace::new(App::Sysinternals, &tool.name(), &tool, &path);
        if let Some(eula) = find(&values, "EulaAccepted") {
            trace.replayed |= eula.status() == Status::Replayed;
            let (text, raw, why) = text_of(eula);
            trace.value = text;
            trace.data_raw = raw;
            trace
                .problems
                .extend(why.map(|w| format!("EulaAccepted: {w}")));
            if values.len() == 1 && tool.subkey_count() == 0 {
                trace.first_used = Some(tool.last_written());
            }
        }
        f.records.push(trace);
    }
}

/// The paths of a list key's values named by their positions (`0`, `1`, … or `name1`, …),
/// in the order of their positions; values with another name are left out.
fn numbered<'h>(f: &mut Found<'h>, app: App, item: &str, key: &Key<'h>, at: &str) {
    let values = f.values(key, at);
    let mut traces: Vec<AppTrace> = values
        .iter()
        .filter_map(|value| {
            let n = position(&value.name())?;
            let mut trace = AppTrace::of_value(app, item, key, at, value);
            trace.mru_position = Some(n);
            let (text, raw, why) = text_of(value);
            trace.path = text;
            trace.data_raw = raw;
            trace.problems.extend(why);
            Some(trace)
        })
        .collect();
    traces.sort_by_key(|t| t.mru_position);
    f.records.extend(traces);
}

/// WinRAR's history.
fn winrar(f: &mut Found) {
    let Some((winrar, at)) = f.key(r"Software\WinRAR") else {
        return;
    };
    if let Some((key, path)) = Found::subkey(&winrar, &at, "ArcHistory") {
        numbered(f, App::WinRar, "ArcHistory", &key, &path);
    }
    if let Some((dialog, dialog_at)) = Found::subkey(&winrar, &at, "DialogEditHistory") {
        for item in ["ArcName", "ExtrPath"] {
            if let Some((key, path)) = Found::subkey(&dialog, &dialog_at, item) {
                numbered(f, App::WinRar, item, &key, &path);
            }
        }
    }
}

/// The strings of a 7-Zip history list: UTF-16, each ended by a NUL; `Err` with those read when
/// its bytes are not whole UTF-16 code units or valid UTF-16.
fn utf16_list(bytes: &[u8]) -> Result<Vec<String>, (Vec<String>, String)> {
    let units = utf16_units(bytes);
    let mut items: Vec<String> = Vec::new();
    let mut bad = !bytes.len().is_multiple_of(2);
    for item in units.split(|&u| u == 0).filter(|i| !i.is_empty()) {
        bad |= String::from_utf16(item).is_err();
        items.push(String::from_utf16_lossy(item));
    }
    if bad {
        Err((items, "is not a list of valid UTF-16 strings".to_owned()))
    } else {
        Ok(items)
    }
}

/// 7-Zip's history.
fn seven_zip(f: &mut Found) {
    let Some((seven, at)) = f.key(r"Software\7-Zip") else {
        return;
    };
    for (sub, item) in [
        ("Compression", "ArcHistory"),
        ("Extraction", "PathHistory"),
        ("FM", "FolderHistory"),
        ("FM", "CopyHistory"),
    ] {
        let Some((key, path)) = Found::subkey(&seven, &at, sub) else {
            continue;
        };
        let values = f.values(&key, &path);
        let Some(value) = find(&values, item) else {
            continue;
        };
        let (bytes, why) = value.read_data();
        let (items, bad) = match utf16_list(&bytes) {
            Ok(items) => (items, None),
            Err((items, bad)) => (items, Some(bad)),
        };
        let template = AppTrace::of_value(App::SevenZip, item, &key, &path, value);
        if let Some(problem) = why.or(bad) {
            // the list as far as it goes, and its bytes once
            let mut trace = template.clone();
            trace.data_raw = Some(bytes);
            trace.problems.push(problem);
            f.records.push(trace);
        }
        for (n, entry) in (0u32..).zip(items) {
            let mut trace = template.clone();
            trace.mru_position = Some(n);
            trace.path = Some(entry);
            f.records.push(trace);
        }
    }
    if let Some((key, path)) = Found::subkey(&seven, &at, "FM") {
        let values = f.values(&key, &path);
        for item in ["PanelPath0", "PanelPath1"] {
            let Some(value) = find(&values, item) else {
                continue;
            };
            let (text, raw, why) = text_of(value);
            if text.is_none() && why.is_none() {
                continue;
            }
            let mut trace = AppTrace::of_value(App::SevenZip, item, &key, &path, value);
            trace.path = text;
            trace.data_raw = raw;
            trace.problems.extend(why);
            f.records.push(trace);
        }
    }
}

/// WinZip's history.
fn winzip(f: &mut Found) {
    let Some((winzip, at)) = f.key(r"Software\Nico Mak Computing\WinZip") else {
        return;
    };
    for item in ["filemenu", "extract", r"mru\archives"] {
        let mut key = Some((winzip, at.clone()));
        for part in item.split('\\') {
            key = key.and_then(|(k, p)| Found::subkey(&k, &p, part));
        }
        if let Some((key, path)) = key {
            numbered(f, App::WinZip, item, &key, &path);
        }
    }
}

/// OneDrive account values given as [`AppTrace::details`].
const ONEDRIVE_DETAILS: [&str; 9] = [
    "DisplayName",
    "UserName",
    "UserCID",
    "cid",
    "Business",
    "ConfiguredTenantId",
    "ServiceEndpointUri",
    "SPOResourceId",
    "ClientFirstSignInTimestamp",
];

/// OneDrive's accounts and their synced folders.
fn onedrive(f: &mut Found) {
    let Some((accounts, at)) = f.key(r"Software\Microsoft\OneDrive\Accounts") else {
        return;
    };
    for (account, path) in f.subkeys(&accounts, &at) {
        let name = account.name();
        let values = f.values(&account, &path);
        let mut trace = AppTrace::new(App::OneDrive, &name, &account, &path);
        let read = |trace: &mut AppTrace, value_name: &str| -> Option<String> {
            let value = find(&values, value_name)?;
            trace.replayed |= value.status() == Status::Replayed;
            let (text, raw, why) = text_of(value);
            if let Some(why) = why {
                trace.problems.push(format!("{value_name}: {why}"));
                if trace.data_raw.is_none() {
                    trace.data_raw = raw;
                }
            }
            text
        };
        trace.value = read(&mut trace, "UserEmail");
        trace.path = read(&mut trace, "UserFolder");
        for detail in ONEDRIVE_DETAILS {
            if let Some(text) = read(&mut trace, detail) {
                trace.details.push((detail.to_owned(), text));
            }
        }
        f.records.push(trace);
        // synced libraries: scope id → local folder
        if let Some((key, key_path)) =
            Found::subkey(&account, &path, "ScopeIdToMountPointPathCache")
        {
            let item = format!(r"{name}\ScopeIdToMountPointPathCache");
            for value in f.values(&key, &key_path) {
                let mut trace = AppTrace::of_value(App::OneDrive, &item, &key, &key_path, &value);
                let (text, raw, why) = text_of(&value);
                trace.value = Some(value.name()).filter(|n| !n.is_empty());
                trace.path = text;
                trace.data_raw = raw;
                trace.problems.extend(why);
                f.records.push(trace);
            }
        }
        // synced folders by tenant: local folder → 1
        if let Some((tenants, tenants_at)) = Found::subkey(&account, &path, "Tenants") {
            for (tenant, tenant_at) in f.subkeys(&tenants, &tenants_at) {
                let item = format!(r"{name}\Tenants\{}", tenant.name());
                for value in f.values(&tenant, &tenant_at) {
                    let mut trace =
                        AppTrace::of_value(App::OneDrive, &item, &tenant, &tenant_at, &value);
                    trace.path = Some(value.name()).filter(|n| !n.is_empty());
                    let (text, raw, why) = text_of(&value);
                    trace.value = text;
                    trace.data_raw = raw;
                    trace.problems.extend(why);
                    f.records.push(trace);
                }
            }
        }
    }
}

/// Adobe document values given as [`AppTrace::details`], beside its path.
const ADOBE_DETAILS: [&str; 5] = ["tFileName", "uFileSize", "uPageCount", "sDate", "aFS"];

/// The text of an Adobe value: a string, or (`s…` values) `REG_BINARY` text ended by a NUL.
fn adobe_text(value: &Value) -> (Option<String>, Option<Vec<u8>>, Option<String>) {
    if value.value_type() != ValueType::Binary {
        return text_of(value);
    }
    let (bytes, why) = value.read_data();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    match std::str::from_utf8(&bytes[..end]) {
        Ok(text) if why.is_none() => (Some(text.to_owned()).filter(|t| !t.is_empty()), None, None),
        Ok(text) => (Some(text.to_owned()), Some(bytes), why),
        Err(_) => (None, Some(bytes), Some("is not UTF-8 text".to_owned())),
    }
}

/// Adobe Acrobat's and Reader's recent files and folders.
fn adobe(f: &mut Found) {
    for (product, app) in [
        ("Acrobat Reader", App::AdobeReader),
        ("Adobe Acrobat", App::AdobeAcrobat),
    ] {
        let Some((versions, at)) = f.key(&format!(r"Software\Adobe\{product}")) else {
            continue;
        };
        for (version, version_at) in f.subkeys(&versions, &at) {
            let Some((general, general_at)) = Found::subkey(&version, &version_at, "AVGeneral")
            else {
                continue;
            };
            for item in ["cRecentFiles", "cRecentFolders"] {
                let Some((list, list_at)) = Found::subkey(&general, &general_at, item) else {
                    continue;
                };
                let mut traces = Vec::new();
                for (entry, entry_at) in f.subkeys(&list, &list_at) {
                    let values = f.values(&entry, &entry_at);
                    let mut trace = AppTrace::new(app, item, &entry, &entry_at);
                    trace.mru_position = position(&entry.name());
                    trace.details.push(("Version".to_owned(), version.name()));
                    let read = |trace: &mut AppTrace, name: &str| -> Option<String> {
                        let value = find(&values, name)?;
                        trace.replayed |= value.status() == Status::Replayed;
                        let (text, raw, why) = adobe_text(value);
                        if let Some(why) = why {
                            trace.problems.push(format!("{name}: {why}"));
                            if trace.data_raw.is_none() {
                                trace.data_raw = raw;
                            }
                        }
                        text
                    };
                    // tDIText, else sDI: the same path, as text and as bytes
                    trace.path = read(&mut trace, "tDIText").or_else(|| read(&mut trace, "sDI"));
                    for detail in ADOBE_DETAILS {
                        if let Some(text) = read(&mut trace, detail) {
                            trace.details.push((detail.to_owned(), text));
                        }
                    }
                    traces.push(trace);
                }
                traces.sort_by_key(|t| (t.mru_position.is_none(), t.mru_position));
                f.records.extend(traces);
            }
        }
    }
}

/// Every value of the key at `path` (and, with `versions`, of its `Version<N>` subkeys), one
/// trace each; a list's items one each, with their positions.
fn settings(f: &mut Found, app: App, path: &str, versions: bool) {
    let Some((key, at)) = f.key(path) else {
        return;
    };
    let mut keys = vec![(key, at.clone())];
    if versions {
        keys.extend(f.subkeys(&key, &at).into_iter().filter(|(k, _)| {
            k.name()
                .get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case("Version"))
        }));
    }
    for (key, key_path) in keys {
        for value in f.values(&key, &key_path) {
            let name = value.name();
            let item = if name.is_empty() { "(default)" } else { &name };
            if value.value_type() == ValueType::MultiSz {
                let (bytes, why) = value.read_data();
                if let Data::MultiText { values, lossy } = decode(value.data_type(), &bytes) {
                    let problem = why.or_else(|| {
                        lossy.then(|| "is not valid UTF-16: decoded lossily".to_owned())
                    });
                    for (n, text) in (0u32..).zip(values) {
                        let mut trace = AppTrace::of_value(app, item, &key, &key_path, &value);
                        trace.mru_position = Some(n);
                        trace.value = Some(text).filter(|t| !t.is_empty());
                        if let Some(problem) = &problem {
                            trace.problems.push(problem.clone());
                            trace.data_raw = Some(bytes.clone());
                        }
                        f.records.push(trace);
                    }
                    continue;
                }
            }
            let mut trace = AppTrace::of_value(app, item, &key, &key_path, &value);
            let (text, raw, why) = text_of(&value);
            trace.value = text;
            trace.data_raw = raw;
            trace.problems.extend(why);
            f.records.push(trace);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions() {
        assert_eq!(position("0"), Some(0));
        assert_eq!(position("12"), Some(12));
        assert_eq!(position("filemenu1"), Some(0));
        assert_eq!(position("c3"), Some(2));
        assert_eq!(position("extract0"), None);
        assert_eq!(position("MRUList"), None);
        assert_eq!(position(""), None);
        assert_eq!(position("x9999999999"), None);
        assert_eq!(position("é1"), Some(0));
    }

    #[test]
    fn utf16_lists() {
        let list = |items: &[&str]| -> Vec<u8> {
            let mut b: Vec<u8> = items
                .iter()
                .flat_map(|s| s.encode_utf16().chain([0]))
                .flat_map(u16::to_le_bytes)
                .collect();
            b.extend([0, 0]);
            b
        };
        assert_eq!(
            utf16_list(&list(&[r"C:\a.7z", r"D:\b.zip"])),
            Ok(vec![r"C:\a.7z".to_owned(), r"D:\b.zip".to_owned()])
        );
        assert_eq!(utf16_list(&[]), Ok(Vec::new()));
        assert_eq!(utf16_list(&[0, 0]), Ok(Vec::new()));
        let mut odd = list(&["a"]);
        odd.push(0x41);
        assert!(utf16_list(&odd).is_err());
        assert_eq!(
            utf16_list(&[0x41, 0, 0x00, 0xd8, 0, 0]),
            Err((
                vec!["A\u{fffd}".to_owned()],
                "is not a list of valid UTF-16 strings".to_owned()
            ))
        );
        assert_eq!(App::SevenZip.name(), "7-Zip");
    }
}
