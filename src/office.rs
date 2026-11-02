//! Microsoft Office in `NTUSER.DAT`: the documents and folders each application opened last, the
//! documents whose editing or macros the user enabled, and the settings that decide whether
//! macros run.
//!
//! Under `Software\Microsoft\Office\<version>\<application>` (`16.0\Word`, …):
//!
//! - `File MRU` and `Place MRU` (Office 2007 and later): the documents and folders opened last,
//!   `Item 1` the most recent, each `[F00000000][T<FILETIME>][O00000000]*<path>`: bracketed
//!   fields (`F` flags, `T` the last-opened time as hexadecimal, `O`), then `*` and the path.
//!   Microsoft 365 keeps a list per account too: `User MRU\<account>\File MRU` and `Place MRU`.
//! - `Security\Trusted Documents\TrustRecords` (Office 2010 and later): a value per document whose
//!   editing or macros the user enabled, named after its path (`%USERPROFILE%/…` or a `file://`
//!   URL); 24 bytes: the FILETIME it was trusted, 12 bytes, and its flags, the last 4 bytes:
//!   `0x7FFFFFFF` when its macros were enabled, `1` when only its editing was.
//! - `Security`: `VBAWarnings`, `BlockContentExecutionFromInternet` and `AccessVBOM`; and
//!   `Security\Trusted Locations`: its values, and a subkey per folder whose documents' macros
//!   run without asking (`Path`, `AllowSubFolders`, `Date`, `Description`). The same settings and
//!   locations set by policy are under `Software\Policies\Microsoft\Office\<version>\<application>`.
//!
//! Times: a list key's last-write time changes when an item moves to its top; each item and
//! trust record carries its own time.

use crate::bytes::{u32_at, u64_at};
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use std::fmt::Write as _;

/// Where Office keeps its settings, under the hive's root.
pub const OFFICE: &str = r"Software\Microsoft\Office";
/// Where Office's policies are, under the hive's root.
pub const OFFICE_POLICIES: &str = r"Software\Policies\Microsoft\Office";

/// The `Security` values read: what decides whether macros run.
const SECURITY_SETTINGS: [&str; 3] = [
    "VBAWarnings",
    "BlockContentExecutionFromInternet",
    "AccessVBOM",
];

/// The flags of a trust record whose macros were enabled.
pub const MACROS_ENABLED: u32 = 0x7fff_ffff;

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OfficeList {
    /// A document an application opened (`File MRU`).
    FileMru,
    /// A folder an application opened a document in (`Place MRU`).
    PlaceMru,
    /// A document whose editing or macros the user enabled (`TrustRecords`).
    TrustRecords,
    /// A trusted location, or a setting of `Trusted Locations` itself.
    TrustedLocations,
    /// A macro setting of `Security`.
    Security,
}

impl OfficeList {
    /// Its key's name: `File MRU`, `Place MRU`, `TrustRecords`, `Trusted Locations`, `Security`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            OfficeList::FileMru => "File MRU",
            OfficeList::PlaceMru => "Place MRU",
            OfficeList::TrustRecords => "TrustRecords",
            OfficeList::TrustedLocations => "Trusted Locations",
            OfficeList::Security => "Security",
        }
    }
}

/// One entry: an item of a `File MRU` or `Place MRU`, a trust record, a trusted location, or a
/// macro setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficeEntry {
    /// What it is.
    pub list: OfficeList,
    /// The Office version's key: `16.0` (2016 and later, Microsoft 365), `15.0` (2013), `14.0`
    /// (2010), `12.0` (2007), …
    pub office_version: String,
    /// The application's key: `Word`, `Excel`, `PowerPoint`, …
    pub application: String,
    /// The account of a Microsoft 365 `User MRU` list (`ADAL_…`, `LiveId_…`).
    pub account: Option<String>,
    /// Whether it is set by policy (`Software\Policies\Microsoft\Office`).
    pub policy: bool,
    /// The key it is in, under the hive's root.
    pub key_path: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// The value's name: `Item 1`, the trusted document's path, `VBAWarnings`; a trusted
    /// location's subkey (`Location0`).
    pub value_name: String,
    /// An item's place in its list (`Item 1`: 0, the most recent).
    pub mru_position: Option<u32>,
    /// The document or folder: an item's path, a trust record's name, a location's `Path`.
    pub path: Option<String>,
    /// When an item was last opened (FILETIME), from its `T` field.
    pub last_opened: Option<u64>,
    /// An item's `F` field.
    pub item_flags: Option<u32>,
    /// When a document was trusted (FILETIME).
    pub trusted_at: Option<u64>,
    /// A trust record's flags (its last 4 bytes).
    pub trust_flags: Option<u32>,
    /// Whether a trusted document's macros were enabled (`trust_flags` is [`MACROS_ENABLED`]).
    pub macros_enabled: Option<bool>,
    /// A setting's value (`1`), or a trusted location's other values (`AllowSubFolders=1;
    /// Description=…`).
    pub value: Option<String>,
    /// The value's data, when it doesn't decode (see `problems`).
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the value or its key.
    pub replayed: bool,
    /// What keeps it from being read.
    pub problems: Vec<String>,
}

/// A `File MRU` or `Place MRU` item's text, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MruItem<'a> {
    /// The `F` field.
    pub flags: Option<u32>,
    /// The `T` field: when it was last opened (FILETIME).
    pub last_opened: Option<u64>,
    /// The path after `*`.
    pub path: &'a str,
}

/// A `File MRU` or `Place MRU` item's text: its bracketed fields, then `*` and the path.
///
/// # Errors
/// When it has no `*` after its fields, a field isn't closed, or `F` or `T` isn't hexadecimal.
pub fn mru_item(text: &str) -> Result<MruItem<'_>, String> {
    let mut item = MruItem {
        flags: None,
        last_opened: None,
        path: "",
    };
    let mut rest = text;
    while let Some(field) = rest.strip_prefix('[') {
        let Some(end) = field.find(']') else {
            return Err("a field has no closing ]".to_owned());
        };
        let mut chars = field[..end].chars();
        let name = chars.next();
        let digits = chars.as_str();
        match name {
            Some('F') => {
                item.flags = Some(
                    u32::from_str_radix(digits, 16)
                        .map_err(|_| format!("F{digits} is not hexadecimal flags"))?,
                );
            }
            Some('T') => {
                item.last_opened = Some(
                    u64::from_str_radix(digits, 16)
                        .map_err(|_| format!("T{digits} is not a hexadecimal FILETIME"))?,
                )
                .filter(|&t| t != 0);
            }
            _ => {}
        }
        rest = &field[end + 1..];
    }
    if let Some(time) = item.last_opened
        && crate::data::filetime(time).is_none()
    {
        return Err(format!("last-opened FILETIME 0x{time:016x} is past 9999"));
    }
    item.path = rest
        .strip_prefix('*')
        .ok_or_else(|| "no * before the path".to_owned())?;
    Ok(item)
}

/// A trust record's data: when the document was trusted (FILETIME; `None` when 0) and its flags.
///
/// # Errors
/// When it isn't 24 bytes.
pub fn trust_record(bytes: &[u8]) -> Result<(Option<u64>, u32), String> {
    if bytes.len() != 24 {
        return Err(format!(
            "{} bytes, not the 24 of a trust record",
            bytes.len()
        ));
    }
    let time = u64_at(bytes, 0).filter(|&t| t != 0);
    if let Some(time) = time
        && crate::data::filetime(time).is_none()
    {
        return Err(format!("trusted-at FILETIME 0x{time:016x} is past 9999"));
    }
    Ok((time, u32_at(bytes, 20).unwrap_or(0)))
}

/// What a macro setting's number means: `VBAWarnings` 1 to 4, `BlockContentExecutionFromInternet`
/// and `AccessVBOM` 0 or 1.
#[must_use]
pub fn setting_meaning(setting: &str, number: u64) -> Option<&'static str> {
    Some(match (setting.to_ascii_lowercase().as_str(), number) {
        ("vbawarnings", 1) => "all macros enabled",
        ("vbawarnings", 2) => "macros disabled with notification",
        ("vbawarnings", 3) => "macros disabled except digitally signed ones",
        ("vbawarnings", 4) => "macros disabled without notification",
        ("blockcontentexecutionfrominternet", 0) => "macros in files from the Internet not blocked",
        ("blockcontentexecutionfrominternet", 1) => "macros in files from the Internet blocked",
        ("accessvbom", 0) => "the VBA project object model not trusted",
        ("accessvbom", 1) => "the VBA project object model trusted",
        _ => return None,
    })
}

/// Every entry of Office's lists and macro settings in `hive`: per version and application (in
/// the hive's order), `File MRU`, `Place MRU`, each account's `User MRU` lists, `TrustRecords`,
/// `Security`'s settings and `Trusted Locations`; then the same settings set by policy. Also what
/// keeps keys from being read (each starting with the key's path). `None` when the hive has
/// neither [`OFFICE`] nor [`OFFICE_POLICIES`].
#[must_use]
pub fn office(hive: &Hive) -> Option<(Vec<OfficeEntry>, Vec<String>)> {
    let user = hive.key(OFFICE);
    let policies = hive.key(OFFICE_POLICIES);
    if user.is_none() && policies.is_none() {
        return None;
    }
    let mut out = Reader::default();
    for (root, path, policy) in [(user, OFFICE, false), (policies, OFFICE_POLICIES, true)] {
        let Some(root) = root else {
            continue;
        };
        for (version, version_path) in out.subkeys(&root, path) {
            let name = version.name();
            if !is_version(&name) {
                continue;
            }
            for (app, app_path) in out.subkeys(&version, &version_path) {
                let at = Place {
                    office_version: name.clone(),
                    application: app.name(),
                    account: None,
                    policy,
                };
                if !policy {
                    for list in [OfficeList::FileMru, OfficeList::PlaceMru] {
                        if let Some(key) = app.subkey(list.name()) {
                            let key_path = format!(r"{app_path}\{}", list.name());
                            out.mru(list, &at, &key, &key_path);
                        }
                    }
                    if let Some(users) = app.subkey("User MRU") {
                        let users_path = format!(r"{app_path}\User MRU");
                        for (account, account_path) in out.subkeys(&users, &users_path) {
                            let at = Place {
                                account: Some(account.name()),
                                ..at.clone()
                            };
                            for list in [OfficeList::FileMru, OfficeList::PlaceMru] {
                                if let Some(key) = account.subkey(list.name()) {
                                    let key_path = format!(r"{account_path}\{}", list.name());
                                    out.mru(list, &at, &key, &key_path);
                                }
                            }
                        }
                    }
                }
                if let Some(security) = app.subkey("Security") {
                    let security_path = format!(r"{app_path}\Security");
                    if let Some(records) = security
                        .subkey("Trusted Documents")
                        .and_then(|k| k.subkey("TrustRecords"))
                    {
                        let records_path =
                            format!(r"{security_path}\Trusted Documents\TrustRecords");
                        out.trust_records(&at, &records, &records_path);
                    }
                    out.settings(&at, &security, &security_path);
                    if let Some(locations) = security.subkey("Trusted Locations") {
                        let locations_path = format!(r"{security_path}\Trusted Locations");
                        out.locations(&at, &locations, &locations_path);
                    }
                }
            }
        }
    }
    Some((out.entries, out.problems))
}

/// Whether a key's name is an Office version's: digits, a dot, digits (`16.0`).
fn is_version(name: &str) -> bool {
    name.split_once('.').is_some_and(|(major, minor)| {
        !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|b| b.is_ascii_digit())
            && minor.bytes().all(|b| b.is_ascii_digit())
    })
}

/// Where entries are: version, application, account, policy.
#[derive(Debug, Clone)]
struct Place {
    office_version: String,
    application: String,
    account: Option<String>,
    policy: bool,
}

/// The entries and problems read so far.
#[derive(Default)]
struct Reader {
    entries: Vec<OfficeEntry>,
    problems: Vec<String>,
}

impl Reader {
    /// The subkeys of `key` (at `path`) with their paths; what keeps others from being read is a
    /// problem.
    fn subkeys<'h>(&mut self, key: &Key<'h>, path: &str) -> Vec<(Key<'h>, String)> {
        let (subkeys, why) = key.subkeys();
        self.problems
            .extend(why.into_iter().map(|w| format!("{path}: {w}")));
        subkeys
            .into_iter()
            .map(|k| {
                let p = format!(r"{path}\{}", k.name());
                (k, p)
            })
            .collect()
    }

    /// The values of `key` (at `path`); what keeps others from being read is a problem.
    fn values<'h>(&mut self, key: &Key<'h>, path: &str) -> Vec<Value<'h>> {
        let (values, why) = key.values();
        self.problems
            .extend(why.into_iter().map(|w| format!("{path}: {w}")));
        values
    }

    /// An entry of `list` at `at`, in `key` (at `path`), for `value`.
    fn entry(list: OfficeList, at: &Place, key: &Key, path: &str, value: &Value) -> OfficeEntry {
        OfficeEntry {
            list,
            office_version: at.office_version.clone(),
            application: at.application.clone(),
            account: at.account.clone(),
            policy: at.policy,
            key_path: path.to_owned(),
            key_last_written: key.last_written(),
            value_name: value.name(),
            mru_position: None,
            path: None,
            last_opened: None,
            item_flags: None,
            trusted_at: None,
            trust_flags: None,
            macros_enabled: None,
            value: None,
            data_raw: None,
            replayed: key.status() == Status::Replayed || value.status() == Status::Replayed,
            problems: Vec::new(),
        }
    }

    /// The items of a `File MRU` or `Place MRU` key (`Item 1`, `Item 2`, …), by their numbers.
    fn mru(&mut self, list: OfficeList, at: &Place, key: &Key, path: &str) {
        let mut items: Vec<(u32, OfficeEntry)> = Vec::new();
        for value in self.values(key, path) {
            let name = value.name();
            let Some(n) = name
                .get(..5)
                .filter(|p| p.eq_ignore_ascii_case("Item "))
                .and_then(|_| name[5..].parse::<u32>().ok())
                .filter(|n| *n >= 1 && n.to_string() == name[5..])
            else {
                // `Max Display`, `Item Metadata N`, `FOLDERID_…`: not items
                continue;
            };
            let mut entry = Self::entry(list, at, key, path, &value);
            entry.mru_position = Some(n - 1);
            if items.iter().any(|(m, _)| *m == n) {
                entry
                    .problems
                    .push(format!("another value is item {n} too"));
            }
            let (text, mut problems) = text_of(&value);
            match text.as_deref().map(mru_item) {
                Some(Ok(item)) => {
                    entry.path = Some(item.path.to_owned());
                    entry.last_opened = item.last_opened;
                    entry.item_flags = item.flags;
                }
                Some(Err(why)) => problems.push(why),
                None => {}
            }
            finish(&mut entry, &value, problems);
            items.push((n, entry));
        }
        items.sort_by_key(|(n, _)| *n);
        self.entries.extend(items.into_iter().map(|(_, e)| e));
    }

    /// The trust records of a `TrustRecords` key.
    fn trust_records(&mut self, at: &Place, key: &Key, path: &str) {
        for value in self.values(key, path) {
            let mut entry = Self::entry(OfficeList::TrustRecords, at, key, path, &value);
            entry.path = Some(entry.value_name.clone());
            let (bytes, read_problem) = value.read_data();
            let mut problems: Vec<String> = read_problem.into_iter().collect();
            if value.value_type() != ValueType::Binary {
                problems.push(format!("is {}, not REG_BINARY", value.value_type().name()));
            }
            match trust_record(&bytes) {
                Ok((time, flags)) => {
                    entry.trusted_at = time;
                    entry.trust_flags = Some(flags);
                    entry.macros_enabled = match flags {
                        MACROS_ENABLED => Some(true),
                        1 => Some(false),
                        flags => {
                            problems.push(format!("trust flags 0x{flags:08x} are not recognized"));
                            None
                        }
                    };
                }
                Err(why) => problems.push(why),
            }
            if !problems.is_empty() {
                entry.data_raw = Some(bytes);
            }
            entry.problems = problems;
            self.entries.push(entry);
        }
    }

    /// The macro settings among `Security`'s values.
    fn settings(&mut self, at: &Place, key: &Key, path: &str) {
        for value in self.values(key, path) {
            let name = value.name();
            if !SECURITY_SETTINGS
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&name))
            {
                continue;
            }
            let mut entry = Self::entry(OfficeList::Security, at, key, path, &value);
            let (text, problems) = setting_text(&value);
            entry.value = text;
            finish(&mut entry, &value, problems);
            self.entries.push(entry);
        }
    }

    /// The values of `Trusted Locations` itself (`AllowNetworkLocations`, …), then each location:
    /// its `Path`, and its other values as `name=value`, by name.
    fn locations(&mut self, at: &Place, key: &Key, path: &str) {
        for value in self.values(key, path) {
            let mut entry = Self::entry(OfficeList::TrustedLocations, at, key, path, &value);
            let (text, problems) = setting_text(&value);
            entry.value = text;
            finish(&mut entry, &value, problems);
            self.entries.push(entry);
        }
        for (location, location_path) in self.subkeys(key, path) {
            let values = self.values(&location, &location_path);
            let mut entry = OfficeEntry {
                value_name: location.name(),
                key_path: location_path.clone(),
                key_last_written: location.last_written(),
                replayed: location.status() == Status::Replayed,
                ..Self::entry_without_value(OfficeList::TrustedLocations, at)
            };
            let mut others: Vec<(String, String)> = Vec::new();
            for value in &values {
                entry.replayed |= value.status() == Status::Replayed;
                let name = value.name();
                let (text, problems) = if name.eq_ignore_ascii_case("Path") {
                    text_of(value)
                } else {
                    setting_text(value)
                };
                if !problems.is_empty() && entry.data_raw.is_none() {
                    entry.data_raw = Some(value.read_data().0);
                }
                entry
                    .problems
                    .extend(problems.into_iter().map(|p| format!("{name}: {p}")));
                if name.eq_ignore_ascii_case("Path") {
                    entry.path = text.filter(|p| !p.is_empty());
                } else {
                    others.push((name, text.unwrap_or_default()));
                }
            }
            if entry.path.is_none() {
                entry.problems.push("it has no Path".to_owned());
            }
            others.sort();
            entry.value = (!others.is_empty()).then(|| {
                others
                    .iter()
                    .map(|(n, v)| format!("{n}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            });
            self.entries.push(entry);
        }
    }

    /// An entry of `list` at `at` with no key or value yet.
    fn entry_without_value(list: OfficeList, at: &Place) -> OfficeEntry {
        OfficeEntry {
            list,
            office_version: at.office_version.clone(),
            application: at.application.clone(),
            account: at.account.clone(),
            policy: at.policy,
            key_path: String::new(),
            key_last_written: 0,
            value_name: String::new(),
            mru_position: None,
            path: None,
            last_opened: None,
            item_flags: None,
            trusted_at: None,
            trust_flags: None,
            macros_enabled: None,
            value: None,
            data_raw: None,
            replayed: false,
            problems: Vec::new(),
        }
    }
}

/// `entry`'s problems, with its value's bytes kept when there are any.
fn finish(entry: &mut OfficeEntry, value: &Value, problems: Vec<String>) {
    if !problems.is_empty() {
        entry.data_raw = Some(value.read_data().0);
    }
    entry.problems.extend(problems);
}

/// A string value's text, and what is wrong with it.
fn text_of(value: &Value) -> (Option<String>, Vec<String>) {
    let (bytes, read_problem) = value.read_data();
    let mut problems: Vec<String> = read_problem.into_iter().collect();
    if !matches!(value.value_type(), ValueType::Sz | ValueType::ExpandSz) {
        problems.push(format!("is {}, not REG_SZ", value.value_type().name()));
    }
    // read as REG_SZ whatever its type says
    match decode(1, &bytes) {
        Data::Text { value, lossy } => {
            if lossy {
                problems.push("its text is not valid UTF-16: decoded lossily".to_owned());
            }
            (Some(value), problems)
        }
        _ => (None, problems),
    }
}

/// A setting's value as text: a number (`REG_DWORD`, `REG_QWORD`) with what it means, or text;
/// and what is wrong with it.
fn setting_text(value: &Value) -> (Option<String>, Vec<String>) {
    let (bytes, read_problem) = value.read_data();
    let mut problems: Vec<String> = read_problem.into_iter().collect();
    let text = match decode(value.data_type(), &bytes) {
        Data::Number(n) => Some(match setting_meaning(&value.name(), n) {
            Some(meaning) => format!("{n} ({meaning})"),
            None => n.to_string(),
        }),
        Data::Text { value, lossy } => {
            if lossy {
                problems.push("its text is not valid UTF-16: decoded lossily".to_owned());
            }
            Some(value)
        }
        Data::MultiText { values, lossy } => {
            if lossy {
                problems.push("its multi-string is not valid UTF-16: decoded lossily".to_owned());
            }
            Some(values.join("|"))
        }
        Data::Malformed(why) => {
            problems.push(why);
            None
        }
        Data::Bytes | Data::Undecoded => Some(bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })),
    };
    (text, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_office_times_are_reported() {
        assert!(mru_item("[TFFFFFFFFFFFFFFFF]*C:\\document.docx").is_err());
        let mut record = vec![0xff; 8];
        record.extend([0u8; 16]);
        assert!(trust_record(&record).is_err());
    }

    #[test]
    fn mru_items() {
        assert_eq!(
            mru_item(r"[F00000000][T01D86AF6D3C287B0][O00000000]*C:\Users\a\b.xlsx"),
            Ok(MruItem {
                flags: Some(0),
                last_opened: Some(0x01D8_6AF6_D3C2_87B0),
                path: r"C:\Users\a\b.xlsx"
            })
        );
        // Office 2007: no O field; a pinned item's flags
        assert_eq!(
            mru_item(r"[F00000001][T01C8000000000000]*\\server\share\c.doc"),
            Ok(MruItem {
                flags: Some(1),
                last_opened: Some(0x01C8_0000_0000_0000),
                path: r"\\server\share\c.doc"
            })
        );
        assert_eq!(mru_item("[T0]*x").map(|i| i.last_opened), Ok(None));
        assert_eq!(
            mru_item(r"C:\no\fields"),
            Err("no * before the path".to_owned())
        );
        assert_eq!(
            mru_item("[F00000000][T01D8"),
            Err("a field has no closing ]".to_owned())
        );
        assert_eq!(
            mru_item("[TXYZ]*a"),
            Err("TXYZ is not a hexadecimal FILETIME".to_owned())
        );
        assert_eq!(
            mru_item("[Fzz]*a"),
            Err("Fzz is not hexadecimal flags".to_owned())
        );
        assert_eq!(mru_item("[]*a").map(|i| i.path), Ok("a"));
        assert_eq!(mru_item("[é]*a").map(|i| i.path), Ok("a"));
    }

    #[test]
    fn trust_records_and_settings() {
        let mut bytes = 0x01D8_28E7_499B_E577_u64.to_le_bytes().to_vec();
        bytes.extend([0, 0xd0, 0x88, 0xc3, 0x10, 0, 0, 0, 0x32, 0x82, 0xa2, 0x01]);
        bytes.extend(MACROS_ENABLED.to_le_bytes());
        assert_eq!(
            trust_record(&bytes),
            Ok((Some(0x01D8_28E7_499B_E577), MACROS_ENABLED))
        );
        assert_eq!(
            trust_record(&bytes[..20]),
            Err("20 bytes, not the 24 of a trust record".to_owned())
        );
        assert_eq!(trust_record(&[0; 24]), Ok((None, 0)));
        assert_eq!(
            setting_meaning("VBAWarnings", 1),
            Some("all macros enabled")
        );
        assert_eq!(setting_meaning("vbawarnings", 9), None);
        assert_eq!(setting_meaning("Level", 1), None);
        assert!(is_version("16.0") && is_version("12.0"));
        assert!(!is_version("Common") && !is_version("16.") && !is_version(".0"));
        assert_eq!(OfficeList::TrustedLocations.name(), "Trusted Locations");
    }
}
