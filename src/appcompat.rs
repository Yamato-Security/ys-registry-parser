//! Application compatibility data beyond the `ShimCache` and Amcache, under
//! `Microsoft\Windows NT\CurrentVersion\AppCompatFlags` in `SOFTWARE` ([`software`]) and a
//! user's `NTUSER.DAT` ([`ntuser`]). One [`AppCompatEntry`] per program, module use or shim
//! database:
//!
//! - **Compatibility layers** (`Layers`, in both hives, and `SOFTWARE`'s `Wow6432Node`): each
//!   program (the value's name) with the layers it runs with (its data: `~ RUNASADMIN WIN7RTM`).
//! - **Program Compatibility Assistant** (`NTUSER.DAT`'s `Compatibility Assistant\Store`, Windows
//!   8 and later, and `Compatibility Assistant\Persisted`, Windows 7): each program Windows saw
//!   run (the value's name; `SIGN.MEDIA=<id> <path>` for a program on removable media). A `Store`
//!   value's data is a `SACP` record, kept as it is (see [`AppCompatEntry::data_raw`]): on Windows
//!   8.1, 10 and 11 the time in it (at offset 0x2C) is shared by the programs of a hive (one or two
//!   values, dates Windows builds were made), not when a program ran, so no time is taken from it.
//! - **CIT** (`SOFTWARE`'s `CIT\Module\<module>`): the programs that loaded each tracked module
//!   (the value's name) and when they last did (its `REG_QWORD` data); and `CIT\System`'s
//!   databases (Windows 7 to early Windows 10): each value is LZNT1-compressed
//!   ([`lznt1`]): the size of the compressed data plus 8, the size of the data uncompressed, then
//!   the data; the program paths and command lines found in it, as UTF-16 strings.
//! - **Custom shim databases** (`SOFTWARE`'s `InstalledSDB\{GUID}`: `DatabasePath`,
//!   `DatabaseDescription`, `DatabaseInstallTimeStamp`, `DatabaseType`; and `Custom\<program>`:
//!   each `{GUID}.sdb` value with its install time): databases installed with `sdbinst`, which
//!   can make Windows load a DLL into a program or run another one (MITRE ATT&CK T1546.011).

use crate::bytes::{u16_at, u32_at, utf16_units};
use crate::data::ValueType;
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{number, string};

/// Where the compatibility data is, under `SOFTWARE`'s root and `NTUSER.DAT`'s `Software`.
const APP_COMPAT_FLAGS: &str = r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags";
/// `CIT\Module` values that are not programs.
const CIT_MODULE_SETTINGS: [&str; 2] = ["OverflowQuota", "OverflowValue"];
/// The prefix of a Program Compatibility Assistant value name of a program on removable media.
const SIGN_MEDIA: &str = "SIGN.MEDIA=";

/// Where an [`AppCompatEntry`] comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AppCompatSource {
    /// `Layers`: a program's compatibility layers.
    Layers,
    /// `Compatibility Assistant\Store`.
    PcaStore,
    /// `Compatibility Assistant\Persisted`.
    PcaPersisted,
    /// `CIT\Module\<module>`: a program that loaded the module.
    CitModule,
    /// `CIT\System`: a program path or command line in a CIT database.
    CitSystem,
    /// `InstalledSDB\{GUID}`: an installed shim database.
    InstalledSdb,
    /// `Custom\<program>`: a shim database applied to a program.
    CustomSdb,
}

impl AppCompatSource {
    /// `layers`, `pca_store`, `pca_persisted`, `cit_module`, `cit_system`, `installed_sdb` or
    /// `custom_sdb`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            AppCompatSource::Layers => "layers",
            AppCompatSource::PcaStore => "pca_store",
            AppCompatSource::PcaPersisted => "pca_persisted",
            AppCompatSource::CitModule => "cit_module",
            AppCompatSource::CitSystem => "cit_system",
            AppCompatSource::InstalledSdb => "installed_sdb",
            AppCompatSource::CustomSdb => "custom_sdb",
        }
    }
}

/// One program, module use or shim database. Empty strings are left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCompatEntry {
    /// Where it comes from.
    pub source: AppCompatSource,
    /// Whether it is the machine's (`SOFTWARE`), not a user's (`NTUSER.DAT`).
    pub machine: bool,
    /// The program: a layer's, Program Compatibility Assistant's or CIT module's value name (the
    /// path on removable media after `SIGN.MEDIA=<id>`), a path or command line in a CIT
    /// database, or the program a custom shim database applies to (`Custom`'s key name).
    pub path: Option<String>,
    /// The compatibility layers a program runs with, as written (`~ RUNASADMIN WIN7RTM`).
    pub layers: Option<String>,
    /// When a program last loaded a CIT module (FILETIME).
    pub last_seen: Option<u64>,
    /// A shim database's GUID (`{…}`).
    pub sdb_guid: Option<String>,
    /// A shim database's file: `DatabasePath`, also for `Custom` when `InstalledSDB` names it.
    pub sdb_path: Option<String>,
    /// When a shim database was installed (FILETIME).
    pub sdb_installed: Option<u64>,
    /// More, as names and values: a CIT module's name, a CIT database's value name, a program's
    /// removable media id (`SignMedia`), a shim database's `DatabaseDescription` and
    /// `DatabaseType`.
    pub details: Vec<(String, String)>,
    /// Its key, under the hive's root, with the names as they are written.
    pub key_path: String,
    /// When its key was last written (FILETIME).
    pub key_last_written: u64,
    /// The value it comes from (`None` for a key: an installed shim database).
    pub value_name: Option<String>,
    /// Whether its key is under `Wow6432Node`.
    pub wow64: bool,
    /// The value's bytes: a Program Compatibility Assistant `Store` value's data (`SACP`), or
    /// data that isn't what it should be.
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote its key or value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl AppCompatEntry {
    fn new(source: AppCompatSource, machine: bool, key: &Key, key_path: &str) -> Self {
        AppCompatEntry {
            source,
            machine,
            path: None,
            layers: None,
            last_seen: None,
            sdb_guid: None,
            sdb_path: None,
            sdb_installed: None,
            details: Vec::new(),
            key_path: key_path.to_owned(),
            key_last_written: key.last_written(),
            value_name: None,
            wow64: false,
            data_raw: None,
            replayed: key.status() == Status::Replayed,
            problems: Vec::new(),
        }
    }

    /// The entry of `value`, of the key at `key_path`.
    fn of_value(
        source: AppCompatSource,
        machine: bool,
        key: &Key,
        key_path: &str,
        value: &Value,
    ) -> Self {
        let mut entry = AppCompatEntry::new(source, machine, key, key_path);
        entry.value_name = Some(value.name());
        entry.replayed |= value.status() == Status::Replayed;
        entry
    }

    /// A time from `value`: a `REG_QWORD`, or `REG_BINARY` of 8 bytes; else a problem and the
    /// bytes.
    fn time(&mut self, value: &Value) -> Option<u64> {
        let (bytes, why) = value.read_data();
        let time = match (value.value_type(), why) {
            (_, Some(why)) => Err(why),
            (ValueType::Qword | ValueType::Binary, None) if bytes.len() == 8 => Ok(
                u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or_default()),
            ),
            (kind, None) => Err(format!(
                "{} of {} bytes, not a time (REG_QWORD)",
                kind.name(),
                bytes.len()
            )),
        };
        match time {
            Ok(t) => Some(t),
            Err(why) => {
                self.problems.push(format!("{}: {why}", value.name()));
                self.data_raw = Some(bytes);
                None
            }
        }
    }

    /// The text of `value`; with a problem and its bytes when it isn't text.
    fn text(&mut self, value: &Value) -> Option<String> {
        self.replayed |= value.status() == Status::Replayed;
        let (text, why) = string(value);
        if let Some(why) = why {
            self.problems.push(format!("{}: {why}", value.name()));
            if self.data_raw.is_none() {
                self.data_raw = Some(value.read_data().0);
            }
        }
        text.filter(|t| !t.is_empty())
    }
}

/// The compatibility data of a `SOFTWARE` hive, and what kept parts of it from being read:
/// `Layers` (then `Wow6432Node`'s), `CIT\Module`, `CIT\System`, `InstalledSDB` and `Custom`
/// (then `Wow6432Node`'s).
#[must_use]
pub fn software(hive: &Hive) -> (Vec<AppCompatEntry>, Vec<String>) {
    let mut f = Found::new(hive);
    for (prefix, wow64) in [("", false), (r"Wow6432Node\", true)] {
        layers(&mut f, &format!(r"{prefix}{APP_COMPAT_FLAGS}"), true, wow64);
    }
    cit(&mut f, APP_COMPAT_FLAGS);
    for (prefix, wow64) in [("", false), (r"Wow6432Node\", true)] {
        shim_databases(&mut f, &format!(r"{prefix}{APP_COMPAT_FLAGS}"), wow64);
    }
    (f.records, f.problems)
}

/// The compatibility data of a user's `NTUSER.DAT`, and what kept parts of it from being read:
/// `Layers`, then the Program Compatibility Assistant's `Store` and `Persisted`.
#[must_use]
pub fn ntuser(hive: &Hive) -> (Vec<AppCompatEntry>, Vec<String>) {
    let mut f = Found::new(hive);
    let base = format!(r"Software\{APP_COMPAT_FLAGS}");
    layers(&mut f, &base, false, false);
    for (name, source) in [
        ("Store", AppCompatSource::PcaStore),
        ("Persisted", AppCompatSource::PcaPersisted),
    ] {
        let Some((key, at)) = f.key(&format!(r"{base}\Compatibility Assistant\{name}")) else {
            continue;
        };
        for value in f.values(&key, &at) {
            let mut entry = AppCompatEntry::of_value(source, false, &key, &at, &value);
            let name = value.name();
            match sign_media(&name) {
                Some((media, path)) => {
                    entry
                        .details
                        .push(("SignMedia".to_owned(), media.to_owned()));
                    entry.path = Some(path.to_owned()).filter(|p| !p.is_empty());
                }
                None => entry.path = Some(name).filter(|p| !p.is_empty()),
            }
            let (bytes, why) = value.read_data();
            if source == AppCompatSource::PcaStore {
                if !bytes.starts_with(b"SACP") {
                    entry.problems.push(
                        "is not a SACP record (Program Compatibility Assistant data)".to_owned(),
                    );
                }
                entry.data_raw = Some(bytes).filter(|b| !b.is_empty());
            } else if value.value_type() != ValueType::Dword {
                entry
                    .problems
                    .push(format!("is {}, not REG_DWORD", value.value_type().name()));
                entry.data_raw = Some(bytes).filter(|b| !b.is_empty());
            }
            entry.problems.extend(why);
            f.records.push(entry);
        }
    }
    (f.records, f.problems)
}

/// The removable media id and the path of a Program Compatibility Assistant value name
/// `SIGN.MEDIA=<id> <path>`; `None` for other names.
#[must_use]
pub fn sign_media(name: &str) -> Option<(&str, &str)> {
    let rest = name
        .get(..SIGN_MEDIA.len())
        .filter(|p| p.eq_ignore_ascii_case(SIGN_MEDIA))
        .map(|_| &name[SIGN_MEDIA.len()..])?;
    let (media, path) = rest.split_once(' ').unwrap_or((rest, ""));
    Some((media, path))
}

/// The records found so far, and what kept parts of the hive from being read.
struct Found<'h> {
    hive: &'h Hive,
    records: Vec<AppCompatEntry>,
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

/// Each program of the `Layers` key under `base`.
fn layers(f: &mut Found, base: &str, machine: bool, wow64: bool) {
    let Some((key, at)) = f.key(&format!(r"{base}\Layers")) else {
        return;
    };
    for value in f.values(&key, &at) {
        let mut entry =
            AppCompatEntry::of_value(AppCompatSource::Layers, machine, &key, &at, &value);
        entry.wow64 = wow64;
        entry.path = Some(value.name()).filter(|p| !p.is_empty());
        entry.layers = entry.text(&value).map(|t| t.trim().to_owned());
        f.records.push(entry);
    }
}

/// `CIT\Module`'s programs and `CIT\System`'s databases.
fn cit(f: &mut Found, base: &str) {
    if let Some((modules, at)) = f.key(&format!(r"{base}\CIT\Module")) {
        for (module, module_at) in f.subkeys(&modules, &at) {
            let name = module.name();
            for value in f.values(&module, &module_at) {
                let program = value.name();
                if CIT_MODULE_SETTINGS
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&program))
                {
                    continue;
                }
                let mut entry = AppCompatEntry::of_value(
                    AppCompatSource::CitModule,
                    true,
                    &module,
                    &module_at,
                    &value,
                );
                entry.path = Some(program).filter(|p| !p.is_empty());
                entry.details.push(("Module".to_owned(), name.clone()));
                entry.last_seen = entry.time(&value);
                f.records.push(entry);
            }
        }
    }
    if let Some((system, at)) = f.key(&format!(r"{base}\CIT\System")) {
        for value in f.values(&system, &at) {
            let (bytes, why) = value.read_data();
            if value.value_type() != ValueType::Binary {
                continue; // settings, not databases
            }
            let template =
                AppCompatEntry::of_value(AppCompatSource::CitSystem, true, &system, &at, &value);
            let decompressed = why.map_or_else(|| cit_database(&bytes), Err);
            match decompressed {
                Ok(data) => {
                    for text in program_strings(&data) {
                        let mut entry = template.clone();
                        entry.path = Some(text);
                        entry.details.push(("Database".to_owned(), value.name()));
                        f.records.push(entry);
                    }
                }
                Err(why) => {
                    let mut entry = template;
                    entry.details.push(("Database".to_owned(), value.name()));
                    entry.problems.push(why);
                    entry.data_raw = Some(bytes);
                    f.records.push(entry);
                }
            }
        }
    }
}

/// A CIT database's data, decompressed: `bytes` is the size of the compressed data plus 8, the
/// size of the data uncompressed, then the compressed data (LZNT1).
fn cit_database(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (Some(compressed), Some(size)) = (u32_at(bytes, 0), u32_at(bytes, 4)) else {
        return Err(format!(
            "{} bytes, fewer than a CIT database's 8-byte header",
            bytes.len()
        ));
    };
    let end = (compressed as usize).min(bytes.len());
    if (compressed as usize) < 8 || compressed as usize > bytes.len() {
        return Err(format!(
            "its header gives {compressed} bytes, the value has {}",
            bytes.len()
        ));
    }
    let data = lznt1(&bytes[8..end], size as usize)?;
    if data.len() == size as usize {
        Ok(data)
    } else {
        Err(format!(
            "{} bytes decompressed, its header gives {size}",
            data.len()
        ))
    }
}

/// The program paths and command lines in uncompressed CIT data: UTF-16 strings, at even
/// offsets, that start as a path does (`\Device\…`, `\??\…`, `\\server\…`, `C:\…`, `"C:\…`),
/// each once in their order.
fn program_strings(data: &[u8]) -> Vec<String> {
    let units = utf16_units(data);
    let mut found: Vec<String> = Vec::new();
    let mut i = 0;
    while i < units.len() {
        let end = units[i..]
            .iter()
            .position(|&u| u < 0x20 || (0xd800..0xe000).contains(&u))
            .map_or(units.len(), |n| i + n);
        if end > i {
            let text = String::from_utf16_lossy(&units[i..end]);
            if let Some(start) = path_start(&text) {
                let path = text[start..].to_owned();
                if !found.contains(&path) {
                    found.push(path);
                }
            }
        }
        i = end + 1;
    }
    found
}

/// Where a path starts in `text`, when one does: `\Device\…`, `\??\…`, `\\…`, `X:\…`, or the
/// same quoted.
fn path_start(text: &str) -> Option<usize> {
    let starts = |at: usize| {
        let rest = &text[at..];
        let unquoted = rest.strip_prefix('"').unwrap_or(rest);
        let b = unquoted.as_bytes();
        let device = unquoted
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"\Device\"));
        let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
        device || unquoted.starts_with(r"\??\") || unquoted.starts_with(r"\\") || drive
    };
    text.char_indices()
        .map(|(i, _)| i)
        .find(|&i| starts(i) && text.len() - i >= 4)
}

/// LZNT1-compressed `data` (Microsoft's MS-XCA 2.5) decompressed, at most `limit` bytes: chunks,
/// each a 2-byte header (its size less 3 in the low 12 bits, whether it is compressed in the
/// top bit), then its data: as it is, or groups of a flag byte and 8 items, a literal byte for
/// a 0 bit and a 2-byte copy of earlier data for a 1 bit, whose offset and length bits are split
/// by how much of the chunk is decompressed.
///
/// # Errors
/// When a chunk is cut short or a copy reaches before its chunk.
pub fn lznt1(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0;
    while at < data.len() && out.len() < limit {
        let Some(header) = u16_at(data, at) else {
            break;
        };
        if header == 0 {
            break;
        }
        let size = usize::from(header & 0x0fff) + 1;
        let chunk = data
            .get(at + 2..at + 2 + size)
            .ok_or_else(|| format!("LZNT1 chunk at {at} is cut short"))?;
        at += 2 + size;
        if header & 0x8000 == 0 {
            out.extend_from_slice(chunk);
            continue;
        }
        let start = out.len();
        let mut i = 0;
        while i < chunk.len() {
            let flags = chunk[i];
            i += 1;
            for bit in 0..8 {
                if i >= chunk.len() {
                    break;
                }
                if out.len() >= limit {
                    out.truncate(limit);
                    return Ok(out);
                }
                if flags & (1 << bit) == 0 {
                    out.push(chunk[i]);
                    i += 1;
                    continue;
                }
                let Some(word) = u16_at(chunk, i) else {
                    return Err(format!("LZNT1 chunk ending at {at} is cut short"));
                };
                i += 2;
                let pos = out.len() - start;
                let mut length_mask: u16 = 0x0fff;
                let mut shift = 12;
                let mut n = pos.saturating_sub(1);
                while n >= 0x10 {
                    length_mask >>= 1;
                    shift -= 1;
                    n >>= 1;
                }
                let length = usize::from(word & length_mask) + 3;
                let offset = usize::from(word >> shift) + 1;
                if offset > pos {
                    return Err(format!(
                        "LZNT1 copy reaches {offset} bytes back, {pos} decompressed in its chunk"
                    ));
                }
                if pos + length > 4096 {
                    return Err(format!(
                        "LZNT1 chunk ending at {at} decompresses to more than 4096 bytes"
                    ));
                }
                for _ in 0..length {
                    out.push(out[out.len() - offset]);
                }
            }
        }
    }
    out.truncate(limit);
    Ok(out)
}

/// The installed shim databases and the programs they apply to, under `base`.
fn shim_databases(f: &mut Found, base: &str, wow64: bool) {
    let mut installed: Vec<(String, String)> = Vec::new();
    if let Some((list, at)) = f.key(&format!(r"{base}\InstalledSDB")) {
        for (key, key_at) in f.subkeys(&list, &at) {
            let values = f.values(&key, &key_at);
            let mut entry = AppCompatEntry::new(AppCompatSource::InstalledSdb, true, &key, &key_at);
            entry.wow64 = wow64;
            entry.sdb_guid = Some(key.name());
            for value in &values {
                let name = value.name();
                match name.to_ascii_lowercase().as_str() {
                    "databasepath" => entry.sdb_path = entry.text(value),
                    "databaseinstalltimestamp" => {
                        entry.replayed |= value.status() == Status::Replayed;
                        entry.sdb_installed = entry.time(value);
                    }
                    "databasedescription" => {
                        if let Some(text) = entry.text(value) {
                            entry.details.push(("DatabaseDescription".to_owned(), text));
                        }
                    }
                    "databasetype" => {
                        entry.replayed |= value.status() == Status::Replayed;
                        match number(value) {
                            Ok(n) => entry
                                .details
                                .push(("DatabaseType".to_owned(), format!("0x{n:x}"))),
                            Err(why) => entry.problems.push(format!("{name}: {why}")),
                        }
                    }
                    _ => {}
                }
            }
            if let Some(path) = &entry.sdb_path {
                installed.push((key.name().to_ascii_uppercase(), path.clone()));
            }
            f.records.push(entry);
        }
    }
    if let Some((list, at)) = f.key(&format!(r"{base}\Custom")) {
        for (key, key_at) in f.subkeys(&list, &at) {
            for value in f.values(&key, &key_at) {
                let name = value.name();
                let mut entry = AppCompatEntry::of_value(
                    AppCompatSource::CustomSdb,
                    true,
                    &key,
                    &key_at,
                    &value,
                );
                entry.wow64 = wow64;
                entry.path = Some(key.name()).filter(|p| !p.is_empty());
                let guid = name
                    .len()
                    .checked_sub(4)
                    .filter(|&n| name.is_char_boundary(n))
                    .filter(|&n| name[n..].eq_ignore_ascii_case(".sdb"))
                    .map_or(name.as_str(), |n| &name[..n]);
                entry.sdb_guid = Some(guid.to_owned()).filter(|g| !g.is_empty());
                entry.sdb_path = installed
                    .iter()
                    .find(|(g, _)| g.eq_ignore_ascii_case(guid))
                    .map(|(_, p)| p.clone());
                if value.size() > 0 {
                    entry.sdb_installed = entry.time(&value);
                }
                f.records.push(entry);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `data` as uncompressed LZNT1 chunks.
    fn stored(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in data.chunks(4096) {
            let header = 0x3000 | (chunk.len() as u16 - 1);
            out.extend(header.to_le_bytes());
            out.extend(chunk);
        }
        out
    }

    #[test]
    fn lznt1_chunks() {
        // a compressed chunk: "abc" as literals, then a copy of 6 bytes from 3 back
        // (pos 3: 12 length bits; offset 3 → 2 << 12, length 6 → 3)
        let mut chunk = vec![0b0000_1000, b'a', b'b', b'c'];
        chunk.extend(((2u16 << 12) | 3).to_le_bytes());
        let mut data = (0xb000u16 | (chunk.len() as u16 - 1))
            .to_le_bytes()
            .to_vec();
        data.extend(&chunk);
        assert_eq!(lznt1(&data, 100).unwrap(), b"abcabcabc");
        // stored chunks, a header of 0 ends it, and the limit
        let plain: Vec<u8> = (0..5000u32).map(|n| n as u8).collect();
        let mut both = stored(&plain);
        assert_eq!(lznt1(&both, 10_000).unwrap(), plain);
        both.extend([0, 0, 0xff]);
        assert_eq!(lznt1(&both, 10_000).unwrap(), plain);
        assert_eq!(lznt1(&both, 7).unwrap(), &plain[..7]);
        // a copy before the chunk's start, a chunk cut short
        let mut bad = (0xb000u16 | 2).to_le_bytes().to_vec();
        bad.extend([0b0000_0001, 0x00, 0x00]);
        assert!(lznt1(&bad, 100).is_err());
        assert!(lznt1(&stored(b"abcdef")[..5], 100).is_err());
        assert_eq!(lznt1(&[], 100).unwrap(), b"");
    }

    #[test]
    fn cit_databases_and_their_strings() {
        let utf16 = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        let mut data = vec![1, 0, 2, 0, 0x41, 0x41];
        data.extend(utf16(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\MMC.EXE"));
        data.extend([7, 0, 0, 0]);
        data.extend(utf16(r#""C:\WINDOWS\SYSTEM32\MMC.EXE" /S"#));
        data.extend(utf16("not a path"));
        data.extend(utf16(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\MMC.EXE"));
        let compressed = stored(&data);
        let mut value = ((compressed.len() + 8) as u32).to_le_bytes().to_vec();
        value.extend((data.len() as u32).to_le_bytes());
        value.extend(&compressed);
        let decompressed = cit_database(&value).unwrap();
        assert_eq!(decompressed, data);
        assert_eq!(
            program_strings(&decompressed),
            [
                r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\MMC.EXE",
                r#""C:\WINDOWS\SYSTEM32\MMC.EXE" /S"#
            ]
        );
        assert!(cit_database(&value[..6]).is_err());
        let mut short = value.clone();
        short[4] = short[4].wrapping_add(1);
        assert!(cit_database(&short).is_err());
        let mut long = value;
        long[0] = 0xff;
        assert!(cit_database(&long).is_err());
        assert_eq!(path_start(r"xx\\server\share"), Some(2));
        assert_eq!(path_start(r"\??\C:\x"), Some(0));
        assert_eq!(path_start("C:"), None);
        assert_eq!(path_start("é\\\\"), None);
    }

    #[test]
    fn sign_media_names() {
        assert_eq!(
            sign_media("SIGN.MEDIA=1FF3254 setup64.exe"),
            Some(("1FF3254", "setup64.exe"))
        );
        assert_eq!(
            sign_media(r"sign.media=61753187 things\ChromeSetup.exe"),
            Some(("61753187", r"things\ChromeSetup.exe"))
        );
        assert_eq!(sign_media("SIGN.MEDIA=1FF3254"), Some(("1FF3254", "")));
        assert_eq!(sign_media(r"C:\x.exe"), None);
        assert_eq!(sign_media("SIGN.MEDIé"), None);
        assert_eq!(AppCompatSource::CustomSdb.name(), "custom_sdb");
    }
}
