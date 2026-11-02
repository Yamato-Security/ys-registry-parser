//! Which LSA secrets and cached domain logons a `SECURITY` hive holds, and when they were set:
//! names and times only. Nothing is decrypted, and no secret's bytes are read.
//!
//! Each secret is a key under `Policy\Secrets` named after it. Its subkeys `CurrVal` and
//! `OldVal` hold the current and previous values (encrypted), and the default values of
//! `CupdTime` and `OupdTime` the times they were set (FILETIMEs). Whether a value is there is
//! told by its size, as its `vk` record gives it.
//!
//! A secret's name says what it is: `DefaultPassword` (the autologon password), `_SC_<service>`
//! (the password of the account a service runs as), `$MACHINE.ACC` (the computer account's
//! password), `DPAPI_SYSTEM`, `NL$KM` (the key cached logons are encrypted with), and names
//! starting with `L$` (local), `G$` (global) or `M$` (machine), the prefixes
//! `LsaStorePrivateData` gives private data.
//!
//! `Cache` holds the cached domain logons: one value per slot (`NL$1` …), and `NL$Control`,
//! whose second `u32` is how many slots Windows keeps. A slot is in use when its record's
//! header (not encrypted) gives a user name's length; only those 2 bytes of it are used.

use std::fmt::Write as _;

use crate::bytes::{u16_at, u32_at, u64_at};
use crate::data::{ValueType, filetime};
use crate::hive::{Hive, Key, Status};

/// Where the secrets are, under the `SECURITY` hive's root.
pub const SECRETS: &str = r"Policy\Secrets";
/// Where the cached logons are.
pub const CACHE: &str = "Cache";

/// What a secret is, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    /// `DefaultPassword`: the password Winlogon signs in with automatically.
    Autologon,
    /// `_SC_<service>`: the password of the account a service runs as.
    ServiceAccount,
    /// `$MACHINE.ACC`: the computer account's password in its domain.
    MachineAccount,
    /// `DPAPI_SYSTEM`: the system's DPAPI keys.
    DpapiSystem,
    /// `NL$KM`: the key cached domain logons are encrypted with.
    CachedLogonKey,
    /// `L$_SQSA_<SID>`: a local account's security questions (Windows 10 and later).
    SecurityQuestions,
    /// `RasDialParams…` (`RasDialParms…`), `RasCredentials…`, `L$_RasDefaultCredentials…`,
    /// `L$_RasUserCredentials…`: dial-up and VPN credentials.
    RasCredentials,
    /// Another `L$` name: a local secret.
    Local,
    /// A `G$` name: a global secret, replicated to the domain's controllers.
    Global,
    /// An `M$` name: a machine secret.
    Machine,
    /// Any other name.
    Other,
}

impl SecretKind {
    /// `autologon`, `service_account`, `machine_account`, `dpapi_system`, `cached_logon_key`,
    /// `security_questions`, `ras_credentials`, `local`, `global`, `machine`, `other`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SecretKind::Autologon => "autologon",
            SecretKind::ServiceAccount => "service_account",
            SecretKind::MachineAccount => "machine_account",
            SecretKind::DpapiSystem => "dpapi_system",
            SecretKind::CachedLogonKey => "cached_logon_key",
            SecretKind::SecurityQuestions => "security_questions",
            SecretKind::RasCredentials => "ras_credentials",
            SecretKind::Local => "local",
            SecretKind::Global => "global",
            SecretKind::Machine => "machine",
            SecretKind::Other => "other",
        }
    }
}

/// Whether `name` starts with `prefix`, in any case.
fn starts(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// What a secret named `name` is, the service it is for (`_SC_<service>`) and the user's SID it
/// names (`L$_SQSA_<SID>`, `RasDialParams!<SID>#0`).
#[must_use]
pub fn secret_kind(name: &str) -> (SecretKind, Option<String>, Option<String>) {
    let after = |prefix: &str| Some(name[prefix.len()..].to_owned()).filter(|s| !s.is_empty());
    if name.eq_ignore_ascii_case("DefaultPassword") {
        (SecretKind::Autologon, None, None)
    } else if starts(name, "_SC_") {
        (SecretKind::ServiceAccount, after("_SC_"), None)
    } else if name.eq_ignore_ascii_case("$MACHINE.ACC") {
        (SecretKind::MachineAccount, None, None)
    } else if name.eq_ignore_ascii_case("DPAPI_SYSTEM") {
        (SecretKind::DpapiSystem, None, None)
    } else if name.eq_ignore_ascii_case("NL$KM") {
        (SecretKind::CachedLogonKey, None, None)
    } else if starts(name, "L$_SQSA_") {
        (SecretKind::SecurityQuestions, None, after("L$_SQSA_"))
    } else if ["RasDialParams", "RasDialParms", "RasCredentials", "L$_Ras"]
        .iter()
        .any(|prefix| starts(name, prefix))
    {
        // RasDialParams!<SID>#<n>
        let sid = name
            .split_once('!')
            .map(|(_, rest)| rest.split('#').next().unwrap_or_default().to_owned())
            .filter(|sid| starts(sid, "S-1-"));
        (SecretKind::RasCredentials, None, sid)
    } else if starts(name, "L$") {
        (SecretKind::Local, None, None)
    } else if starts(name, "G$") {
        (SecretKind::Global, None, None)
    } else if starts(name, "M$") {
        (SecretKind::Machine, None, None)
    } else {
        (SecretKind::Other, None, None)
    }
}

/// One of a secret's two values: whether it holds data, and when it was set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecretValue {
    /// The size of `CurrVal`'s or `OldVal`'s default value, as its record gives it (the bytes
    /// are not read); `None` when the key or value isn't there.
    pub size: Option<u32>,
    /// When the `CurrVal` or `OldVal` key was last written (FILETIME).
    pub key_last_written: Option<u64>,
    /// `CupdTime`'s or `OupdTime`'s FILETIME: when the value was set. `None` when it isn't there
    /// or is 0.
    pub set: Option<u64>,
}

impl SecretValue {
    /// Whether the value holds data.
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.size.is_some_and(|size| size > 0)
    }
}

/// An LSA secret: a key under `Policy\Secrets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// Its name: `DefaultPassword`, `_SC_ExampleSvc`, `$MACHINE.ACC`, ….
    pub name: String,
    /// What it is, from its name.
    pub kind: SecretKind,
    /// The service an `_SC_` secret is for.
    pub service_name: Option<String>,
    /// The user's SID a secret's name gives (`L$_SQSA_<SID>`, `RasDialParams!<SID>#0`).
    pub user_sid: Option<String>,
    /// When its key was last written (FILETIME).
    pub key_last_written: u64,
    /// `CurrVal` and `CupdTime`.
    pub current: SecretValue,
    /// `OldVal` and `OupdTime`.
    pub old: SecretValue,
    /// Whether the transaction logs' replay wrote one of its keys, or a time or size read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The value (`CurrVal` with `CupdTime`, or `OldVal` with `OupdTime`) of the secret at `path`,
/// whose subkeys are `subkeys`.
fn secret_value(
    hive: &Hive,
    subkeys: &[Key],
    path: &str,
    (value, time): (&str, &str),
    replayed: &mut bool,
    problems: &mut Vec<String>,
) -> SecretValue {
    let find = |name: &str| subkeys.iter().find(|k| k.name().eq_ignore_ascii_case(name));
    let mut found = SecretValue::default();
    if let Some(key) = find(value) {
        found.key_last_written = Some(key.last_written());
        *replayed |= key.status() == Status::Replayed;
        let (values, why) = key.values();
        problems.extend(why.into_iter().map(|w| format!(r"{path}\{value}: {w}")));
        // the size alone, from the value's record: its data cells are never read
        if let Some(v) = values.iter().find(|v| v.name().is_empty()) {
            found.size = Some(v.size());
            *replayed |= hive.replayed(v.offset());
        }
    }
    if let Some(key) = find(time) {
        *replayed |= key.status() == Status::Replayed;
        let (values, why) = key.values();
        problems.extend(why.into_iter().map(|w| format!(r"{path}\{time}: {w}")));
        if let Some(v) = values.iter().find(|v| v.name().is_empty()) {
            *replayed |= v.status() == Status::Replayed;
            match v.data() {
                Ok(bytes) if bytes.len() == 8 => match u64_at(&bytes, 0).filter(|&t| t != 0) {
                    Some(t) if filetime(t).is_none() => {
                        problems.push(format!(r"{path}\{time}: FILETIME 0x{t:016x} is past 9999"));
                    }
                    value => found.set = value,
                },
                Ok(bytes) => problems.push(format!(
                    r"{path}\{time}: {} bytes, not a FILETIME ({})",
                    bytes.len(),
                    bytes.iter().fold(String::new(), |mut hex, b| {
                        let _ = write!(hex, "{b:02x}");
                        hex
                    })
                )),
                Err(why) => problems.push(format!(r"{path}\{time}: {why}")),
            }
        }
    }
    found
}

/// The secrets under `security`'s `Policy\Secrets`, in the hive's order, and what keeps others
/// from being read; `None` when the hive hasn't the key.
#[must_use]
pub fn secrets(security: &Hive) -> Option<(Vec<Secret>, Vec<String>)> {
    let list = security.key(SECRETS)?;
    let (keys, why) = list.subkeys();
    let problems = why.into_iter().map(|w| format!("{SECRETS}: {w}")).collect();
    let found = keys
        .iter()
        .map(|key| {
            let name = key.name();
            let path = format!(r"{SECRETS}\{name}");
            let (kind, service_name, user_sid) = secret_kind(&name);
            let (subkeys, why) = key.subkeys();
            let mut problems: Vec<String> =
                why.into_iter().map(|w| format!("{path}: {w}")).collect();
            let mut replayed = key.status() == Status::Replayed;
            let current = secret_value(
                security,
                &subkeys,
                &path,
                ("CurrVal", "CupdTime"),
                &mut replayed,
                &mut problems,
            );
            let old = secret_value(
                security,
                &subkeys,
                &path,
                ("OldVal", "OupdTime"),
                &mut replayed,
                &mut problems,
            );
            Secret {
                name,
                kind,
                service_name,
                user_sid,
                key_last_written: key.last_written(),
                current,
                old,
                replayed,
                problems,
            }
        })
        .collect();
    Some((found, problems))
}

/// The cached domain logons under `Cache`: how many slots there are and are in use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachedLogons {
    /// When `Cache` was last written (FILETIME): about when a cached logon was last stored.
    pub key_last_written: u64,
    /// The slots (`NL$1` …).
    pub slots: usize,
    /// The validated slots whose header names a user. When problems exist, this count
    /// does not classify the damaged slots as either empty or occupied.
    pub in_use: usize,
    /// `NL$Control`'s count of the slots Windows keeps (`CachedLogonsCount`, 10 by default).
    pub control_count: Option<u32>,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Whether `name` is a slot's: `NL$` and a number.
fn slot_name(name: &str) -> bool {
    starts(name, "NL$") && name.len() > 3 && name[3..].bytes().all(|b| b.is_ascii_digit())
}

/// The cached logons of `security`; `None` when the hive hasn't the `Cache` key.
#[must_use]
pub fn cached_logons(security: &Hive) -> Option<CachedLogons> {
    let key = security.key(CACHE)?;
    let (values, problems) = key.values();
    let mut found = CachedLogons {
        key_last_written: key.last_written(),
        replayed: key.status() == Status::Replayed,
        problems: problems
            .into_iter()
            .map(|w| format!("{CACHE}: {w}"))
            .collect(),
        ..CachedLogons::default()
    };
    for value in &values {
        let name = value.name();
        if name.eq_ignore_ascii_case("NL$Control") {
            found.replayed |= value.status() == Status::Replayed;
            if value.value_type() != ValueType::Binary {
                found.problems.push(format!(
                    r"{CACHE}\NL$Control: is {}, not REG_BINARY",
                    value.value_type().name()
                ));
                continue;
            }
            match value.data() {
                Ok(bytes) => {
                    found.control_count = u32_at(&bytes, 4);
                    if found.control_count.is_none() {
                        found.problems.push(format!(
                            r"{CACHE}\NL$Control: {} bytes, too short for a count",
                            bytes.len()
                        ));
                    }
                }
                Err(why) => found.problems.push(format!(r"{CACHE}\NL$Control: {why}")),
            }
        } else if slot_name(&name) {
            found.slots += 1;
            found.replayed |= value.status() == Status::Replayed;
            if value.value_type() != ValueType::Binary {
                found.problems.push(format!(
                    r"{CACHE}\{name}: is {}, not REG_BINARY",
                    value.value_type().name()
                ));
                continue;
            }
            // Validate the 96-byte clear NL_RECORD header before using its first u16.
            // Diagnostics never include the encrypted payload or its bytes.
            match value.read_data() {
                (bytes, None) => {
                    if bytes.len() < 96 {
                        found.problems.push(format!(
                            r"{CACHE}\{name}: {} bytes, too short for a cached-logon header",
                            bytes.len()
                        ));
                    } else if let Some(length) = u16_at(&bytes, 0) {
                        if !length.is_multiple_of(2) {
                            found.problems.push(format!(
                                r"{CACHE}\{name}: odd UTF-16 user-name length {length}"
                            ));
                        } else if length > 0 {
                            if usize::from(length) > bytes.len() - 96 {
                                found.problems.push(format!(r"{CACHE}\{name}: user-name length exceeds the encrypted payload size"));
                            } else {
                                found.in_use += 1;
                            }
                        }
                    }
                }
                (_, Some(why)) => found.problems.push(format!(r"{CACHE}\{name}: {why}")),
            }
        }
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_of_secrets() {
        let kind = |name: &str| {
            let (kind, service, sid) = secret_kind(name);
            (kind.name(), service, sid)
        };
        assert_eq!(kind("DefaultPassword"), ("autologon", None, None));
        assert_eq!(
            kind("_SC_ExampleSvc"),
            ("service_account", Some("ExampleSvc".to_owned()), None)
        );
        assert_eq!(kind("_SC_"), ("service_account", None, None));
        assert_eq!(kind("$MACHINE.ACC"), ("machine_account", None, None));
        assert_eq!(kind("DPAPI_SYSTEM"), ("dpapi_system", None, None));
        assert_eq!(kind("NL$KM"), ("cached_logon_key", None, None));
        assert_eq!(
            kind("L$_SQSA_S-1-5-21-1-2-3-1001"),
            (
                "security_questions",
                None,
                Some("S-1-5-21-1-2-3-1001".to_owned())
            )
        );
        assert_eq!(
            kind("RasDialParams!S-1-5-21-1-2-3-1001#0"),
            (
                "ras_credentials",
                None,
                Some("S-1-5-21-1-2-3-1001".to_owned())
            )
        );
        assert_eq!(
            kind("L$_RasDefaultCredentials#0"),
            ("ras_credentials", None, None)
        );
        assert_eq!(
            kind("RasDialParms!S-1-5-21-1-2-3-1001#0"),
            (
                "ras_credentials",
                None,
                Some("S-1-5-21-1-2-3-1001".to_owned())
            )
        );
        assert_eq!(kind("RasCredentials!x"), ("ras_credentials", None, None));
        assert_eq!(kind("L$HYDRAENCKEY_28ada6da"), ("local", None, None));
        assert_eq!(kind("G$BCKUPKEY_PREFERRED"), ("global", None, None));
        assert_eq!(kind("M$Example"), ("machine", None, None));
        assert_eq!(kind("SAC"), ("other", None, None));
        assert_eq!(kind("é"), ("other", None, None));
        assert!(slot_name("NL$1") && slot_name("nl$10"));
        assert!(!slot_name("NL$") && !slot_name("NL$Control") && !slot_name("NL$KM"));
    }
}
