//! `SAM` hives: the local accounts (`SAM\Domains\Account\Users`).
//!
//! Each account is a key named by its RID in hex (`000001F4` for 500). Its `F` value is a fixed
//! record: the last logon (0x08), the password's last change (0x18), when the account expires
//! (0x20), the last failed logon (0x28; FILETIMEs), the RID (0x30), the account control flags
//! (0x38), the country code (0x3C) and code page (0x3E), the failed logon count (0x40) and the
//! logon count (0x42). Its `V` value starts with a table of (offset, size, unknown) entries, 12
//! bytes each, the offsets from the end of the table (0xCC): the user name, full name, comment,
//! user comment, home directory, home drive, logon script, profile path, … in UTF-16.
//! `Users\Names\<user name>` names each account: the RID is its default value's type.
//! Password hashes are not read.

use std::collections::HashMap;

use crate::bytes::{u16_at, u32_at, u64_at, utf16_units};
use crate::data::ValueType;
use crate::hive::{Hive, Key, Status, Value};

/// Where the local accounts are, under the hive's root.
pub const ACCOUNT_USERS: &str = r"SAM\Domains\Account\Users";
/// A FILETIME that means "never" (an account that doesn't expire).
pub const NEVER: u64 = 0x7FFF_FFFF_FFFF_FFFF;
/// The size of `F` up to the logon count.
const F_SIZE: usize = 0x44;
/// The size of `V`'s table.
const V_TABLE: usize = 0xCC;

/// An account's `F` value, decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserF {
    /// The last logon (FILETIME; 0: never).
    pub last_logon: u64,
    /// When the password was last set (FILETIME).
    pub password_last_set: u64,
    /// When the account expires (FILETIME; 0 or [`NEVER`]: never).
    pub account_expires: u64,
    /// The last failed logon (a wrong password; FILETIME; 0: never).
    pub last_failed_logon: u64,
    /// The account's RID.
    pub rid: u32,
    /// The account control flags: see [`account_flag_names`].
    pub flags: u16,
    /// The country code.
    pub country_code: u16,
    /// The code page.
    pub code_page: u16,
    /// Failed logons since the last good one.
    pub failed_logon_count: u16,
    /// Logons since the account was made (at most 65,535).
    pub logon_count: u16,
}

/// An `F` value's bytes, decoded.
///
/// # Errors
/// When they are shorter than the record up to the logon count (68 bytes; Windows writes 80).
pub fn user_f(bytes: &[u8]) -> Result<UserF, String> {
    if bytes.len() < F_SIZE {
        return Err(format!(
            "F of {} bytes, shorter than the {F_SIZE} its fields take",
            bytes.len()
        ));
    }
    let q = |at| u64_at(bytes, at).unwrap_or(0);
    let w = |at| u16_at(bytes, at).unwrap_or(0);
    Ok(UserF {
        last_logon: q(0x08),
        password_last_set: q(0x18),
        account_expires: q(0x20),
        last_failed_logon: q(0x28),
        rid: u32_at(bytes, 0x30).unwrap_or(0),
        flags: w(0x38),
        country_code: w(0x3C),
        code_page: w(0x3E),
        failed_logon_count: w(0x40),
        logon_count: w(0x42),
    })
}

/// An account's `V` value: the strings of its table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserV {
    /// The user name.
    pub username: Option<String>,
    /// The full name.
    pub full_name: Option<String>,
    /// The comment (an administrator's: `Built-in account for administering …`).
    pub comment: Option<String>,
    /// The user's comment.
    pub user_comment: Option<String>,
    /// The home directory.
    pub home_directory: Option<String>,
    /// The home directory's drive.
    pub home_drive: Option<String>,
    /// The logon script.
    pub logon_script: Option<String>,
    /// The profile path.
    pub profile_path: Option<String>,
}

/// A `V` value's bytes, decoded: its strings, and the entries that can't be read.
#[must_use]
pub fn user_v(bytes: &[u8]) -> (UserV, Vec<String>) {
    let mut problems = Vec::new();
    if bytes.len() < V_TABLE {
        problems.push(format!(
            "V of {} bytes, shorter than its {V_TABLE}-byte table",
            bytes.len()
        ));
    }
    let mut entry = |index: usize, name: &str| -> Option<String> {
        let at = index * 12;
        let offset = u32_at(bytes, at)? as usize;
        let size = u32_at(bytes, at + 4)? as usize;
        if size == 0 {
            return None;
        }
        let data = V_TABLE
            .checked_add(offset)
            .and_then(|start| bytes.get(start..start.checked_add(size)?));
        let Some(data) = data else {
            problems.push(format!(
                "V: its {name} of {size} bytes at {offset} is past its end"
            ));
            return None;
        };
        let units = utf16_units(data);
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        if !size.is_multiple_of(2) || String::from_utf16(&units[..end]).is_err() {
            problems.push(format!(
                "V: its {name} is not valid UTF-16: decoded lossily"
            ));
        }
        Some(String::from_utf16_lossy(&units[..end]))
    };
    let v = UserV {
        username: entry(1, "user name"),
        full_name: entry(2, "full name"),
        comment: entry(3, "comment"),
        user_comment: entry(4, "user comment"),
        home_directory: entry(6, "home directory"),
        home_drive: entry(7, "home drive"),
        logon_script: entry(8, "logon script"),
        profile_path: entry(9, "profile path"),
    };
    (v, problems)
}

/// The names of the account control flags set in `flags` (`disabled`, `normal_account`,
/// `dont_expire_password`, `locked_out`, …).
#[must_use]
pub fn account_flag_names(flags: u16) -> Vec<String> {
    const FLAGS: [(u16, &str); 16] = [
        (0x0001, "disabled"),
        (0x0002, "home_directory_required"),
        (0x0004, "password_not_required"),
        (0x0008, "temporary_duplicate_account"),
        (0x0010, "normal_account"),
        (0x0020, "mns_logon_account"),
        (0x0040, "interdomain_trust_account"),
        (0x0080, "workstation_trust_account"),
        (0x0100, "server_trust_account"),
        (0x0200, "dont_expire_password"),
        (0x0400, "locked_out"),
        (0x0800, "encrypted_text_password_allowed"),
        (0x1000, "smartcard_required"),
        (0x2000, "trusted_for_delegation"),
        (0x4000, "not_delegated"),
        (0x8000, "use_des_key_only"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect()
}

/// A local account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// Its RID: its key's name (hex), else its `Names` entry's.
    pub rid: Option<u32>,
    /// Its user name: from `V`, else from its `Names` entry.
    pub username: Option<String>,
    /// Its key under `Users` (`000001F4`); `None` for a `Names` entry without one.
    pub key_name: Option<String>,
    /// When its key was last written (FILETIME).
    pub last_written: Option<u64>,
    /// When its `Names` entry was last written (FILETIME): about when the account was made.
    pub names_last_written: Option<u64>,
    /// `F`, decoded.
    pub f: Option<UserF>,
    /// `V`'s strings.
    pub v: UserV,
    /// `UserPasswordHint`.
    pub password_hint: Option<String>,
    /// `InternetUserName`: the Microsoft account it is linked to.
    pub internet_user_name: Option<String>,
    /// `UserDontShowInLogonUI`: whether the sign-in screen leaves it out; `None` without it.
    pub hidden_from_logon_ui: Option<bool>,
    /// Whether the transaction logs' replay wrote its keys or values.
    pub replayed: bool,
    /// What couldn't be read, and what doesn't match.
    pub problems: Vec<String>,
}

/// The name, RID, key time and replay status of an entry under `Users\Names`.
type NameEntry = (String, Option<u32>, u64, bool);

/// Read the `Names` entries and the damage that keeps any part from being read.
fn account_names(key: &Key, problems: &mut Vec<String>) -> Vec<NameEntry> {
    let (entries, why) = key.subkeys();
    problems.extend(why.into_iter().map(|w| format!("Names: {w}")));
    entries
        .into_iter()
        .map(|entry| {
            let (values, why) = entry.values();
            problems.extend(
                why.into_iter()
                    .map(|w| format!(r"Names\{}: {w}", entry.name())),
            );
            let defaults: Vec<&Value> = values.iter().filter(|v| v.name().is_empty()).collect();
            if defaults.is_empty() {
                problems.push(format!(
                    r"Names\{}: its default value is not there",
                    entry.name()
                ));
            } else if defaults.len() > 1 {
                problems.push(format!(
                    r"Names\{}: its default value is present more than once",
                    entry.name()
                ));
            }
            let default = defaults.first().copied();
            if let Some(value) = default {
                let (bytes, why) = value.read_data();
                problems.extend(
                    why.into_iter()
                        .map(|w| format!(r"Names\{}: {w}", entry.name())),
                );
                if !bytes.is_empty() {
                    problems.push(format!(
                        r"Names\{}: its default value has {} data bytes, not 0",
                        entry.name(),
                        bytes.len()
                    ));
                }
            }
            let replayed = entry.status() == Status::Replayed
                || defaults.iter().any(|v| v.status() == Status::Replayed);
            (
                entry.name(),
                default.map(Value::data_type),
                entry.last_written(),
                replayed,
            )
        })
        .collect()
}

/// The local accounts of `hive`, in the order of their keys, then `Names` entries without one,
/// and what keeps parts of them from being read; `None` when the hive has no
/// `SAM\Domains\Account\Users` key.
#[must_use]
pub fn accounts(hive: &Hive) -> Option<(Vec<Account>, Vec<String>)> {
    let users = hive.key(ACCOUNT_USERS)?;
    let (keys, mut problems) = users.subkeys();
    // Names: each user name, its RID (its default value's type) and its key's time
    let names_keys: Vec<&Key> = keys
        .iter()
        .filter(|k| k.name().eq_ignore_ascii_case("Names"))
        .collect();
    if names_keys.len() > 1 {
        problems.push("the Names key is present more than once".to_owned());
    }
    let names_key = names_keys.first().copied();
    if names_key.is_none() {
        problems.push("the Names key is not there".to_owned());
    }
    let names = names_key.map_or_else(Vec::new, |key| account_names(key, &mut problems));
    let mut by_rid: HashMap<u32, usize> = HashMap::new();
    for (i, (_, rid, _, _)) in names.iter().enumerate() {
        if let Some(rid) = rid
            && let Some(previous) = by_rid.insert(*rid, i)
        {
            problems.push(format!(
                "Names entries {:?} and {:?} have the same RID {rid}",
                names[previous].0, names[i].0
            ));
            by_rid.insert(*rid, previous);
        }
    }
    let mut taken = vec![false; names.len()];
    let mut found = Vec::new();
    for key in keys
        .iter()
        .filter(|k| !k.name().eq_ignore_ascii_case("Names"))
    {
        let mut account = account(key);
        let entry = account.rid.and_then(|rid| by_rid.get(&rid).copied());
        if let Some(i) = entry {
            taken[i] = true;
            let (name, _, written, replayed) = &names[i];
            account.names_last_written = Some(*written);
            account.replayed |= replayed;
            match &account.username {
                Some(user) if !user.eq_ignore_ascii_case(name) => account
                    .problems
                    .push(format!("its Names entry is {name}, not its user name")),
                Some(_) => {}
                None => account.username = Some(name.clone()),
            }
        } else if names_key.is_some() {
            account
                .problems
                .push("no Names entry has its RID".to_owned());
        }
        found.push(account);
    }
    for (i, (name, rid, written, replayed)) in names.into_iter().enumerate() {
        if !taken[i] {
            found.push(Account {
                rid,
                username: Some(name),
                names_last_written: Some(written),
                replayed,
                problems: vec!["its Users key is not there".to_owned()],
                ..Account::default()
            });
        }
    }
    Some((found, problems))
}

/// The account whose key is `key`.
fn account(key: &Key) -> Account {
    let (values, mut problems) = key.values();
    let name = key.name();
    let mut a = Account {
        rid: u32::from_str_radix(&name, 16).ok(),
        key_name: Some(name.clone()),
        last_written: Some(key.last_written()),
        replayed: key.status() == Status::Replayed,
        ..Account::default()
    };
    if a.rid.is_none() {
        problems.push(format!("its key's name {name} is not a RID in hex"));
    }
    let mut seen = Vec::new();
    for value in &values {
        let vname = value.name().to_ascii_lowercase();
        let known = matches!(
            vname.as_str(),
            "f" | "v" | "userpasswordhint" | "internetusername" | "userdontshowinlogonui"
        );
        if !known {
            continue;
        }
        if seen.contains(&vname) {
            a.replayed |= value.status() == Status::Replayed;
            problems.push(format!(
                "value {:?} is present more than once",
                value.name()
            ));
            continue;
        }
        seen.push(vname.clone());
        a.replayed |= value.status() == Status::Replayed;
        let (bytes, why) = value.read_data();
        problems.extend(why.map(|w| format!("{}: {w}", value.name())));
        if value.value_type() != ValueType::Binary {
            problems.push(format!(
                "{}: is {}, not REG_BINARY",
                value.name(),
                value.value_type().name()
            ));
        }
        match vname.as_str() {
            "f" => match user_f(&bytes) {
                Ok(f) => {
                    if a.rid.is_some_and(|rid| rid != f.rid) {
                        problems.push(format!("F's RID is {}, not its key's", f.rid));
                    }
                    a.f = Some(f);
                }
                Err(why) => problems.push(why),
            },
            "v" => {
                let (v, why) = user_v(&bytes);
                problems.extend(why);
                a.username.clone_from(&v.username);
                a.v = v;
            }
            "userpasswordhint" => {
                let (text, why) = text(&bytes);
                a.password_hint = text;
                problems.extend(why.map(|w| format!("UserPasswordHint: {w}")));
            }
            "internetusername" => {
                let (text, why) = text(&bytes);
                a.internet_user_name = text;
                problems.extend(why.map(|w| format!("InternetUserName: {w}")));
            }
            _ => {
                if bytes.len() != 4 {
                    problems.push(format!(
                        "UserDontShowInLogonUI: is {} bytes, not 4",
                        bytes.len()
                    ));
                }
                a.hidden_from_logon_ui = u32_at(&bytes, 0).map(|n| n != 0);
            }
        }
    }
    for (name, display) in [("f", "F"), ("v", "V")] {
        if !seen.iter().any(|seen| seen == name) {
            problems.push(format!("{display} is not there"));
        }
    }
    a.problems = problems;
    a
}

/// UTF-16 text up to its NUL, when there is any, and whether it decoded lossily.
fn text(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let units = utf16_units(bytes);
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    let lossy = !bytes.len().is_multiple_of(2) || String::from_utf16(&units[..end]).is_err();
    (
        (end > 0).then(|| String::from_utf16_lossy(&units[..end])),
        lossy.then(|| "is not valid UTF-16: decoded lossily".to_owned()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `F` value.
    fn f(times: [u64; 4], rid: u32, flags: u16, counts: (u16, u16)) -> Vec<u8> {
        let mut b = vec![0u8; 80];
        for (at, t) in [0x08, 0x18, 0x20, 0x28].into_iter().zip(times) {
            b[at..at + 8].copy_from_slice(&t.to_le_bytes());
        }
        b[0x30..0x34].copy_from_slice(&rid.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&flags.to_le_bytes());
        b[0x40..0x42].copy_from_slice(&counts.0.to_le_bytes());
        b[0x42..0x44].copy_from_slice(&counts.1.to_le_bytes());
        b
    }

    #[test]
    fn f_values() {
        let decoded = user_f(&f([1, 2, NEVER, 4], 1001, 0x0211, (3, 42))).unwrap_or_default();
        assert_eq!(
            (
                decoded.last_logon,
                decoded.password_last_set,
                decoded.account_expires,
                decoded.last_failed_logon
            ),
            (1, 2, NEVER, 4)
        );
        assert_eq!(
            (
                decoded.rid,
                decoded.flags,
                decoded.failed_logon_count,
                decoded.logon_count
            ),
            (1001, 0x0211, 3, 42)
        );
        assert_eq!(
            account_flag_names(decoded.flags),
            ["disabled", "normal_account", "dont_expire_password"]
        );
        assert_eq!(
            user_f(&[0; 20]),
            Err("F of 20 bytes, shorter than the 68 its fields take".to_owned())
        );
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn v_values() {
        let mut v = vec![0u8; V_TABLE];
        let mut data = Vec::new();
        for (index, text) in [(1, "alice"), (2, "Alice Example"), (3, "")] {
            let bytes = utf16(text);
            v[index * 12..index * 12 + 4].copy_from_slice(&(data.len() as u32).to_le_bytes());
            v[index * 12 + 4..index * 12 + 8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            data.extend(&bytes);
            data.resize(data.len().next_multiple_of(4), 0);
        }
        // the profile path past the end
        v[9 * 12..9 * 12 + 4].copy_from_slice(&1000u32.to_le_bytes());
        v[9 * 12 + 4..9 * 12 + 8].copy_from_slice(&8u32.to_le_bytes());
        v.extend(data);
        let (decoded, problems) = user_v(&v);
        assert_eq!(decoded.username.as_deref(), Some("alice"));
        assert_eq!(decoded.full_name.as_deref(), Some("Alice Example"));
        assert_eq!(decoded.comment, None);
        assert_eq!(decoded.profile_path, None);
        assert_eq!(
            problems,
            ["V: its profile path of 8 bytes at 1000 is past its end"]
        );
        assert_eq!(
            user_v(&[0; 10]).1,
            ["V of 10 bytes, shorter than its 204-byte table"]
        );
    }
}
