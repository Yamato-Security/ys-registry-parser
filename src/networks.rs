//! The networks a system joined and how it was set up: `SOFTWARE`'s network profiles (with their
//! first and last connection times), their signatures (the gateway's MAC address, the DNS
//! suffix) and the network cards; a `SYSTEM` control set's TCP/IP interfaces (addresses, DHCP
//! server and lease), shares, `netsh interface portproxy` tunnels and persistent routes; and its
//! time zone, to turn the profiles' local times into UTC.
//!
//! A profile's `DateCreated` and `DateLastConnected` are `SYSTEMTIME`s (year, month, weekday,
//! day, hour, minute, second, millisecond; 2 bytes each) in local time. [`TimeZone::to_utc`]
//! converts one with the system's current time zone and its daylight saving rule: a time from a
//! year with another rule, or from before the time zone was changed, can be off.

use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{control_set_name, string};

/// Where `SOFTWARE` keeps the network profiles and signatures.
pub const NETWORK_LIST: &str = r"Microsoft\Windows NT\CurrentVersion\NetworkList";
/// Where `SOFTWARE` keeps the network cards.
pub const NETWORK_CARDS: &str = r"Microsoft\Windows NT\CurrentVersion\NetworkCards";

/// A `SYSTEMTIME`: a date and time as Windows writes it, here in local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemTime {
    /// The year.
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u16,
    /// The day of the month.
    pub day: u16,
    /// The hour.
    pub hour: u16,
    /// The minute.
    pub minute: u16,
    /// The second.
    pub second: u16,
    /// The millisecond.
    pub millisecond: u16,
    /// The weekday as stored, 0 (Sunday) to 6.
    pub weekday: u16,
}

impl SystemTime {
    /// The time as ISO 8601 without a time zone, to the millisecond:
    /// `2021-02-10T14:50:37.716`.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millisecond
        )
    }

    /// Seconds since 1970-01-01 of this time read as if it were UTC.
    fn seconds(&self) -> i64 {
        days_from_civil(
            i64::from(self.year),
            i64::from(self.month),
            i64::from(self.day),
        ) * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The days of `month` in `year`.
fn days_in_month(year: u16, month: u16) -> u16 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The weekday of a date, 0 (Sunday) to 6.
fn weekday(year: u16, month: u16, day: u16) -> u16 {
    // 1970-01-01 was a Thursday
    let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day));
    u16::try_from((days + 4).rem_euclid(7)).unwrap_or(0)
}

/// A `SYSTEMTIME`'s 16 bytes, checked: `None` for 16 zero bytes (no time).
///
/// # Errors
/// When there aren't 16 bytes or a field is out of range. A weekday that disagrees with the date
/// is kept, not an error.
pub fn system_time(bytes: &[u8]) -> Result<Option<SystemTime>, String> {
    let Ok(fields) = <[u8; 16]>::try_from(bytes) else {
        return Err(format!("{} bytes, not the 16 of a SYSTEMTIME", bytes.len()));
    };
    if fields == [0; 16] {
        return Ok(None);
    }
    let f: Vec<u16> = fields
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect();
    let time = SystemTime {
        year: f[0],
        month: f[1],
        weekday: f[2],
        day: f[3],
        hour: f[4],
        minute: f[5],
        second: f[6],
        millisecond: f[7],
    };
    let valid = valid_time(&time);
    if valid {
        Ok(Some(time))
    } else {
        Err(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} (weekday {}) is not a valid SYSTEMTIME",
            time.year,
            time.month,
            time.day,
            time.hour,
            time.minute,
            time.second,
            time.millisecond,
            time.weekday
        ))
    }
}

fn valid_time(time: &SystemTime) -> bool {
    (1601..=30_827).contains(&time.year)
        && (1..=12).contains(&time.month)
        && time.day >= 1
        && time.day <= days_in_month(time.year, time.month)
        && time.hour < 24
        && time.minute < 60
        && time.second < 60
        && time.millisecond < 1000
        && time.weekday < 7
}

// --- time zone -------------------------------------------------------------------------------

/// When a time zone changes to or from daylight saving time: `TimeZoneInformation`'s
/// `StandardStart` or `DaylightStart`. These are the kernel's `TIME_FIELDS` (year, month, day,
/// hour, minute, second, millisecond, weekday), not `SYSTEMTIME`s: the weekday is last. With a
/// year of 0, `day` is the week (1 to 5, 5 the last) of `weekday` in `month`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// 0 for every year, else the one year it applies to.
    pub year: u16,
    /// The month; 0 when there is no daylight saving time.
    pub month: u16,
    /// The day of the month, or (every year) the week.
    pub day: u16,
    /// The local time of the change.
    pub hour: u16,
    /// The local time of the change.
    pub minute: u16,
    /// 0 (Sunday) to 6.
    pub weekday: u16,
}

impl Transition {
    /// The rule from its 16 bytes.
    fn read(bytes: &[u8]) -> Option<Self> {
        let f: Vec<u16> = <[u8; 16]>::try_from(bytes)
            .ok()?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect();
        Some(Transition {
            year: f[0],
            month: f[1],
            day: f[2],
            hour: f[3],
            minute: f[4],
            weekday: f[7],
        })
    }

    /// The local date and time of the change in `year` (month, day, hour, minute), when it
    /// happens that year.
    fn in_year(&self, year: u16) -> Option<(u16, u16, u16, u16)> {
        if !(1..=12).contains(&self.month) || self.weekday > 6 || self.hour > 23 || self.minute > 59
        {
            return None;
        }
        if self.year != 0 {
            return (self.year == year
                && (1..=days_in_month(year, self.month)).contains(&self.day))
            .then_some((self.month, self.day, self.hour, self.minute));
        }
        if !(1..=5).contains(&self.day) {
            return None;
        }
        let first = weekday(year, self.month, 1);
        let mut day = 1 + (self.weekday + 7 - first) % 7 + (self.day - 1) * 7;
        while day > days_in_month(year, self.month) {
            day -= 7;
        }
        Some((self.month, day, self.hour, self.minute))
    }
}

/// A system's time zone, from a control set's `Control\TimeZoneInformation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeZone {
    /// `TimeZoneKeyName`, else `StandardName`.
    pub name: Option<String>,
    /// Minutes UTC is ahead of local standard time, before `StandardBias` (300 for UTC-5).
    pub bias: i32,
    /// Added to `bias` outside daylight saving time.
    pub standard_bias: i32,
    /// Added to `bias` during daylight saving time.
    pub daylight_bias: i32,
    /// When daylight saving time ends.
    pub standard_start: Option<Transition>,
    /// When daylight saving time starts.
    pub daylight_start: Option<Transition>,
    /// `DynamicDaylightTimeDisabled`: 1 turns daylight saving time off.
    pub dynamic_daylight_time_disabled: bool,
}

impl TimeZone {
    /// The time zone of control set `set` (`ControlSet001` for 1); `None` without its `Bias`.
    #[must_use]
    pub fn read(hive: &Hive, set: u32) -> Option<Self> {
        let key = hive.key(&format!(
            r"{}\Control\TimeZoneInformation",
            control_set_name(set)
        ))?;
        let signed = |name: &str| {
            let value = key.value(name)?;
            match decode(value.data_type(), &value.data().ok()?) {
                Data::Number(n) => u32::try_from(n).ok().map(u32::cast_signed),
                _ => None,
            }
        };
        let rule = |name: &str| -> Option<Option<Transition>> {
            let Some(value) = key.value(name) else {
                return Some(None);
            };
            if value.value_type() != ValueType::Binary {
                return None;
            }
            let bytes = value.data().ok()?;
            // Transition exposes minute precision. Reject unsupported seconds/milliseconds.
            if bytes.get(10..14)? != [0, 0, 0, 0] {
                return None;
            }
            let rule = Transition::read(&bytes)?;
            if rule.month != 0
                && rule
                    .in_year(if rule.year == 0 { 2000 } else { rule.year })
                    .is_none()
            {
                return None;
            }
            Some(Some(rule))
        };
        let optional = |name: &str| {
            if key.value(name).is_some() {
                signed(name)
            } else {
                Some(0)
            }
        };
        let text = |name: &str| string(&key.value(name)?).0.filter(|t| !t.is_empty());
        Some(TimeZone {
            name: text("TimeZoneKeyName").or_else(|| text("StandardName")),
            bias: signed("Bias")?,
            standard_bias: optional("StandardBias")?,
            daylight_bias: optional("DaylightBias")?,
            standard_start: rule("StandardStart")?,
            daylight_start: rule("DaylightStart")?,
            dynamic_daylight_time_disabled: optional("DynamicDaylightTimeDisabled")? == 1,
        })
    }

    /// Convert a local timestamp only when it has one unambiguous UTC interpretation.
    /// Missing rules mean no DST; incomplete rules, invalid dates or offsets, DST folds/gaps,
    /// and timestamps beyond the supported export range return `None`.
    #[must_use]
    pub fn to_utc(&self, time: &SystemTime) -> Option<u64> {
        if !valid_time(time) {
            return None;
        }
        let standard = i64::from(self.bias) + i64::from(self.standard_bias);
        let daylight = i64::from(self.bias) + i64::from(self.daylight_bias);
        if standard.abs() > 1440 || daylight.abs() > 1440 {
            return None;
        }
        let ticks = |seconds: i64| {
            let ticks = (i128::from(seconds) + 11_644_473_600) * 10_000_000
                + i128::from(time.millisecond) * 10_000;
            u64::try_from(ticks)
                .ok()
                .filter(|&t| t > 0 && crate::data::filetime(t).is_some())
        };
        let local = time.seconds();
        let absent = |r: Option<Transition>| r.is_none_or(|r| r.month == 0);
        if self.dynamic_daylight_time_disabled
            || standard == daylight
            || (absent(self.standard_start) && absent(self.daylight_start))
        {
            return ticks(local + standard * 60);
        }
        let transition = |rule: Option<Transition>, before: i64| {
            let (month, day, hour, minute) = rule?.in_year(time.year)?;
            let at = SystemTime {
                year: time.year,
                month,
                day,
                hour,
                minute,
                second: 0,
                millisecond: 0,
                weekday: 0,
            };
            Some(at.seconds() + before * 60)
        };
        // Each transition is recorded in the local time in force just before the change.
        let start = transition(self.daylight_start, standard)?;
        let end = transition(self.standard_start, daylight)?;
        if start == end {
            return None;
        }
        let is_daylight = |utc| {
            if start < end {
                start <= utc && utc < end
            } else {
                utc >= start || utc < end
            }
        };
        let mut result = None;
        for (bias, dst) in [(standard, false), (daylight, true)] {
            let utc = local + bias * 60;
            if is_daylight(utc) == dst {
                if result.is_some() {
                    return None;
                }
                result = ticks(utc);
            }
        }
        result
    }
}

// --- SOFTWARE ----------------------------------------------------------------------------------

/// A network profile: a network the system connected to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// `NetworkList\Profiles\{GUID}`.
    pub key_path: String,
    /// The key's name.
    pub guid: String,
    /// `ProfileName`: the network's name, a Wi-Fi network's SSID.
    pub profile_name: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// `Category`: 0 public, 1 private, 2 domain.
    pub category: Option<u32>,
    /// `NameType`: the interface type (6 wired, 23 VPN, 71 wireless, 243 mobile broadband).
    pub name_type: Option<u32>,
    /// `Managed`: whether a domain manages it.
    pub managed: Option<bool>,
    /// `DateCreated`: when the system first connected to it (local time).
    pub date_created: Option<SystemTime>,
    /// `DateLastConnected`: when it last connected (local time).
    pub date_last_connected: Option<SystemTime>,
    /// The signatures that name this profile.
    pub signatures: Vec<Signature>,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// The bytes of a time that isn't a valid `SYSTEMTIME`: `DateCreated`'s, then
    /// `DateLastConnected`'s.
    pub data_raw: Option<Vec<u8>>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// A network's signature: what identifies it (the gateway's MAC address, the DNS suffix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// `NetworkList\Signatures\Managed|Unmanaged\<signature>`.
    pub key_path: String,
    /// Whether it is under `Managed` (a domain network) rather than `Unmanaged`.
    pub managed: bool,
    /// `ProfileGuid`: the profile it belongs to.
    pub profile_guid: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// `DefaultGatewayMac` as `00:15:5d:d2:f0:64`.
    pub gateway_mac: Option<String>,
    /// `DnsSuffix`.
    pub dns_suffix: Option<String>,
    /// `FirstNetwork`: the name the network first had.
    pub first_network: Option<String>,
    /// `Source`.
    pub source: Option<u32>,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// A network card: `NetworkCards\<n>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCard {
    /// `NetworkCards\<n>`.
    pub key_path: String,
    /// `ServiceName`: the interface's GUID (the key under `Tcpip\Parameters\Interfaces`).
    pub service_name: Option<String>,
    /// `Description`: the adapter.
    pub description: Option<String>,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// What `SOFTWARE` says about networks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoftwareNetworks {
    /// The profiles, each with its signatures.
    pub profiles: Vec<Profile>,
    /// The signatures no profile has.
    pub signatures: Vec<Signature>,
    /// The network cards.
    pub cards: Vec<NetworkCard>,
    /// What keeps keys from being read.
    pub problems: Vec<String>,
}

/// The text of `key`'s string value `name`; `None` when it is missing or empty. A value that
/// isn't a string is a problem.
fn text(key: &Key, name: &str, replayed: &mut bool, problems: &mut Vec<String>) -> Option<String> {
    let value = key.value(name)?;
    *replayed |= value.status() == Status::Replayed;
    let (text, why) = string(&value);
    let why = why.or_else(|| {
        (!matches!(
            value.value_type(),
            ValueType::Sz | ValueType::ExpandSz | ValueType::Link
        ))
        .then(|| format!("is {}, not a string", value.value_type().name()))
    });
    if let Some(why) = why {
        problems.push(format!(
            "{name}: {why}; its data: {}",
            hex(&value.read_data().0)
        ));
    }
    text.filter(|t| !t.is_empty())
}

/// The strings of `key`'s value `name`, a `REG_MULTI_SZ` or a `REG_SZ` (`;`, `,` or space
/// separated in some values); empty when it is missing or empty.
fn texts(key: &Key, name: &str, replayed: &mut bool, problems: &mut Vec<String>) -> Vec<String> {
    let Some(value) = key.value(name) else {
        return Vec::new();
    };
    *replayed |= value.status() == Status::Replayed;
    let (bytes, why) = value.read_data();
    problems.extend(why.map(|w| format!("{name}: {w}")));
    match decode(value.data_type(), &bytes) {
        Data::MultiText { values, lossy } => {
            if lossy {
                problems.push(format!(
                    "{name}: is not valid UTF-16: decoded lossily; its data: {}",
                    hex(&bytes)
                ));
            }
            values.into_iter().filter(|v| !v.is_empty()).collect()
        }
        Data::Text { value, lossy } => {
            if lossy {
                problems.push(format!(
                    "{name}: is not valid UTF-16: decoded lossily; its data: {}",
                    hex(&bytes)
                ));
            }
            value
                .split([' ', ',', ';'])
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect()
        }
        _ => {
            problems.push(format!(
                "{name}: is {}, not a string; its data: {}",
                value.value_type().name(),
                hex(&bytes)
            ));
            Vec::new()
        }
    }
}

/// The number of `key`'s `REG_DWORD` value `name`; `None` when it is missing. Another type is a
/// problem.
fn number(key: &Key, name: &str, replayed: &mut bool, problems: &mut Vec<String>) -> Option<u32> {
    let value = key.value(name)?;
    *replayed |= value.status() == Status::Replayed;
    match crate::system::number(&value) {
        Ok(n) => Some(n),
        Err(why) => {
            problems.push(format!(
                "{name}: {why}; its data: {}",
                hex(&value.read_data().0)
            ));
            None
        }
    }
}

/// Bytes in lower-case hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, b| {
            let _ = write!(text, "{b:02x}");
            text
        })
}

/// A MAC address's 6 bytes as `00:15:5d:d2:f0:64`.
#[must_use]
pub fn mac(bytes: &[u8]) -> Option<String> {
    (bytes.len() == 6).then(|| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

/// A signature's typed MAC, retaining malformed bytes in its diagnostic.
fn gateway_mac(key: &Key, replayed: &mut bool, problems: &mut Vec<String>) -> Option<String> {
    let value = key.value("DefaultGatewayMac")?;
    *replayed |= value.status() == Status::Replayed;
    let (bytes, why) = value.read_data();
    if let Some(why) = why {
        problems.push(format!(
            "DefaultGatewayMac: {why}; its data: {}",
            hex(&bytes)
        ));
    }
    if value.value_type() == ValueType::Binary {
        let parsed = mac(&bytes);
        if parsed.is_none() && !bytes.is_empty() {
            problems.push(format!(
                "DefaultGatewayMac: {} bytes, not the 6 of a MAC address; its data: {}",
                bytes.len(),
                hex(&bytes)
            ));
        }
        parsed
    } else {
        problems.push(format!(
            "DefaultGatewayMac: is {}, not REG_BINARY; its data: {}",
            value.value_type().name(),
            hex(&bytes)
        ));
        None
    }
}

/// The subkeys of the key at `path`, their problems added to `problems`; empty without the key.
fn subkeys_at<'h>(hive: &'h Hive, path: &str, problems: &mut Vec<String>) -> Vec<Key<'h>> {
    let Some(key) = hive.key(path) else {
        return Vec::new();
    };
    let (subkeys, why) = key.subkeys();
    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
    subkeys
}

/// A profile's time value `name`, into `profile`.
fn profile_time(key: &Key, name: &str, profile: &mut Profile) -> Option<SystemTime> {
    let value = key.value(name)?;
    profile.replayed |= value.status() == Status::Replayed;
    let (bytes, why) = value.read_data();
    if let Some(why) = why {
        profile.problems.push(format!("{name}: {why}"));
        profile.data_raw.get_or_insert_with(|| bytes.clone());
    }
    if value.value_type() != ValueType::Binary {
        profile.problems.push(format!(
            "{name}: is {}, not REG_BINARY",
            value.value_type().name()
        ));
        profile.data_raw.get_or_insert(bytes);
        return None;
    }
    match system_time(&bytes) {
        Ok(time) => time,
        Err(why) => {
            profile.problems.push(format!("{name}: {why}"));
            profile.data_raw.get_or_insert(bytes);
            None
        }
    }
}

/// What `SOFTWARE` says about networks: each profile (with the signatures that name it), the
/// signatures no profile has, and the network cards.
#[must_use]
pub fn software(hive: &Hive) -> SoftwareNetworks {
    let mut out = SoftwareNetworks::default();
    let mut signatures = Vec::new();
    for managed in [true, false] {
        let path = format!(
            r"{NETWORK_LIST}\Signatures\{}",
            if managed { "Managed" } else { "Unmanaged" }
        );
        for key in subkeys_at(hive, &path, &mut out.problems) {
            let mut sig = Signature {
                key_path: format!(r"{path}\{}", key.name()),
                managed,
                profile_guid: None,
                description: None,
                gateway_mac: None,
                dns_suffix: None,
                first_network: None,
                source: None,
                key_last_written: key.last_written(),
                replayed: key.status() == Status::Replayed,
                problems: Vec::new(),
            };
            let (r, p) = (&mut sig.replayed, &mut sig.problems);
            sig.profile_guid = text(&key, "ProfileGuid", r, p);
            sig.description = text(&key, "Description", r, p);
            sig.dns_suffix = text(&key, "DnsSuffix", r, p);
            sig.first_network = text(&key, "FirstNetwork", r, p);
            sig.source = number(&key, "Source", r, p);
            sig.gateway_mac = gateway_mac(&key, r, p);
            signatures.push(sig);
        }
    }
    let path = format!(r"{NETWORK_LIST}\Profiles");
    for key in subkeys_at(hive, &path, &mut out.problems) {
        let guid = key.name();
        let mut profile = Profile {
            key_path: format!(r"{path}\{guid}"),
            guid,
            profile_name: None,
            description: None,
            category: None,
            name_type: None,
            managed: None,
            date_created: None,
            date_last_connected: None,
            signatures: Vec::new(),
            key_last_written: key.last_written(),
            replayed: key.status() == Status::Replayed,
            data_raw: None,
            problems: Vec::new(),
        };
        let (r, p) = (&mut profile.replayed, &mut profile.problems);
        profile.profile_name = text(&key, "ProfileName", r, p);
        profile.description = text(&key, "Description", r, p);
        profile.category = number(&key, "Category", r, p);
        profile.name_type = number(&key, "NameType", r, p);
        profile.managed = number(&key, "Managed", r, p).map(|n| n != 0);
        profile.date_created = profile_time(&key, "DateCreated", &mut profile);
        profile.date_last_connected = profile_time(&key, "DateLastConnected", &mut profile);
        let (mine, rest): (Vec<Signature>, Vec<Signature>) =
            signatures.into_iter().partition(|s| {
                s.profile_guid
                    .as_deref()
                    .is_some_and(|g| g.eq_ignore_ascii_case(&profile.guid))
            });
        profile.signatures = mine;
        signatures = rest;
        out.profiles.push(profile);
    }
    out.signatures = signatures;
    for key in subkeys_at(hive, NETWORK_CARDS, &mut out.problems) {
        let mut card = NetworkCard {
            key_path: format!(r"{NETWORK_CARDS}\{}", key.name()),
            service_name: None,
            description: None,
            key_last_written: key.last_written(),
            replayed: key.status() == Status::Replayed,
            problems: Vec::new(),
        };
        let (r, p) = (&mut card.replayed, &mut card.problems);
        card.service_name = text(&key, "ServiceName", r, p);
        card.description = text(&key, "Description", r, p);
        out.cards.push(card);
    }
    out
}

/// The name of a profile's `Category`.
#[must_use]
pub fn category_name(category: u32) -> Option<&'static str> {
    match category {
        0 => Some("public"),
        1 => Some("private"),
        2 => Some("domain"),
        _ => None,
    }
}

/// The name of a profile's `NameType` (an interface type, `IFTYPE`).
#[must_use]
pub fn connection_type_name(name_type: u32) -> Option<&'static str> {
    match name_type {
        6 => Some("wired"),
        23 => Some("vpn"),
        71 => Some("wireless"),
        243 | 244 => Some("mobile_broadband"),
        _ => None,
    }
}

// --- SYSTEM -----------------------------------------------------------------------------------

/// A TCP/IP interface: `Tcpip\Parameters\Interfaces\{GUID}`, or a key under one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// The key, from the hive's root.
    pub key_path: String,
    /// The interface's GUID (its key's name, or its parent's for a key under one).
    pub guid: String,
    /// The name of a key under the interface's key.
    pub subkey: Option<String>,
    /// `EnableDHCP`.
    pub dhcp_enabled: Option<bool>,
    /// The addresses in use: `DhcpIPAddress` with DHCP, else `IPAddress`.
    pub ip_addresses: Vec<String>,
    /// `DhcpSubnetMask` or `SubnetMask`.
    pub subnet_masks: Vec<String>,
    /// `DhcpDefaultGateway` or `DefaultGateway`.
    pub default_gateways: Vec<String>,
    /// `DhcpServer`.
    pub dhcp_server: Option<String>,
    /// `NameServer`, else `DhcpNameServer`: the DNS servers.
    pub name_servers: Vec<String>,
    /// `Domain`, else `DhcpDomain`.
    pub domain: Option<String>,
    /// `LeaseObtainedTime` (Unix seconds).
    pub lease_obtained: Option<u32>,
    /// `LeaseTerminatesTime` (Unix seconds).
    pub lease_terminates: Option<u32>,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// A share: a value of `LanmanServer\Shares`, `Name=Value` strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// `LanmanServer\Shares`.
    pub key_path: String,
    /// The value's name: the share's name.
    pub name: String,
    /// `Path`.
    pub path: Option<String>,
    /// `Remark`.
    pub remark: Option<String>,
    /// `Type` (`STYPE_*`: 0 disk, 1 printer, 2 device, 3 IPC; 0x80000000 special, 0x40000000
    /// temporary).
    pub share_type: Option<u32>,
    /// Every `Name=Value` string, in order.
    pub fields: Vec<(String, String)>,
    /// When the key was last written (FILETIME): when any share last changed.
    pub key_last_written: u64,
    /// The value's bytes, when they aren't a list of strings.
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the key or the value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// A `netsh interface portproxy` tunnel: a value of `PortProxy\<v4tov4|…>\tcp`, named
/// `listenaddress/listenport`, its data `connectaddress/connectport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortProxy {
    /// `Services\PortProxy\v4tov4\tcp`, …
    pub key_path: String,
    /// `v4tov4`, `v4tov6`, `v6tov4` or `v6tov6`.
    pub kind: String,
    /// The value's name.
    pub value_name: String,
    /// The address listened on (`*` or `0.0.0.0` for every one).
    pub listen_address: String,
    /// The port listened on.
    pub listen_port: Option<u16>,
    /// The address connected to.
    pub connect_address: Option<String>,
    /// The port connected to.
    pub connect_port: Option<u16>,
    /// When the key was last written (FILETIME): when any tunnel of the kind last changed.
    pub key_last_written: u64,
    /// The value's bytes, when they aren't a string.
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the key or the value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// A persistent route: a value of `Tcpip\Parameters\PersistentRoutes`, named
/// `destination,netmask,gateway,metric`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// `Tcpip\Parameters\PersistentRoutes`.
    pub key_path: String,
    /// The value's name.
    pub value_name: String,
    /// The destination network.
    pub destination: Option<String>,
    /// Its mask.
    pub netmask: Option<String>,
    /// The gateway.
    pub gateway: Option<String>,
    /// The metric (`-1`: the interface's).
    pub metric: Option<String>,
    /// When the key was last written (FILETIME): when any route last changed.
    pub key_last_written: u64,
    /// Whether the transaction logs' replay wrote the key or the value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// What a `SYSTEM` control set says about networks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemNetworks {
    /// The TCP/IP interfaces, and the keys under them.
    pub interfaces: Vec<Interface>,
    /// The shares.
    pub shares: Vec<Share>,
    /// The port proxies.
    pub port_proxies: Vec<PortProxy>,
    /// The persistent routes.
    pub routes: Vec<Route>,
    /// The time zone.
    pub time_zone: Option<TimeZone>,
    /// What keeps keys from being read.
    pub problems: Vec<String>,
}

/// Split `address/port` at its last `/`.
fn address_port(text: &str) -> (String, Option<u16>) {
    match text.rsplit_once('/') {
        Some((address, port)) => (
            address.to_owned(),
            port.bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| port.parse().ok())
                .flatten(),
        ),
        None => (text.to_owned(), None),
    }
}

/// An interface's record from its key.
fn interface(key: &Key, key_path: String, guid: &str, subkey: Option<String>) -> Interface {
    let mut replayed = key.status() == Status::Replayed;
    let mut problems = Vec::new();
    let (r, p) = (&mut replayed, &mut problems);
    let dhcp_enabled = number(key, "EnableDHCP", r, p).map(|n| n != 0);
    // DHCP's values with DHCP on, the static ones with it off; whichever is there without it
    let mut pick = |name: &str| {
        let dhcp = texts(key, &format!("Dhcp{name}"), r, p);
        let fixed = texts(key, name, r, p);
        if dhcp_enabled == Some(false) || (dhcp_enabled.is_none() && dhcp.is_empty()) {
            fixed
        } else {
            dhcp
        }
    };
    let ip_addresses = pick("IPAddress")
        .into_iter()
        .filter(|a| a != "0.0.0.0")
        .collect();
    let subnet_masks = pick("SubnetMask");
    let default_gateways = pick("DefaultGateway");
    let mut name_servers = texts(key, "NameServer", r, p);
    if name_servers.is_empty() {
        name_servers = texts(key, "DhcpNameServer", r, p);
    }
    let dhcp_server = text(key, "DhcpServer", r, p).filter(|s| s != "255.255.255.255");
    let domain = text(key, "Domain", r, p).or_else(|| text(key, "DhcpDomain", r, p));
    let lease_obtained = number(key, "LeaseObtainedTime", r, p);
    let lease_terminates = number(key, "LeaseTerminatesTime", r, p);
    Interface {
        key_path,
        guid: guid.to_owned(),
        subkey,
        dhcp_enabled,
        ip_addresses,
        subnet_masks,
        default_gateways,
        dhcp_server,
        name_servers,
        domain,
        lease_obtained,
        lease_terminates,
        key_last_written: key.last_written(),
        replayed,
        problems,
    }
}

/// What control set `set` (`ControlSet001` for 1) of a `SYSTEM` hive says about networks: its
/// TCP/IP interfaces (and the keys under them), shares, port proxies, persistent routes and time
/// zone. `None` when the control set isn't there.
#[must_use]
pub fn system(hive: &Hive, set: u32) -> Option<SystemNetworks> {
    let prefix = control_set_name(set);
    hive.key(&prefix)?;
    let mut out = SystemNetworks {
        time_zone: TimeZone::read(hive, set),
        ..SystemNetworks::default()
    };
    let path = format!(r"{prefix}\Services\Tcpip\Parameters\Interfaces");
    for key in subkeys_at(hive, &path, &mut out.problems) {
        let guid = key.name();
        let key_path = format!(r"{path}\{guid}");
        let (subkeys, why) = key.subkeys();
        out.problems
            .extend(why.into_iter().map(|w| format!("{key_path}: {w}")));
        out.interfaces
            .push(interface(&key, key_path.clone(), &guid, None));
        for sub in subkeys {
            let name = sub.name();
            out.interfaces.push(interface(
                &sub,
                format!(r"{key_path}\{name}"),
                &guid,
                Some(name),
            ));
        }
    }
    shares(hive, &prefix, &mut out);
    port_proxies(hive, &prefix, &mut out);
    routes(hive, &prefix, &mut out);
    Some(out)
}

/// The values of the key at `path`, with the key; `None` without the key.
fn values_at<'h>(
    hive: &'h Hive,
    path: &str,
    problems: &mut Vec<String>,
) -> Option<(Key<'h>, Vec<Value<'h>>)> {
    let key = hive.key(path)?;
    let (values, why) = key.values();
    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
    Some((key, values))
}

/// The shares of `LanmanServer\Shares`.
fn shares(hive: &Hive, prefix: &str, out: &mut SystemNetworks) {
    let path = format!(r"{prefix}\Services\LanmanServer\Shares");
    let Some((key, values)) = values_at(hive, &path, &mut out.problems) else {
        return;
    };
    for value in values {
        let mut share = Share {
            key_path: path.clone(),
            name: value.name(),
            path: None,
            remark: None,
            share_type: None,
            fields: Vec::new(),
            key_last_written: key.last_written(),
            data_raw: None,
            replayed: key.status() == Status::Replayed || value.status() == Status::Replayed,
            problems: Vec::new(),
        };
        let (bytes, why) = value.read_data();
        if why.is_some() {
            share.data_raw = Some(bytes.clone());
        }
        share.problems.extend(why);
        if let Data::MultiText { values, lossy } = decode(value.data_type(), &bytes) {
            if lossy {
                share
                    .problems
                    .push("is not valid UTF-16: decoded lossily".to_owned());
                share.data_raw = Some(bytes);
            }
            for item in values.into_iter().filter(|v| !v.is_empty()) {
                match item.split_once('=') {
                    Some((name, field)) => {
                        share.fields.push((name.to_owned(), field.to_owned()));
                    }
                    None => share.problems.push(format!("{item:?} isn't Name=Value")),
                }
            }
        } else {
            share.problems.push(format!(
                "is {}, not REG_MULTI_SZ",
                value.value_type().name()
            ));
            share.data_raw = Some(bytes);
        }
        let field = |name: &str| {
            share
                .fields
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        share.path = field("Path").filter(|p| !p.is_empty());
        share.remark = field("Remark").filter(|p| !p.is_empty());
        share.share_type = field("Type").and_then(|t| t.parse().ok());
        out.shares.push(share);
    }
}

/// The tunnels of `PortProxy\v4tov4|v4tov6|v6tov4|v6tov6\tcp`.
fn port_proxies(hive: &Hive, prefix: &str, out: &mut SystemNetworks) {
    for kind in ["v4tov4", "v4tov6", "v6tov4", "v6tov6"] {
        let path = format!(r"{prefix}\Services\PortProxy\{kind}\tcp");
        let Some((key, values)) = values_at(hive, &path, &mut out.problems) else {
            continue;
        };
        for value in values {
            let name = value.name();
            let (listen_address, listen_port) = address_port(&name);
            let mut proxy = PortProxy {
                key_path: path.clone(),
                kind: kind.to_owned(),
                value_name: name,
                listen_address,
                listen_port,
                connect_address: None,
                connect_port: None,
                key_last_written: key.last_written(),
                data_raw: None,
                replayed: key.status() == Status::Replayed || value.status() == Status::Replayed,
                problems: Vec::new(),
            };
            if proxy.listen_port.is_none() {
                proxy
                    .problems
                    .push("its name isn't listenaddress/listenport".to_owned());
            }
            match string(&value) {
                (Some(text), why) => {
                    if let Some(why) = why {
                        proxy.problems.push(why);
                        proxy.data_raw = Some(value.read_data().0);
                    }
                    let (address, port) = address_port(&text);
                    if port.is_none() {
                        proxy
                            .problems
                            .push(format!("{text:?} isn't connectaddress/connectport"));
                    }
                    proxy.connect_address = Some(address).filter(|a| !a.is_empty());
                    proxy.connect_port = port;
                }
                (None, why) => {
                    proxy.problems.push(why.unwrap_or_else(|| {
                        format!(
                            "is {}, not a nonempty address/port string",
                            value.value_type().name()
                        )
                    }));
                    proxy.data_raw = Some(value.read_data().0);
                }
            }
            out.port_proxies.push(proxy);
        }
    }
}

/// The routes of `Tcpip\Parameters\PersistentRoutes`.
fn routes(hive: &Hive, prefix: &str, out: &mut SystemNetworks) {
    let path = format!(r"{prefix}\Services\Tcpip\Parameters\PersistentRoutes");
    let Some((key, values)) = values_at(hive, &path, &mut out.problems) else {
        return;
    };
    for value in values {
        let name = value.name();
        let parts: Vec<&str> = name.split(',').collect();
        let part = |i: usize| {
            parts
                .get(i)
                .map(|p| (*p).to_owned())
                .filter(|p| !p.is_empty())
        };
        let mut route = Route {
            key_path: path.clone(),
            destination: part(0),
            netmask: part(1),
            gateway: part(2),
            metric: part(3),
            value_name: name.clone(),
            key_last_written: key.last_written(),
            replayed: key.status() == Status::Replayed || value.status() == Status::Replayed,
            problems: Vec::new(),
        };
        if parts.len() != 4 {
            route
                .problems
                .push("its name isn't destination,netmask,gateway,metric".to_owned());
        }
        out.routes.push(route);
    }
}

/// The name of a share's `Type`.
#[must_use]
pub fn share_type_name(share_type: u32) -> String {
    let base = match share_type & 0x0fff_ffff {
        0 => "disk".to_owned(),
        1 => "printer".to_owned(),
        2 => "device".to_owned(),
        3 => "ipc".to_owned(),
        n => format!("type {n}"),
    };
    let mut name = base;
    if share_type & 0x8000_0000 != 0 {
        name.push_str(", special");
    }
    if share_type & 0x4000_0000 != 0 {
        name.push_str(", temporary");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(f: [u16; 8]) -> Vec<u8> {
        f.iter().flat_map(|n| n.to_le_bytes()).collect()
    }

    #[test]
    fn system_times() {
        // 2021-02-10 (Wednesday) 14:50:37.716
        let time = system_time(&st([2021, 2, 3, 10, 14, 50, 37, 716]))
            .unwrap()
            .unwrap();
        assert_eq!(time.text(), "2021-02-10T14:50:37.716");
        assert_eq!(weekday(2021, 2, 10), 3);
        assert_eq!(system_time(&[0; 16]), Ok(None));
        assert!(system_time(&st([2021, 2, 3, 30, 14, 50, 37, 716])).is_err());
        assert!(system_time(&st([2020, 2, 6, 29, 0, 0, 0, 0])).is_ok());
        assert!(system_time(&st([2021, 2, 1, 29, 0, 0, 0, 0])).is_err());
        assert!(system_time(&st([2021, 13, 1, 1, 0, 0, 0, 0])).is_err());
        assert_eq!(
            system_time(&[1, 2, 3]),
            Err("3 bytes, not the 16 of a SYSTEMTIME".to_owned())
        );
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1601, 1, 1), -134_774);
    }

    #[test]
    fn transitions() {
        // second Sunday of March and first Sunday of November, 02:00
        let dst = Transition {
            year: 0,
            month: 3,
            day: 2,
            hour: 2,
            minute: 0,
            weekday: 0,
        };
        assert_eq!(dst.in_year(2021), Some((3, 14, 2, 0)));
        let last = Transition {
            month: 10,
            day: 5,
            ..dst
        };
        // the last Sunday of October 2021 is the 31st, of 2022 the 30th
        assert_eq!(last.in_year(2021), Some((10, 31, 2, 0)));
        assert_eq!(last.in_year(2022), Some((10, 30, 2, 0)));
        assert_eq!(Transition { month: 0, ..dst }.in_year(2021), None);
        assert_eq!(Transition { day: 6, ..dst }.in_year(2021), None);
        let fixed = Transition {
            year: 2021,
            day: 20,
            ..dst
        };
        assert_eq!(fixed.in_year(2021), Some((3, 20, 2, 0)));
        assert_eq!(fixed.in_year(2022), None);
    }

    #[test]
    fn local_times_to_utc() {
        let eastern = TimeZone {
            name: Some("Eastern Standard Time".into()),
            bias: 300,
            standard_bias: 0,
            daylight_bias: -60,
            standard_start: Some(Transition {
                year: 0,
                month: 11,
                day: 1,
                hour: 2,
                minute: 0,
                weekday: 0,
            }),
            daylight_start: Some(Transition {
                year: 0,
                month: 3,
                day: 2,
                hour: 2,
                minute: 0,
                weekday: 0,
            }),
            dynamic_daylight_time_disabled: false,
        };
        let at = |y, mo, d, h, mi| SystemTime {
            year: y,
            month: mo,
            day: d,
            hour: h,
            minute: mi,
            second: 0,
            millisecond: 0,
            weekday: weekday(y, mo, d),
        };
        let utc = |t: &SystemTime, tz: &TimeZone| {
            tz.to_utc(t).and_then(crate::data::filetime).map(|(s, _)| s)
        };
        // winter: UTC-5; summer: UTC-4
        assert_eq!(utc(&at(2021, 2, 10, 14, 50), &eastern), Some(1_612_986_600));
        assert_eq!(utc(&at(2021, 7, 1, 12, 0), &eastern), Some(1_625_155_200));
        // around the changes
        assert_eq!(utc(&at(2021, 3, 14, 1, 59), &eastern), Some(1_615_705_140));
        assert_eq!(utc(&at(2021, 3, 14, 3, 0), &eastern), Some(1_615_705_200));
        assert_eq!(utc(&at(2021, 11, 7, 2, 0), &eastern), Some(1_636_268_400));
        // southern: daylight saving from September to April
        let easter = TimeZone {
            name: None,
            bias: 360,
            standard_bias: 0,
            daylight_bias: -60,
            standard_start: Some(Transition {
                year: 0,
                month: 4,
                day: 1,
                hour: 22,
                minute: 0,
                weekday: 6,
            }),
            daylight_start: Some(Transition {
                year: 0,
                month: 9,
                day: 1,
                hour: 22,
                minute: 0,
                weekday: 6,
            }),
            dynamic_daylight_time_disabled: false,
        };
        assert_eq!(utc(&at(2021, 1, 15, 12, 0), &easter), Some(1_610_730_000));
        assert_eq!(utc(&at(2021, 6, 15, 12, 0), &easter), Some(1_623_780_000));
        let none = TimeZone {
            dynamic_daylight_time_disabled: true,
            ..eastern.clone()
        };
        assert_eq!(utc(&at(2021, 7, 1, 12, 0), &none), Some(1_625_158_800));
    }

    #[test]
    fn time_zone_conversion_rejects_overflow_and_invalid_dates() {
        let mut tz = TimeZone {
            name: None,
            bias: i32::MAX,
            standard_bias: 1,
            daylight_bias: 0,
            standard_start: None,
            daylight_start: None,
            dynamic_daylight_time_disabled: false,
        };
        let mut time = SystemTime {
            year: 2026,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            millisecond: 0,
            weekday: 4,
        };
        assert_eq!(tz.to_utc(&time), None);
        tz.bias = 0;
        tz.standard_bias = 0;
        time.month = 2;
        time.day = 30;
        assert_eq!(tz.to_utc(&time), None);
        time.year = u16::MAX;
        assert_eq!(tz.to_utc(&time), None);
    }

    #[test]
    fn dst_gaps_and_folds_are_not_assigned_a_guessed_utc_time() {
        let tz = TimeZone {
            name: None,
            bias: 300,
            standard_bias: 0,
            daylight_bias: -60,
            dynamic_daylight_time_disabled: false,
            standard_start: Some(Transition {
                year: 0,
                month: 11,
                day: 1,
                hour: 2,
                minute: 0,
                weekday: 0,
            }),
            daylight_start: Some(Transition {
                year: 0,
                month: 3,
                day: 2,
                hour: 2,
                minute: 0,
                weekday: 0,
            }),
        };
        let time = |month, day, hour| SystemTime {
            year: 2026,
            month,
            day,
            hour,
            minute: 30,
            second: 0,
            millisecond: 0,
            weekday: 0,
        };
        assert_eq!(tz.to_utc(&time(3, 8, 2)), None);
        assert_eq!(tz.to_utc(&time(11, 1, 1)), None);
        assert!(tz.to_utc(&time(3, 8, 1)).is_some());
        assert!(tz.to_utc(&time(3, 8, 3)).is_some());
        assert!(tz.to_utc(&time(11, 1, 0)).is_some());
        assert!(tz.to_utc(&time(11, 1, 2)).is_some());
    }

    #[test]
    fn names_and_parts() {
        assert_eq!(
            mac(&[0, 0x15, 0x5d, 0xd2, 0xf0, 0x64]).as_deref(),
            Some("00:15:5d:d2:f0:64")
        );
        assert_eq!(mac(&[1, 2]), None);
        assert_eq!(address_port("0.0.0.0/8080"), ("0.0.0.0".into(), Some(8080)));
        assert_eq!(address_port("fe80::1/443"), ("fe80::1".into(), Some(443)));
        assert_eq!(address_port("x/99999"), ("x".into(), None));
        assert_eq!(address_port("x"), ("x".into(), None));
        assert_eq!(share_type_name(0), "disk");
        assert_eq!(share_type_name(0x8000_0000), "disk, special");
        assert_eq!(share_type_name(3 | 0x8000_0000), "ipc, special");
        assert_eq!(share_type_name(0x4000_0001), "printer, temporary");
        assert_eq!(category_name(2), Some("domain"));
        assert_eq!(connection_type_name(71), Some("wireless"));
        assert_eq!(connection_type_name(1), None);
    }
}
