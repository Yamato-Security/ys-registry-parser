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

//! What a timeline needs to know about a system, from its `SYSTEM`, `SOFTWARE`, `SAM` and
//! `SECURITY` hives: its names, Windows version and install time, time zone, last shutdown,
//! processor architecture and code pages, the Windows versions it was upgraded from, its
//! profiles, the user who last signed in, and its SIDs.
//!
//! - `SYSTEM` ([`system`]), in the control set Windows used last: `Control\ComputerName`,
//!   `Services\Tcpip\Parameters` (`Hostname`, `Domain`), `Control\TimeZoneInformation`,
//!   `Control\Windows` (`ShutdownTime`), `Control\Session Manager\Environment`
//!   (`PROCESSOR_ARCHITECTURE`), `Control\Nls\CodePage` (`ACP`, `OEMCP`); and outside the control
//!   sets, `Setup\Source OS (Updated on …)`: a copy of `CurrentVersion` from before each upgrade.
//! - `SOFTWARE` ([`software`]): `Microsoft\Windows NT\CurrentVersion`, its `ProfileList`, and
//!   `Microsoft\Windows\CurrentVersion\Authentication\LogonUI`.
//! - `SAM` ([`machine_sid`]): the computer's SID, the last 24 bytes of `SAM\Domains\Account`'s
//!   `V`.
//! - `SECURITY` ([`domains`]): LSA's policy, each in the default value of a key under `Policy`:
//!   `PolAcDmN` and `PolPrDmN` (the account domain's name, which is the computer's, and the
//!   primary domain's: the domain the computer is joined to, or its workgroup) are
//!   `UNICODE_STRING`s (length and maximum length in bytes, the offset of the text, then the
//!   UTF-16 text); `PolAcDmS` and `PolPrDmS` are their SIDs; `PolDnDDN`, `PolDnTrN` and `PolDnDmG`
//!   the DNS names of the domain and its forest and the domain's GUID; `PolMachineAccountS` the
//!   computer account's SID in its domain.
//!
//! A time zone's `Bias` is the minutes to add to local standard time to get UTC (300: UTC-05:00),
//! `StandardBias` and `DaylightBias` the minutes added to it in standard and daylight time, and
//! `ActiveTimeBias` the bias in force when the key was written. `StandardStart` and
//! `DaylightStart` are the kernel's `TIME_FIELDS` (year, month, day, hour, minute, second,
//! milliseconds, weekday), not `SYSTEMTIME`s, whose weekday is third (as in the `TZI` value of the
//! zone's key in `SOFTWARE`): with a year of 0, the change comes every year, on the `day`-th (5:
//! last) `weekday` of `month`, at the time given ([`TransitionDate`]); a month of 0 means there is
//! no daylight saving time.

use std::fmt::Write as _;

use crate::bytes::{u16_at, u32_at, u64_at};
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{ControlSets, control_set_name, number, string};

/// Where `SOFTWARE` keeps the Windows version.
pub const CURRENT_VERSION: &str = r"Microsoft\Windows NT\CurrentVersion";
/// Where `SOFTWARE` keeps the profiles.
const PROFILE_LIST: &str = r"Microsoft\Windows NT\CurrentVersion\ProfileList";
/// Where `SOFTWARE` keeps the user who last signed in.
const LOGON_UI: &str = r"Microsoft\Windows\CurrentVersion\Authentication\LogonUI";
/// The start of the names of the keys `Setup` keeps for each earlier Windows version.
const SOURCE_OS: &str = "Source OS";

/// A key's values, read by name, with whether any read came from the transaction logs and what
/// was wrong with them.
struct Fields<'h> {
    path: String,
    last_written: u64,
    values: Vec<Value<'h>>,
    replayed: bool,
    problems: Vec<String>,
}

impl<'h> Fields<'h> {
    /// The values of the key at `path`; `None` when the hive hasn't the key.
    fn of(hive: &'h Hive, path: &str) -> Option<Self> {
        hive.key(path).map(|key| Fields::at(&key, path))
    }

    /// The values of `key`, which is at `path`.
    fn at(key: &Key<'h>, path: &str) -> Self {
        let (values, why) = key.values();
        Fields {
            path: path.to_owned(),
            last_written: key.last_written(),
            values,
            replayed: key.status() == Status::Replayed,
            problems: why.into_iter().map(|w| format!(r"{path}: {w}")).collect(),
        }
    }

    fn problem(&mut self, name: &str, why: &str) {
        self.problems.push(format!(r"{}\{name}: {why}", self.path));
    }

    /// The value `name`, in any case.
    fn value(&mut self, name: &str) -> Option<Value<'h>> {
        let value = self
            .values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case(name))
            .copied()?;
        self.replayed |= value.status() == Status::Replayed;
        Some(value)
    }

    /// A string value's text; `None` when it is empty, or isn't a string (a problem).
    fn text(&mut self, name: &str) -> Option<String> {
        let value = self.value(name)?;
        let (text, why) = string(&value);
        if let Some(why) = why {
            self.problem(name, &why);
        }
        text.filter(|t| !t.is_empty())
    }

    /// A `REG_DWORD` value's number; `None` when it isn't one (a problem).
    fn dword(&mut self, name: &str) -> Option<u32> {
        let value = self.value(name)?;
        number(&value).map_err(|why| self.problem(name, &why)).ok()
    }

    /// A `REG_DWORD`'s number as a signed one (a bias in minutes).
    fn signed(&mut self, name: &str) -> Option<i32> {
        self.dword(name).map(u32::cast_signed)
    }

    /// A `REG_QWORD` value's number; `None` when it isn't one (a problem).
    fn qword(&mut self, name: &str) -> Option<u64> {
        let value = self.value(name)?;
        let read = value.data().and_then(|bytes| {
            if value.value_type() != ValueType::Qword {
                return Err(format!("is {}, not REG_QWORD", value.value_type().name()));
            }
            match decode(value.data_type(), &bytes) {
                Data::Number(n) => Ok(n),
                Data::Malformed(why) => Err(why),
                _ => Err("is not a number".to_owned()),
            }
        });
        read.map_err(|why| self.problem(name, &why)).ok()
    }

    /// A binary value's bytes; `None` when they can't all be read (a problem).
    fn bytes(&mut self, name: &str) -> Option<Vec<u8>> {
        let value = self.value(name)?;
        value.data().map_err(|why| self.problem(name, &why)).ok()
    }

    /// A FILETIME kept as two `REG_DWORD`s, `<name>High` and `<name>Low`; `None` when either
    /// isn't there or the time is 0.
    fn split_filetime(&mut self, name: &str) -> Option<u64> {
        let high = self.dword(&format!("{name}High"));
        let low = self.dword(&format!("{name}Low"));
        if high.is_some() != low.is_some() {
            self.problem(name, "only one FILETIME half is present");
        }
        Some((u64::from(high?) << 32) | u64::from(low?)).filter(|&t| t != 0)
    }

    /// Hand the replay status and problems over to `replayed` and `problems`.
    fn finish(self, replayed: &mut bool, problems: &mut Vec<String>) {
        *replayed |= self.replayed;
        problems.extend(self.problems);
    }
}

// --- SYSTEM -------------------------------------------------------------------------------------

/// `StandardStart` or `DaylightStart`: when standard or daylight time begins, as the kernel's
/// `TIME_FIELDS` keeps it (the weekday last).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransitionDate {
    /// 0: every year, by `month`, `day` and `weekday`; else that year only, on that date.
    pub year: u16,
    /// 1 (January) to 12; 0: no change (no daylight saving time).
    pub month: u16,
    /// With a year of 0, which `weekday` of the month: 1 to 4, or 5 for the last; else the day
    /// of the month.
    pub day: u16,
    /// The local time of the change: hours.
    pub hour: u16,
    /// Minutes.
    pub minute: u16,
    /// Seconds.
    pub second: u16,
    /// Milliseconds.
    pub milliseconds: u16,
    /// 0 (Sunday) to 6.
    pub weekday: u16,
}

/// The size of a `TIME_FIELDS`.
const TIME_FIELDS: usize = 16;

impl TransitionDate {
    /// A `TIME_FIELDS`' 16 bytes: year, month, day, hour, minute, second, milliseconds, weekday.
    ///
    /// # Errors
    /// When there aren't 16 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != TIME_FIELDS {
            return Err(format!(
                "{} bytes, not the {TIME_FIELDS} of a TIME_FIELDS",
                bytes.len()
            ));
        }
        let field = |i: usize| u16_at(bytes, i * 2).unwrap_or(0);
        Ok(TransitionDate {
            year: field(0),
            month: field(1),
            day: field(2),
            hour: field(3),
            minute: field(4),
            second: field(5),
            milliseconds: field(6),
            weekday: field(7),
        })
    }

    /// Whether it names a change: a month other than 0.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.month != 0
    }

    /// The change in words: `second Sunday of March, 02:00`, `last Sunday of October, 03:00`, or
    /// for one year only `2007-03-11 02:00`; numbers out of their ranges as they are
    /// (`month 13, day 9 of the week, week 7, 02:00`). `None` when it names no change.
    #[must_use]
    pub fn describe(&self) -> Option<String> {
        const MONTHS: [&str; 12] = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];
        const DAYS: [&str; 7] = [
            "Sunday",
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
        ];
        const WEEKS: [&str; 5] = ["first", "second", "third", "fourth", "last"];
        if !self.is_set() {
            return None;
        }
        let mut time = format!("{:02}:{:02}", self.hour, self.minute);
        if self.second != 0 || self.milliseconds != 0 {
            let _ = write!(time, ":{:02}", self.second);
        }
        if self.milliseconds != 0 {
            let _ = write!(time, ".{:03}", self.milliseconds);
        }
        if self.year != 0 {
            return Some(format!(
                "{:04}-{:02}-{:02} {time}",
                self.year, self.month, self.day
            ));
        }
        let month = MONTHS.get(usize::from(self.month).wrapping_sub(1));
        let day = DAYS.get(usize::from(self.weekday));
        let week = WEEKS.get(usize::from(self.day).wrapping_sub(1));
        Some(match (week, day, month) {
            (Some(week), Some(day), Some(month)) => format!("{week} {day} of {month}, {time}"),
            _ => format!(
                "month {}, day {} of the week, week {}, {time}",
                self.month, self.weekday, self.day
            ),
        })
    }
}

/// `Bias` minutes as an offset from UTC: `UTC-05:00` for 300, `UTC+09:00` for -540.
#[must_use]
pub fn utc_offset(bias_minutes: i32) -> String {
    let offset = -i64::from(bias_minutes);
    let sign = if offset < 0 { '-' } else { '+' };
    let minutes = offset.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

/// `Control\TimeZoneInformation`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeZone {
    /// The key's path, from the control set.
    pub key_path: String,
    /// When the key was last written (FILETIME): when the time zone was last set, or Windows
    /// last wrote `ActiveTimeBias` (at a change to or from daylight time, or at boot).
    pub key_last_written: u64,
    /// `TimeZoneKeyName` (Windows Vista and later): the time zone's key under `SOFTWARE`'s
    /// `Time Zones`, such as `Tokyo Standard Time`.
    pub key_name: Option<String>,
    /// `StandardName`: the standard time's name, or a resource reference to it
    /// (`@tzres.dll,-112`).
    pub standard_name: Option<String>,
    /// `DaylightName`: the same for daylight time.
    pub daylight_name: Option<String>,
    /// `Bias`: minutes from local standard time to UTC (UTC = local + bias).
    pub bias: Option<i32>,
    /// `StandardBias`: minutes added to `bias` in standard time (usually 0).
    pub standard_bias: Option<i32>,
    /// `DaylightBias`: minutes added to `bias` in daylight time (usually -60).
    pub daylight_bias: Option<i32>,
    /// `ActiveTimeBias`: the bias in force when it was written.
    pub active_time_bias: Option<i32>,
    /// `StandardStart`: when standard time begins.
    pub standard_start: Option<TransitionDate>,
    /// `DaylightStart`: when daylight time begins.
    pub daylight_start: Option<TransitionDate>,
    /// `DynamicDaylightTimeDisabled`: whether automatic daylight saving time is turned off.
    pub dynamic_daylight_time_disabled: Option<bool>,
    /// `RealTimeIsUniversal`: whether the hardware clock keeps UTC rather than local time.
    pub real_time_is_universal: Option<bool>,
}

impl TimeZone {
    /// Its name: `TimeZoneKeyName`, else `StandardName` (Windows XP and 2003 have only that one,
    /// and it is the name).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.key_name.as_deref().or(self.standard_name.as_deref())
    }
}

/// A Windows version: `SOFTWARE`'s `CurrentVersion`, or the copy of it `SYSTEM`'s
/// `Setup\Source OS (Updated on …)` keeps from before an upgrade. A value the key hasn't (or
/// that is empty) is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsVersion {
    /// The key's path.
    pub key_path: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// `ProductName`, as written (Windows 11 keeps `Windows 10 …`: tell them apart by the build,
    /// 22000 and later).
    pub product_name: Option<String>,
    /// `EditionID`: `Professional`, `Enterprise`, `ServerStandard`, ….
    pub edition_id: Option<String>,
    /// `DisplayVersion` (Windows 10 20H2 and later): `21H2`, `23H2`, ….
    pub display_version: Option<String>,
    /// `ReleaseId` (Windows 10 1507 to 2009): `1809`, `2009`, ….
    pub release_id: Option<String>,
    /// `CurrentVersion`: `6.1` (Windows 7), `6.3` (8.1, and kept by 10 and 11).
    pub current_version: Option<String>,
    /// `CurrentMajorVersionNumber` (Windows 10 and later): 10.
    pub major_version: Option<u32>,
    /// `CurrentMinorVersionNumber`.
    pub minor_version: Option<u32>,
    /// `CurrentBuild`, else `CurrentBuildNumber`: `7601`, `19045`, ….
    pub current_build: Option<String>,
    /// `UBR` (Windows 10 and later): the update build revision, the number after the build.
    pub ubr: Option<u32>,
    /// `CSDVersion`: the service pack (`Service Pack 1`).
    pub csd_version: Option<String>,
    /// `BuildLabEx`: build, revision, architecture, branch and date.
    pub build_lab_ex: Option<String>,
    /// `InstallationType`: `Client`, `Server`, `Server Core`.
    pub installation_type: Option<String>,
    /// `InstallDate`: when Windows was installed, or last upgraded to a new release (Unix
    /// seconds).
    pub install_date: Option<u32>,
    /// `InstallTime` (Windows 10 and later): the same, as a FILETIME.
    pub install_time: Option<u64>,
    /// `RegisteredOwner`.
    pub registered_owner: Option<String>,
    /// `RegisteredOrganization`.
    pub registered_organization: Option<String>,
    /// `SystemRoot`: where Windows is (`C:\Windows`).
    pub system_root: Option<String>,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The Windows version in a `CurrentVersion` or `Source OS` key's values.
fn windows_version(mut fields: Fields) -> WindowsVersion {
    let mut version = WindowsVersion {
        key_path: fields.path.clone(),
        key_last_written: fields.last_written,
        product_name: fields.text("ProductName"),
        edition_id: fields.text("EditionID"),
        display_version: fields.text("DisplayVersion"),
        release_id: fields.text("ReleaseId"),
        current_version: fields.text("CurrentVersion"),
        major_version: fields.dword("CurrentMajorVersionNumber"),
        minor_version: fields.dword("CurrentMinorVersionNumber"),
        current_build: fields
            .text("CurrentBuild")
            .or_else(|| fields.text("CurrentBuildNumber")),
        ubr: fields.dword("UBR"),
        csd_version: fields.text("CSDVersion"),
        build_lab_ex: fields.text("BuildLabEx"),
        installation_type: fields.text("InstallationType"),
        install_date: fields.dword("InstallDate").filter(|&d| d != 0),
        install_time: fields.qword("InstallTime").filter(|&t| t != 0),
        registered_owner: fields.text("RegisteredOwner"),
        registered_organization: fields.text("RegisteredOrganization"),
        system_root: fields.text("SystemRoot"),
        ..WindowsVersion::default()
    };
    fields.finish(&mut version.replayed, &mut version.problems);
    version
}

/// A Windows version the system was upgraded from: a `Setup\Source OS (Updated on …)` key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreviousVersion {
    /// The key's name: `Source OS (Updated on 5/16/2019 00:55:20)`.
    pub key_name: String,
    /// The date in the name, as written there (month/day/year), in ISO 8601 form without a
    /// time zone, which the name doesn't give: `2019-05-16T00:55:20`. `None` when the name
    /// doesn't hold one.
    pub updated_on: Option<String>,
    /// The version, from the key's values.
    pub version: WindowsVersion,
}

/// The date of a `Source OS (Updated on M/D/YYYY HH:MM:SS)` key's name, in ISO 8601 form.
fn updated_on(name: &str) -> Option<String> {
    let inner = name
        .trim()
        .strip_suffix(')')?
        .split_once("(Updated on ")?
        .1
        .trim();
    let (date, time) = inner.split_once(' ')?;
    let numbers = |text: &str, sep: char| -> Option<Vec<u32>> {
        text.trim()
            .split(sep)
            .map(|n| {
                (!n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| n.parse().ok())
                    .flatten()
            })
            .collect()
    };
    let [month, day, year] = <[u32; 3]>::try_from(numbers(date, '/')?).ok()?;
    let [hour, minute, second] = <[u32; 3]>::try_from(numbers(time, ':')?).ok()?;
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => 31,
    };
    ((1..=12).contains(&month)
        && (1..=max_day).contains(&day)
        && hour < 24
        && minute < 60
        && second < 61)
        .then(|| format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"))
}

/// What a `SYSTEM` hive says about its system, from the control set Windows used last (else its
/// first) and from `Setup`. A key or value the hive hasn't is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemDetails {
    /// The control set read: `Select\Current` when the hive has it, else its first. `None` when
    /// it has none (`ControlSet001`, …): not a `SYSTEM` hive.
    pub control_set: Option<u32>,
    /// Whether `control_set` is the one `Select\Current` names.
    pub is_current: bool,
    /// `Control\ComputerName\ComputerName`'s `ComputerName`: the `NetBIOS` name.
    pub computer_name: Option<String>,
    /// When that key was last written (FILETIME): about when the computer was last named.
    pub computer_name_last_written: Option<u64>,
    /// `Services\Tcpip\Parameters`' `Hostname`: the DNS host name.
    pub hostname: Option<String>,
    /// Its `Domain`: the DNS domain (suffix), when there is one.
    pub domain: Option<String>,
    /// `Control\TimeZoneInformation`.
    pub time_zone: Option<TimeZone>,
    /// `Control\Windows`' `ShutdownTime`: when Windows last shut down cleanly (FILETIME).
    pub last_shutdown: Option<u64>,
    /// `Control\Session Manager\Environment`'s `PROCESSOR_ARCHITECTURE`: `AMD64`, `x86`,
    /// `ARM64`.
    pub processor_architecture: Option<String>,
    /// `Control\Nls\CodePage`'s `ACP`: the ANSI code page (`1252`, `932`, …).
    pub ansi_code_page: Option<String>,
    /// Its `OEMCP`: the OEM code page (`437`, `932`, …).
    pub oem_code_page: Option<String>,
    /// The Windows versions it was upgraded from (`Setup\Source OS (Updated on …)`), in the
    /// hive's order.
    pub previous_versions: Vec<PreviousVersion>,
    /// Whether the transaction logs' replay wrote a key or value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// What a `SYSTEM` hive says about its system: see [`SystemDetails`].
#[must_use]
pub fn system(hive: &Hive) -> SystemDetails {
    let sets = ControlSets::read(hive);
    let mut found = SystemDetails {
        control_set: sets.current_or_first(),
        ..SystemDetails::default()
    };
    found.is_current = found.control_set.is_some() && found.control_set == sets.current;
    let mut replayed = false;
    let mut problems = Vec::new();
    if let Some(set) = found.control_set {
        let set = control_set_name(set);
        let path = |key: &str| format!(r"{set}\{key}");
        if let Some(mut f) = Fields::of(hive, &path(r"Control\ComputerName\ComputerName")) {
            found.computer_name = f.text("ComputerName");
            found.computer_name_last_written = Some(f.last_written);
            f.finish(&mut replayed, &mut problems);
        }
        if let Some(mut f) = Fields::of(hive, &path(r"Services\Tcpip\Parameters")) {
            found.hostname = f.text("Hostname");
            // a workgroup's Domain is empty, or on some systems a REG_DWORD 0
            if f.value("Domain").is_some_and(|v| {
                matches!(
                    v.value_type(),
                    ValueType::Sz | ValueType::ExpandSz | ValueType::MultiSz
                )
            }) {
                found.domain = f.text("Domain");
            }
            f.finish(&mut replayed, &mut problems);
        }
        if let Some(f) = Fields::of(hive, &path(r"Control\TimeZoneInformation")) {
            found.time_zone = Some(time_zone(f, &mut replayed, &mut problems));
        }
        if let Some(mut f) = Fields::of(hive, &path(r"Control\Windows")) {
            if let Some(bytes) = f.bytes("ShutdownTime") {
                match u64_at(&bytes, 0).filter(|_| bytes.len() == 8) {
                    Some(time) => found.last_shutdown = Some(time).filter(|&t| t != 0),
                    None => f.problem(
                        "ShutdownTime",
                        &format!("{} bytes ({}), not a FILETIME", bytes.len(), hex(&bytes)),
                    ),
                }
            }
            f.finish(&mut replayed, &mut problems);
        }
        if let Some(mut f) = Fields::of(hive, &path(r"Control\Session Manager\Environment")) {
            found.processor_architecture = f.text("PROCESSOR_ARCHITECTURE");
            f.finish(&mut replayed, &mut problems);
        }
        if let Some(mut f) = Fields::of(hive, &path(r"Control\Nls\CodePage")) {
            found.ansi_code_page = f.text("ACP");
            found.oem_code_page = f.text("OEMCP");
            f.finish(&mut replayed, &mut problems);
        }
    }
    if let Some(setup) = hive.key("Setup") {
        let (keys, why) = setup.subkeys();
        problems.extend(why.into_iter().map(|w| format!("Setup: {w}")));
        for key in keys.iter().filter(|k| {
            k.name()
                .get(..SOURCE_OS.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(SOURCE_OS))
        }) {
            let name = key.name();
            let version = windows_version(Fields::at(key, &format!(r"Setup\{name}")));
            replayed |= version.replayed;
            found.previous_versions.push(PreviousVersion {
                updated_on: updated_on(&name),
                key_name: name,
                version,
            });
        }
    }
    found.replayed = replayed;
    found.problems = problems;
    found
}

/// The time zone in the values of `Control\TimeZoneInformation`.
fn time_zone(mut f: Fields, replayed: &mut bool, problems: &mut Vec<String>) -> TimeZone {
    let start = |f: &mut Fields, name: &str| {
        let bytes = f.bytes(name)?;
        TransitionDate::from_bytes(&bytes)
            .map_err(|why| f.problem(name, &format!("{why} ({})", hex(&bytes))))
            .ok()
    };
    let zone = TimeZone {
        key_path: f.path.clone(),
        key_last_written: f.last_written,
        key_name: f.text("TimeZoneKeyName"),
        standard_name: f.text("StandardName"),
        daylight_name: f.text("DaylightName"),
        bias: f.signed("Bias"),
        standard_bias: f.signed("StandardBias"),
        daylight_bias: f.signed("DaylightBias"),
        active_time_bias: f.signed("ActiveTimeBias"),
        standard_start: start(&mut f, "StandardStart"),
        daylight_start: start(&mut f, "DaylightStart"),
        dynamic_daylight_time_disabled: f.dword("DynamicDaylightTimeDisabled").map(|n| n != 0),
        real_time_is_universal: f.dword("RealTimeIsUniversal").map(|n| n != 0),
    };
    f.finish(replayed, problems);
    zone
}

// --- SOFTWARE -----------------------------------------------------------------------------------

/// A profile under `ProfileList`: a user (or service) that has signed in on the system.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// The key's name: the user's SID.
    pub sid: String,
    /// When the key was last written (FILETIME): about when the profile was last loaded or
    /// unloaded.
    pub key_last_written: u64,
    /// `ProfileImagePath`: the profile's folder, as written (`C:\Users\alice`,
    /// `%systemroot%\ServiceProfiles\LocalService`).
    pub path: Option<String>,
    /// `ProfileLoadTimeHigh` and `ProfileLoadTimeLow` (FILETIME), when not 0.
    pub load_time: Option<u64>,
    /// `LocalProfileLoadTimeHigh` and `…Low` (Windows 10 and later): when the profile was last
    /// loaded: about when the user last signed in.
    pub local_load_time: Option<u64>,
    /// `LocalProfileUnloadTimeHigh` and `…Low`: when it was last unloaded: about when the user
    /// last signed out.
    pub local_unload_time: Option<u64>,
    /// `State`: the profile's state flags.
    pub state: Option<u32>,
    /// `Flags`.
    pub flags: Option<u32>,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The user who last signed in, as the sign-in screen keeps them (`LogonUI`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LastLoggedOn {
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// `LastLoggedOnUser`: `DOMAIN\user`, or `.\user` for a local account.
    pub user: Option<String>,
    /// `LastLoggedOnSAMUser`.
    pub sam_user: Option<String>,
    /// `LastLoggedOnUserSID` (Windows 8 and later).
    pub user_sid: Option<String>,
    /// `LastLoggedOnDisplayName`.
    pub display_name: Option<String>,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// What a `SOFTWARE` hive says about its system. What it hasn't is `None` or empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoftwareDetails {
    /// `Microsoft\Windows NT\CurrentVersion`.
    pub version: Option<WindowsVersion>,
    /// `ProfileList`'s profiles, in the hive's order.
    pub profiles: Vec<Profile>,
    /// `Authentication\LogonUI`.
    pub last_logged_on: Option<LastLoggedOn>,
    /// What keeps profiles from being read.
    pub problems: Vec<String>,
}

/// What a `SOFTWARE` hive says about its system: see [`SoftwareDetails`].
#[must_use]
pub fn software(hive: &Hive) -> SoftwareDetails {
    let mut found = SoftwareDetails {
        version: Fields::of(hive, CURRENT_VERSION).map(windows_version),
        ..SoftwareDetails::default()
    };
    if let Some(list) = hive.key(PROFILE_LIST) {
        let (keys, why) = list.subkeys();
        found
            .problems
            .extend(why.into_iter().map(|w| format!("{PROFILE_LIST}: {w}")));
        for key in &keys {
            let sid = key.name();
            let mut f = Fields::at(key, &format!(r"{PROFILE_LIST}\{sid}"));
            let mut profile = Profile {
                key_last_written: f.last_written,
                path: f.text("ProfileImagePath"),
                load_time: f.split_filetime("ProfileLoadTime"),
                local_load_time: f.split_filetime("LocalProfileLoadTime"),
                local_unload_time: f.split_filetime("LocalProfileUnloadTime"),
                state: f.dword("State"),
                flags: f.dword("Flags"),
                sid,
                ..Profile::default()
            };
            f.finish(&mut profile.replayed, &mut profile.problems);
            found.profiles.push(profile);
        }
    }
    if let Some(mut f) = Fields::of(hive, LOGON_UI) {
        let mut last = LastLoggedOn {
            key_last_written: f.last_written,
            user: f.text("LastLoggedOnUser"),
            sam_user: f.text("LastLoggedOnSAMUser"),
            user_sid: f.text("LastLoggedOnUserSID"),
            display_name: f.text("LastLoggedOnDisplayName"),
            ..LastLoggedOn::default()
        };
        f.finish(&mut last.replayed, &mut last.problems);
        found.last_logged_on = Some(last);
    }
    found
}

// --- SAM and SECURITY ---------------------------------------------------------------------------

/// A SID's binary form as text: `S-1-5-21-…`. `None` when the bytes aren't one: revision 1, as
/// many sub-authorities as the count says (up to 15), nothing past them.
#[must_use]
pub fn sid(bytes: &[u8]) -> Option<String> {
    let (&revision, &count) = (bytes.first()?, bytes.get(1)?);
    let count = usize::from(count);
    if revision != 1 || count > 15 || bytes.len() != 8 + 4 * count {
        return None;
    }
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |n, &b| (n << 8) | u64::from(b));
    let mut text = if authority >> 32 == 0 {
        format!("S-1-{authority}")
    } else {
        format!("S-1-0x{authority:012X}")
    };
    for i in 0..count {
        let _ = write!(text, "-{}", u32_at(bytes, 8 + 4 * i)?);
    }
    Some(text)
}

/// The computer's SID (`S-1-5-21-…`) in a `SAM` hive: its local accounts' SIDs are it and their
/// RIDs. The last 24 bytes of `SAM\Domains\Account`'s `V` hold it. `None` when the key or value
/// isn't there, or those bytes aren't a SID of that form.
#[must_use]
pub fn machine_sid(sam: &Hive) -> Option<String> {
    crate::sam::machine_sid(sam)
}

/// The domains a `SECURITY` hive's LSA policy names. A key the hive hasn't, or whose value is
/// empty, is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Domains {
    /// `PolAcDmN`: the account domain's name, which is the computer's `NetBIOS` name.
    pub account_domain_name: Option<String>,
    /// `PolAcDmS`: the account domain's SID, which is the computer's SID.
    pub account_domain_sid: Option<String>,
    /// `PolPrDmN`: the primary domain's name: the domain the computer is joined to (its `NetBIOS`
    /// name), or its workgroup.
    pub primary_domain_name: Option<String>,
    /// `PolPrDmS`: the primary domain's SID; none in a workgroup.
    pub primary_domain_sid: Option<String>,
    /// When `PolPrDmN` was last written (FILETIME): about when the computer last joined a domain
    /// or workgroup.
    pub primary_domain_last_written: Option<u64>,
    /// `PolDnDDN`: the domain's DNS name.
    pub dns_domain_name: Option<String>,
    /// `PolDnTrN`: the DNS name of the domain's forest.
    pub dns_forest_name: Option<String>,
    /// `PolDnDmG`: the domain's GUID, `{…}`.
    pub domain_guid: Option<String>,
    /// `PolMachineAccountS`: the computer account's SID in its domain.
    pub machine_account_sid: Option<String>,
    /// Whether the transaction logs' replay wrote a key or value read.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The text of a `UNICODE_STRING` as LSA keeps it: its length in bytes, its maximum length, the
/// offset of the text from the start, then the text.
fn unicode_string(bytes: &[u8]) -> Result<String, String> {
    let (Some(length), Some(offset)) = (u16_at(bytes, 0), u32_at(bytes, 4)) else {
        return Err(format!(
            "{} bytes, shorter than a UNICODE_STRING's header",
            bytes.len()
        ));
    };
    let start = offset as usize;
    let maximum = u16_at(bytes, 2).unwrap_or(0);
    if length != 0 && (start < 8 || !start.is_multiple_of(2) || length > maximum) {
        return Err(format!(
            "invalid UNICODE_STRING: length {length}, maximum {maximum}, offset {offset}"
        ));
    }
    let text = start
        .checked_add(usize::from(length))
        .and_then(|end| bytes.get(start..end))
        .ok_or_else(|| {
            format!(
                "a text of {length} bytes at {offset}, past the {} bytes",
                bytes.len()
            )
        })?;
    match decode(1, text) {
        Data::Text {
            value,
            lossy: false,
        } if length % 2 == 0 => Ok(value),
        _ => Err(format!("{length} bytes of text that isn't UTF-16")),
    }
}

/// A GUID's 16 bytes as text, `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
fn guid(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.try_into().ok()?;
    Some(format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        u32_at(b, 0)?,
        u16_at(b, 4)?,
        u16_at(b, 6)?,
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

/// What LSA's policy in a `SECURITY` hive says about the computer's domains; `None` when the
/// hive has no `Policy` key.
#[must_use]
pub fn domains(security: &Hive) -> Option<Domains> {
    security.key("Policy")?;
    let mut found = Domains::default();
    // each in the default value of its key; empty when not set
    let read = |name: &str, found: &mut Domains| -> Option<(Vec<u8>, Option<u64>)> {
        let mut f = Fields::of(security, &format!(r"Policy\{name}"))?;
        let bytes = f.bytes("");
        let when = f.last_written;
        f.finish(&mut found.replayed, &mut found.problems);
        bytes.filter(|b| !b.is_empty()).map(|b| (b, Some(when)))
    };
    let text = |name: &str, found: &mut Domains| {
        let (bytes, when) = read(name, found)?;
        match unicode_string(&bytes) {
            Ok(text) => Some((Some(text).filter(|t| !t.is_empty()), when)),
            Err(why) => {
                found
                    .problems
                    .push(format!(r"Policy\{name}: {why} ({})", hex(&bytes)));
                Some((None, when))
            }
        }
    };
    let account = text("PolAcDmN", &mut found);
    found.account_domain_name = account.and_then(|a| a.0);
    let primary = text("PolPrDmN", &mut found);
    found.primary_domain_last_written = primary.as_ref().and_then(|p| p.1);
    found.primary_domain_name = primary.and_then(|p| p.0);
    found.dns_domain_name = text("PolDnDDN", &mut found).and_then(|d| d.0);
    found.dns_forest_name = text("PolDnTrN", &mut found).and_then(|d| d.0);
    let sid_of = |name: &str, found: &mut Domains| {
        let (bytes, _) = read(name, found)?;
        let text = sid(&bytes);
        if text.is_none() {
            found
                .problems
                .push(format!(r"Policy\{name}: not a SID ({})", hex(&bytes)));
        }
        text
    };
    found.account_domain_sid = sid_of("PolAcDmS", &mut found);
    found.primary_domain_sid = sid_of("PolPrDmS", &mut found);
    found.machine_account_sid = sid_of("PolMachineAccountS", &mut found);
    if let Some((bytes, _)) = read("PolDnDmG", &mut found) {
        match guid(&bytes) {
            Some(g) if bytes.iter().any(|&b| b != 0) => found.domain_guid = Some(g),
            Some(_) => {}
            None => found.problems.push(format!(
                r"Policy\PolDnDmG: {} bytes ({}), not a GUID",
                bytes.len(),
                hex(&bytes)
            )),
        }
    }
    Some(found)
}

/// Bytes in hex, for problems that keep them.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_strings_reject_header_offsets_and_inconsistent_lengths() {
        for bytes in [
            vec![2, 0, 2, 0, 0, 0, 0, 0, b'A', 0],
            vec![2, 0, 0, 0, 8, 0, 0, 0, b'A', 0],
            vec![2, 0, 2, 0, 9, 0, 0, 0, 0, b'A', 0],
        ] {
            assert!(unicode_string(&bytes).is_err(), "{bytes:?}");
        }
        assert_eq!(unicode_string(&[0; 8]), Ok(String::new()));
    }

    #[test]
    fn source_os_dates_reject_impossible_calendar_days() {
        for name in [
            "Source OS (Updated on 2/30/2024 00:00:00)",
            "Source OS (Updated on 4/31/2024 00:00:00)",
            "Source OS (Updated on 2/29/1900 00:00:00)",
        ] {
            assert_eq!(updated_on(name), None, "{name}");
        }
        assert_eq!(
            updated_on("Source OS (Updated on 2/29/2000 00:00:00)").as_deref(),
            Some("2000-02-29T00:00:00")
        );
    }

    #[test]
    fn transition_dates() {
        let date = |fields: [u16; 8]| {
            let bytes: Vec<u8> = fields.iter().flat_map(|f| f.to_le_bytes()).collect();
            TransitionDate::from_bytes(&bytes).unwrap_or_else(|e| panic!("{e}"))
        };
        assert_eq!(
            date([0, 3, 2, 2, 0, 0, 0, 0]).describe().as_deref(),
            Some("second Sunday of March, 02:00")
        );
        assert_eq!(
            date([0, 10, 5, 3, 0, 0, 0, 0]).describe().as_deref(),
            Some("last Sunday of October, 03:00")
        );
        assert_eq!(
            date([0, 12, 5, 23, 59, 59, 999, 6]).describe().as_deref(),
            Some("last Saturday of December, 23:59:59.999")
        );
        assert_eq!(
            date([2007, 3, 11, 2, 0, 30, 0, 0]).describe().as_deref(),
            Some("2007-03-11 02:00:30")
        );
        assert_eq!(
            date([0, 13, 7, 2, 0, 0, 0, 9]).describe().as_deref(),
            Some("month 13, day 9 of the week, week 7, 02:00")
        );
        assert_eq!(date([0; 8]).describe(), None);
        assert!(!date([0; 8]).is_set());
        assert_eq!(
            TransitionDate::from_bytes(&[0; 15]),
            Err("15 bytes, not the 16 of a TIME_FIELDS".to_owned())
        );
    }

    #[test]
    fn offsets_from_utc() {
        assert_eq!(utc_offset(300), "UTC-05:00");
        assert_eq!(utc_offset(-540), "UTC+09:00");
        assert_eq!(utc_offset(-330), "UTC+05:30");
        assert_eq!(utc_offset(0), "UTC+00:00");
        assert_eq!(utc_offset(i32::MIN), "UTC+35791394:08");
    }

    #[test]
    fn source_os_dates() {
        assert_eq!(
            updated_on("Source OS (Updated on 5/16/2019 00:55:20)").as_deref(),
            Some("2019-05-16T00:55:20")
        );
        assert_eq!(
            updated_on("Source OS (Updated on 12/1/2023 13:05:09)").as_deref(),
            Some("2023-12-01T13:05:09")
        );
        for bad in [
            "Source OS",
            "Source OS (Updated on 13/1/2023 13:05:09)",
            "Source OS (Updated on 1/1/2023 25:05:09)",
            "Source OS (Updated on 1/1/2023)",
            "Source OS (Updated on 1/1/2023 1:2)",
            "Source OS (Updated on 1/1/20235 01:02:03)",
            "Source OS (Updated on x/1/2023 01:02:03)",
            "Source OS (Updated on 1/1/2023 01:02:03",
        ] {
            assert_eq!(updated_on(bad), None, "{bad}");
        }
    }

    #[test]
    fn sids_and_strings() {
        let machine = [
            1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0x0e, 0xc9, 0x7e, 0x6a, 0xda, 0x0d, 0x30, 0x6c,
            0xa4, 0x91, 0x8a, 0xa5,
        ];
        assert_eq!(
            sid(&machine).as_deref(),
            Some("S-1-5-21-1786693902-1815088602-2777321892")
        );
        assert_eq!(
            sid(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).as_deref(),
            Some("S-1-5-18")
        );
        assert_eq!(sid(&[1, 0, 0, 0, 0, 0, 0, 1]).as_deref(), Some("S-1-1"));
        assert_eq!(
            sid(&[1, 0, 1, 0, 0, 0, 0, 1]).as_deref(),
            Some("S-1-0x010000000001")
        );
        // revision, count past the bytes, bytes past the count, too many sub-authorities
        assert_eq!(sid(&[2, 0, 0, 0, 0, 0, 0, 5]), None);
        assert_eq!(sid(&machine[..20]), None);
        assert_eq!(sid(&[machine.as_slice(), &[0]].concat()), None);
        let mut many = vec![1, 16, 0, 0, 0, 0, 0, 5];
        many.extend([0; 64]);
        assert_eq!(sid(&many), None);
        assert_eq!(sid(&[]), None);

        let workgroup = [
            0x12, 0, 0x14, 0, 8, 0, 0, 0, b'W', 0, b'O', 0, b'R', 0, b'K', 0, b'G', 0, b'R', 0,
            b'O', 0, b'U', 0, b'P', 0, 0, 0,
        ];
        assert_eq!(unicode_string(&workgroup).as_deref(), Ok("WORKGROUP"));
        let mut long = workgroup;
        long[0] = 0x40;
        assert!(unicode_string(&long).is_err());
        let mut odd = workgroup;
        odd[0] = 0x11;
        assert!(unicode_string(&odd).is_err());
        assert!(unicode_string(&workgroup[..6]).is_err());
        let mut far = workgroup;
        far[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unicode_string(&far).is_err());

        let g = [
            0x3f, 0xe3, 0xa0, 0x1e, 0xa1, 0xfa, 0x62, 0x41, 0xb5, 0x25, 0x3e, 0xd8, 0x0c, 0x00,
            0xc1, 0xad,
        ];
        assert_eq!(
            guid(&g).as_deref(),
            Some("{1ea0e33f-faa1-4162-b525-3ed80c00c1ad}")
        );
        assert_eq!(guid(&g[..15]), None);
    }
}
