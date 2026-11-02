//! The audit policy in force: which security events a system was set to log, from a `SECURITY`
//! hive's `Policy\PolAdtEv`.
//!
//! Windows Vista and later keep one setting per subcategory (`Layout::Subcategories`): a 12-byte
//! header (`0x100`; the number of categories, 9; the offset of a table of how many
//! subcategories each category has), then one `u16` setting per subcategory, category by
//! category, then one `u16` Windows leaves unused, then that table (one `u16` per category).
//! Within a category, the settings are in Windows' own order of its subcategories, the index in
//! the subcategory's message ID (`%%12548` is Logon/Logoff's index 4, Special Logon): the order
//! of their GUIDs differs. Each version adds subcategories at the end of their category: Windows
//! 10 and 11 have 59, Windows 8.1 and Server 2012 R2 56.
//!
//! Windows XP and Server 2003 keep one setting per category (`Layout::Categories`), as the
//! `POLICY_AUDIT_EVENTS_INFO` structure has them: whether auditing is on, the 9 categories'
//! settings, and their number (9), as `u32`s.
//!
//! A setting is 0 (no auditing), 1 (success), 2 (failure) or 3 (both).

use crate::bytes::{u16_at, u32_at};
use crate::hive::{Hive, Status};

/// Where the audit policy is, under the `SECURITY` hive's root.
pub const POL_ADT_EV: &str = r"Policy\PolAdtEv";

/// The categories, in Windows' order (`POLICY_AUDIT_EVENT_TYPE`).
pub const CATEGORIES: [&str; 9] = [
    "System",
    "Logon/Logoff",
    "Object Access",
    "Privilege Use",
    "Detailed Tracking",
    "Policy Change",
    "Account Management",
    "DS Access",
    "Account Logon",
];

/// Each category's subcategories in Windows' order: name and GUID (`ntsecapi.h`; without braces,
/// in upper case as events give them).
const SUBCATEGORIES: [&[(&str, &str)]; 9] = [
    &[
        (
            "Security State Change",
            "0CCE9210-69AE-11D9-BED3-505054503030",
        ),
        (
            "Security System Extension",
            "0CCE9211-69AE-11D9-BED3-505054503030",
        ),
        ("System Integrity", "0CCE9212-69AE-11D9-BED3-505054503030"),
        ("IPsec Driver", "0CCE9213-69AE-11D9-BED3-505054503030"),
        (
            "Other System Events",
            "0CCE9214-69AE-11D9-BED3-505054503030",
        ),
    ],
    &[
        ("Logon", "0CCE9215-69AE-11D9-BED3-505054503030"),
        ("Logoff", "0CCE9216-69AE-11D9-BED3-505054503030"),
        ("Account Lockout", "0CCE9217-69AE-11D9-BED3-505054503030"),
        ("IPsec Main Mode", "0CCE9218-69AE-11D9-BED3-505054503030"),
        ("Special Logon", "0CCE921B-69AE-11D9-BED3-505054503030"),
        ("IPsec Quick Mode", "0CCE9219-69AE-11D9-BED3-505054503030"),
        (
            "IPsec Extended Mode",
            "0CCE921A-69AE-11D9-BED3-505054503030",
        ),
        (
            "Other Logon/Logoff Events",
            "0CCE921C-69AE-11D9-BED3-505054503030",
        ),
        (
            "Network Policy Server",
            "0CCE9243-69AE-11D9-BED3-505054503030",
        ),
        (
            "User / Device Claims",
            "0CCE9247-69AE-11D9-BED3-505054503030",
        ),
        ("Group Membership", "0CCE9249-69AE-11D9-BED3-505054503030"),
    ],
    &[
        ("File System", "0CCE921D-69AE-11D9-BED3-505054503030"),
        ("Registry", "0CCE921E-69AE-11D9-BED3-505054503030"),
        ("Kernel Object", "0CCE921F-69AE-11D9-BED3-505054503030"),
        ("SAM", "0CCE9220-69AE-11D9-BED3-505054503030"),
        (
            "Other Object Access Events",
            "0CCE9227-69AE-11D9-BED3-505054503030",
        ),
        (
            "Certification Services",
            "0CCE9221-69AE-11D9-BED3-505054503030",
        ),
        (
            "Application Generated",
            "0CCE9222-69AE-11D9-BED3-505054503030",
        ),
        (
            "Handle Manipulation",
            "0CCE9223-69AE-11D9-BED3-505054503030",
        ),
        ("File Share", "0CCE9224-69AE-11D9-BED3-505054503030"),
        (
            "Filtering Platform Packet Drop",
            "0CCE9225-69AE-11D9-BED3-505054503030",
        ),
        (
            "Filtering Platform Connection",
            "0CCE9226-69AE-11D9-BED3-505054503030",
        ),
        (
            "Detailed File Share",
            "0CCE9244-69AE-11D9-BED3-505054503030",
        ),
        ("Removable Storage", "0CCE9245-69AE-11D9-BED3-505054503030"),
        (
            "Central Policy Staging",
            "0CCE9246-69AE-11D9-BED3-505054503030",
        ),
    ],
    &[
        (
            "Sensitive Privilege Use",
            "0CCE9228-69AE-11D9-BED3-505054503030",
        ),
        (
            "Non Sensitive Privilege Use",
            "0CCE9229-69AE-11D9-BED3-505054503030",
        ),
        (
            "Other Privilege Use Events",
            "0CCE922A-69AE-11D9-BED3-505054503030",
        ),
    ],
    &[
        ("Process Creation", "0CCE922B-69AE-11D9-BED3-505054503030"),
        (
            "Process Termination",
            "0CCE922C-69AE-11D9-BED3-505054503030",
        ),
        ("DPAPI Activity", "0CCE922D-69AE-11D9-BED3-505054503030"),
        ("RPC Events", "0CCE922E-69AE-11D9-BED3-505054503030"),
        (
            "Plug and Play Events",
            "0CCE9248-69AE-11D9-BED3-505054503030",
        ),
        (
            "Token Right Adjusted Events",
            "0CCE924A-69AE-11D9-BED3-505054503030",
        ),
    ],
    &[
        (
            "Audit Policy Change",
            "0CCE922F-69AE-11D9-BED3-505054503030",
        ),
        (
            "Authentication Policy Change",
            "0CCE9230-69AE-11D9-BED3-505054503030",
        ),
        (
            "Authorization Policy Change",
            "0CCE9231-69AE-11D9-BED3-505054503030",
        ),
        (
            "MPSSVC Rule-Level Policy Change",
            "0CCE9232-69AE-11D9-BED3-505054503030",
        ),
        (
            "Filtering Platform Policy Change",
            "0CCE9233-69AE-11D9-BED3-505054503030",
        ),
        (
            "Other Policy Change Events",
            "0CCE9234-69AE-11D9-BED3-505054503030",
        ),
    ],
    &[
        (
            "User Account Management",
            "0CCE9235-69AE-11D9-BED3-505054503030",
        ),
        (
            "Computer Account Management",
            "0CCE9236-69AE-11D9-BED3-505054503030",
        ),
        (
            "Security Group Management",
            "0CCE9237-69AE-11D9-BED3-505054503030",
        ),
        (
            "Distribution Group Management",
            "0CCE9238-69AE-11D9-BED3-505054503030",
        ),
        (
            "Application Group Management",
            "0CCE9239-69AE-11D9-BED3-505054503030",
        ),
        (
            "Other Account Management Events",
            "0CCE923A-69AE-11D9-BED3-505054503030",
        ),
    ],
    &[
        (
            "Directory Service Access",
            "0CCE923B-69AE-11D9-BED3-505054503030",
        ),
        (
            "Directory Service Changes",
            "0CCE923C-69AE-11D9-BED3-505054503030",
        ),
        (
            "Directory Service Replication",
            "0CCE923D-69AE-11D9-BED3-505054503030",
        ),
        (
            "Detailed Directory Service Replication",
            "0CCE923E-69AE-11D9-BED3-505054503030",
        ),
    ],
    &[
        (
            "Credential Validation",
            "0CCE923F-69AE-11D9-BED3-505054503030",
        ),
        (
            "Kerberos Service Ticket Operations",
            "0CCE9240-69AE-11D9-BED3-505054503030",
        ),
        (
            "Other Account Logon Events",
            "0CCE9241-69AE-11D9-BED3-505054503030",
        ),
        (
            "Kerberos Authentication Service",
            "0CCE9242-69AE-11D9-BED3-505054503030",
        ),
    ],
];

/// The size of the subcategory layout's header.
const HEADER: usize = 12;
/// The size of the category layout: auditing on, 9 settings, their number.
const CATEGORY_LAYOUT: usize = 44;
/// More categories than this is not a header.
const MAX_CATEGORIES: u32 = 64;

/// How `PolAdtEv` keeps the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layout {
    /// Windows Vista and later: a setting per subcategory.
    Subcategories,
    /// Windows XP and Server 2003: a setting per category, and whether auditing is on.
    Categories,
}

impl Layout {
    /// `subcategories` or `categories`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Layout::Subcategories => "subcategories",
            Layout::Categories => "categories",
        }
    }
}

/// What a category or subcategory is set to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Setting {
    /// 0: no auditing.
    None,
    /// 1: successes.
    Success,
    /// 2: failures.
    Failure,
    /// 3: successes and failures.
    SuccessAndFailure,
    /// A value Windows doesn't write.
    Other(u32),
}

impl Setting {
    /// The setting of value `n`.
    #[must_use]
    pub fn from_value(n: u32) -> Self {
        match n {
            0 => Setting::None,
            1 => Setting::Success,
            2 => Setting::Failure,
            3 => Setting::SuccessAndFailure,
            other => Setting::Other(other),
        }
    }

    /// `none`, `success`, `failure`, `success_and_failure`; others in hex.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Setting::None => "none".to_owned(),
            Setting::Success => "success".to_owned(),
            Setting::Failure => "failure".to_owned(),
            Setting::SuccessAndFailure => "success_and_failure".to_owned(),
            Setting::Other(n) => format!("0x{n:x}"),
        }
    }

    /// Its value as stored.
    #[must_use]
    pub fn value(self) -> u32 {
        match self {
            Setting::None => 0,
            Setting::Success => 1,
            Setting::Failure => 2,
            Setting::SuccessAndFailure => 3,
            Setting::Other(n) => n,
        }
    }

    /// Whether successes are logged.
    #[must_use]
    pub fn success(self) -> bool {
        self.value() & 1 != 0
    }

    /// Whether failures are logged.
    #[must_use]
    pub fn failure(self) -> bool {
        self.value() & 2 != 0
    }
}

/// One category's or subcategory's setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSetting {
    /// The category's index in Windows' order (0 System … 8 Account Logon).
    pub category_index: usize,
    /// Its name; `None` past the 9 Windows has.
    pub category: Option<&'static str>,
    /// The subcategory's index in its category (`Layout::Subcategories`).
    pub subcategory_index: Option<usize>,
    /// Its name; `None` for one this crate doesn't know.
    pub subcategory: Option<&'static str>,
    /// Its GUID: `0CCE921B-69AE-11D9-BED3-505054503030`.
    pub subcategory_guid: Option<&'static str>,
    /// What it is set to log.
    pub setting: Setting,
}

impl AuditSetting {
    /// The subcategory's message ID, as event 4719's `SubcategoryId` gives it (`%%12548`):
    /// `0x3000` + 256 × the category's index + the subcategory's.
    #[must_use]
    pub fn subcategory_id(&self) -> Option<u32> {
        let category = u32::try_from(self.category_index).ok()?;
        let index = u32::try_from(self.subcategory_index?).ok()?;
        (category < 9 && index < 256).then(|| 0x3000 + (category << 8) + index)
    }
}

/// The subcategory `index` of category `category`: its name and GUID.
#[must_use]
pub fn subcategory(category: usize, index: usize) -> Option<(&'static str, &'static str)> {
    SUBCATEGORIES.get(category)?.get(index).copied()
}

/// `PolAdtEv`'s data, decoded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditEvents {
    /// How it keeps the policy; `None` when the data has neither layout.
    pub layout: Option<Layout>,
    /// The header's first `u32` (`Layout::Subcategories`): `0x100` on every system read.
    pub revision: Option<u32>,
    /// Whether auditing is on (`Layout::Categories`): when it is off, no category is audited
    /// whatever its setting.
    pub auditing_mode: Option<bool>,
    /// The settings, category by category.
    pub settings: Vec<AuditSetting>,
    /// The `u16` between the settings and the table of counts (`Layout::Subcategories`), which
    /// Windows doesn't use.
    pub unused: Option<u16>,
    /// What doesn't fit either layout.
    pub problems: Vec<String>,
}

/// `PolAdtEv`'s data, decoded by its layout: see [`AuditEvents`].
#[must_use]
pub fn audit_events(bytes: &[u8]) -> AuditEvents {
    if bytes.len() == CATEGORY_LAYOUT
        && u32_at(bytes, 40) == Some(9)
        && u32_at(bytes, 0).is_some_and(|mode| mode <= 1)
    {
        return categories(bytes);
    }
    subcategories(bytes)
}

/// The XP and 2003 layout: auditing on, 9 settings, 9.
fn categories(bytes: &[u8]) -> AuditEvents {
    let mut found = AuditEvents {
        layout: Some(Layout::Categories),
        auditing_mode: u32_at(bytes, 0).map(|m| m == 1),
        ..AuditEvents::default()
    };
    for (i, category) in CATEGORIES.iter().enumerate() {
        let value = u32_at(bytes, 4 + 4 * i).unwrap_or(0);
        let setting = Setting::from_value(value);
        if let Setting::Other(n) = setting {
            found
                .problems
                .push(format!("{category}: a setting of 0x{n:x}, not 0 to 3"));
        }
        found.settings.push(AuditSetting {
            category_index: i,
            category: Some(category),
            subcategory_index: None,
            subcategory: None,
            subcategory_guid: None,
            setting,
        });
    }
    found
}

/// The Vista and later layout: header, settings, an unused `u16`, counts.
fn subcategories(bytes: &[u8]) -> AuditEvents {
    let mut found = AuditEvents::default();
    let unknown = |why: String| AuditEvents {
        problems: vec![format!("an unknown layout of {} bytes: {why}", bytes.len())],
        ..AuditEvents::default()
    };
    let (Some(revision), Some(count), Some(offset)) =
        (u32_at(bytes, 0), u32_at(bytes, 4), u32_at(bytes, 8))
    else {
        return unknown(format!("shorter than the {HEADER}-byte header"));
    };
    if count == 0 || count > MAX_CATEGORIES {
        return unknown(format!("{count} categories"));
    }
    let offset = offset as usize;
    let counts_end = offset.checked_add(2 * count as usize);
    if offset < HEADER || counts_end.is_none_or(|end| end > bytes.len()) {
        return unknown(format!(
            "the table of {count} counts at {offset} doesn't fit its {} bytes",
            bytes.len()
        ));
    }
    found.layout = Some(Layout::Subcategories);
    found.revision = Some(revision);
    let counts: Vec<usize> = (0..count as usize)
        .map(|c| usize::from(u16_at(bytes, offset + 2 * c).unwrap_or(0)))
        .collect();
    let room = (offset - HEADER) / 2;
    let total: usize = counts.iter().sum();
    if total > room {
        found.problems.push(format!(
            "the categories count {total} subcategories, the data holds {room} settings"
        ));
    }
    let mut at = 0;
    for (c, &n) in counts.iter().enumerate() {
        let category = CATEGORIES.get(c).copied();
        if category.is_none() && n > 0 {
            found
                .problems
                .push(format!("category {c} is not one Windows has"));
        }
        for i in 0..n {
            if at >= room {
                break;
            }
            let value = u16_at(bytes, HEADER + 2 * at).unwrap_or(0);
            at += 1;
            let setting = Setting::from_value(u32::from(value));
            let named = subcategory(c, i);
            if let Setting::Other(v) = setting {
                found.problems.push(format!(
                    "{} {}: a setting of 0x{v:x}, not 0 to 3",
                    category.unwrap_or("?"),
                    named.map_or_else(|| format!("subcategory {i}"), |n| n.0.to_owned())
                ));
            }
            found.settings.push(AuditSetting {
                category_index: c,
                category,
                subcategory_index: Some(i),
                subcategory: named.map(|n| n.0),
                subcategory_guid: named.map(|n| n.1),
                setting,
            });
        }
    }
    // one u16 between the settings and the counts on every system read
    match room.checked_sub(total) {
        Some(1) => found.unused = u16_at(bytes, HEADER + 2 * total),
        Some(0) | None => {}
        Some(left) => found.problems.push(format!(
            "{left} u16s between the settings and the counts, where Windows leaves 1"
        )),
    }
    if !(offset - HEADER).is_multiple_of(2) {
        found
            .problems
            .push(format!("the counts at {offset}, an odd offset"));
    }
    if let Some(end) = counts_end
        && end < bytes.len()
    {
        found
            .problems
            .push(format!("{} bytes past the counts", bytes.len() - end));
    }
    found
}

/// The audit policy of a `SECURITY` hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPolicy {
    /// When `Policy\PolAdtEv` was last written (FILETIME): about when the policy last changed.
    pub key_last_written: u64,
    /// Its data, decoded.
    pub events: AuditEvents,
    /// Its data, when it doesn't decode whole (an unknown layout, or problems).
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the key or its value.
    pub replayed: bool,
    /// What couldn't be read, and what doesn't decode.
    pub problems: Vec<String>,
}

/// The audit policy in `security`'s `Policy\PolAdtEv`; `None` when the hive hasn't the key.
#[must_use]
pub fn audit_policy(security: &Hive) -> Option<AuditPolicy> {
    let key = security.key(POL_ADT_EV)?;
    let (values, mut problems) = key.values();
    let mut replayed = key.status() == Status::Replayed;
    let value = values.iter().find(|v| v.name().is_empty());
    let (bytes, why) = match value {
        Some(v) => {
            replayed |= v.status() == Status::Replayed;
            v.read_data()
        }
        None => (Vec::new(), Some("no default value".to_owned())),
    };
    problems.extend(why);
    let events = if bytes.is_empty() {
        AuditEvents::default()
    } else {
        audit_events(&bytes)
    };
    problems.extend(events.problems.iter().cloned());
    let data_raw = (!problems.is_empty() || events.layout.is_none()).then_some(bytes);
    Some(AuditPolicy {
        key_last_written: key.last_written(),
        events,
        data_raw,
        replayed,
        problems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subcategory layout of `settings`, one list per category.
    fn layout(settings: &[&[u16]], unused: u16) -> Vec<u8> {
        let total: usize = settings.iter().map(|s| s.len()).sum();
        let offset = HEADER + 2 * (total + 1);
        let mut b = Vec::new();
        for v in [0x100u32, settings.len() as u32, offset as u32] {
            b.extend(v.to_le_bytes());
        }
        for s in settings.iter().flat_map(|s| s.iter()) {
            b.extend(s.to_le_bytes());
        }
        b.extend(unused.to_le_bytes());
        for s in settings {
            b.extend((s.len() as u16).to_le_bytes());
        }
        b
    }

    #[test]
    fn subcategory_tables() {
        assert_eq!(SUBCATEGORIES.iter().map(|s| s.len()).sum::<usize>(), 59);
        // every GUID once
        let mut guids: Vec<&str> = SUBCATEGORIES
            .iter()
            .flat_map(|s| s.iter().map(|x| x.1))
            .collect();
        guids.sort_unstable();
        guids.dedup();
        assert_eq!(guids.len(), 59);
        assert_eq!(
            subcategory(1, 4),
            Some(("Special Logon", "0CCE921B-69AE-11D9-BED3-505054503030"))
        );
        assert_eq!(subcategory(1, 11), None);
        assert_eq!(subcategory(9, 0), None);
    }

    #[test]
    fn windows_10_defaults() {
        let data = layout(
            &[
                &[1, 0, 3, 0, 3],
                &[3, 1, 1, 0, 1, 0, 0, 0, 3, 0, 0],
                &[0; 14],
                &[0; 3],
                &[0; 6],
                &[1, 1, 0, 0, 0, 0],
                &[1, 0, 1, 0, 0, 0],
                &[0; 4],
                &[0; 4],
            ],
            0x30c2,
        );
        assert_eq!(data.len(), 150);
        let found = audit_events(&data);
        assert_eq!(found.problems, Vec::<String>::new());
        assert_eq!(
            (found.layout, found.revision, found.unused),
            (Some(Layout::Subcategories), Some(0x100), Some(0x30c2))
        );
        assert_eq!(found.settings.len(), 59);
        let special = &found.settings[5 + 4];
        assert_eq!(
            (special.category, special.subcategory, special.setting),
            (
                Some("Logon/Logoff"),
                Some("Special Logon"),
                Setting::Success
            )
        );
        assert_eq!(special.subcategory_id(), Some(12548));
        let nps = &found.settings[5 + 8];
        assert_eq!(
            (nps.subcategory, nps.setting.name().as_str()),
            (Some("Network Policy Server"), "success_and_failure")
        );
        let last = found.settings.last().unwrap_or_else(|| panic!("settings"));
        assert_eq!(last.subcategory, Some("Kerberos Authentication Service"));
        assert_eq!(last.subcategory_id(), Some(14339));
    }

    #[test]
    fn layouts_that_dont_fit() {
        // a category Windows hasn't, a subcategory past the table, a value past 3
        let found = audit_events(&layout(
            &[
                &[1, 0, 3, 0, 3, 9],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[2],
            ],
            0,
        ));
        assert_eq!(
            found.problems,
            [
                "System subcategory 5: a setting of 0x9, not 0 to 3",
                "category 9 is not one Windows has"
            ]
        );
        assert_eq!(found.settings.len(), 7);
        assert_eq!(found.settings[5].subcategory, None);
        assert_eq!(found.settings[6].category, None);
        assert_eq!(found.settings[6].subcategory_id(), None);
        // counts adding up to more than the data holds
        let mut data = layout(&[&[1, 1]], 0);
        data[18..20].copy_from_slice(&5u16.to_le_bytes());
        let found = audit_events(&data);
        assert_eq!(
            found.problems,
            ["the categories count 5 subcategories, the data holds 3 settings"]
        );
        assert_eq!(found.settings.len(), 3);
        // bytes past the counts; more unused u16s
        let mut data = layout(&[&[1]], 0);
        data.push(0);
        assert_eq!(audit_events(&data).problems, ["1 bytes past the counts"]);
        // unknown layouts
        for (bytes, why) in [
            (
                vec![0u8; 8],
                "an unknown layout of 8 bytes: shorter than the 12-byte header",
            ),
            (
                [0x100u32, 0, 12]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect(),
                "an unknown layout of 12 bytes: 0 categories",
            ),
            (
                [0x100u32, 9, 200]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect(),
                "an unknown layout of 12 bytes: the table of 9 counts at 200 doesn't fit its 12 bytes",
            ),
        ] {
            let found = audit_events(&bytes);
            assert_eq!((found.layout, found.problems), (None, vec![why.to_owned()]));
        }
    }

    #[test]
    fn the_xp_layout() {
        let mut data = 1u32.to_le_bytes().to_vec();
        for v in [3u32, 3, 0, 0, 1, 3, 3, 0, 7] {
            data.extend(v.to_le_bytes());
        }
        data.extend(9u32.to_le_bytes());
        let found = audit_events(&data);
        assert_eq!(
            (found.layout, found.auditing_mode),
            (Some(Layout::Categories), Some(true))
        );
        let got: Vec<(&str, String)> = found
            .settings
            .iter()
            .map(|s| (s.category.unwrap_or("?"), s.setting.name()))
            .collect();
        assert_eq!(got[0], ("System", "success_and_failure".to_owned()));
        assert_eq!(got[4], ("Detailed Tracking", "success".to_owned()));
        assert_eq!(got[8], ("Account Logon", "0x7".to_owned()));
        assert_eq!(
            found.problems,
            ["Account Logon: a setting of 0x7, not 0 to 3"]
        );
        assert!(found.settings.iter().all(|s| s.subcategory_id().is_none()));
        assert!(Setting::SuccessAndFailure.success() && Setting::Failure.failure());
        assert!(!Setting::Success.failure() && !Setting::None.success());
        assert_eq!(Layout::Categories.name(), "categories");
    }
}
