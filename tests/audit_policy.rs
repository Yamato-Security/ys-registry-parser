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

//! The audit policy of regipy's `SECURITY` (MIT; `tests/fixtures/regipy/`): Windows 10's default
//! policy. Every setting is what dissect's `auditpol` gives for the same hive (and for 7 other
//! public `SECURITY` hives), and the defaults are those Microsoft documents for Windows 10.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::audit_policy::{Layout, Setting, audit_policy};

fn security() -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/SECURITY.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

#[test]
fn windows_10_default_policy() {
    let policy = audit_policy(&security()).unwrap();
    assert_eq!(policy.problems, Vec::<String>::new());
    assert_eq!(policy.data_raw, None);
    assert_eq!(policy.key_last_written, 132_726_337_889_109_998);
    let events = &policy.events;
    assert_eq!(
        (events.layout, events.revision, events.unused),
        (Some(Layout::Subcategories), Some(0x100), Some(45_020))
    );
    assert_eq!(events.settings.len(), 59);
    let set: Vec<(&str, Setting)> = events
        .settings
        .iter()
        .filter(|s| s.setting != Setting::None)
        .map(|s| (s.subcategory.unwrap(), s.setting))
        .collect();
    assert_eq!(
        set,
        [
            ("Security State Change", Setting::Success),
            ("System Integrity", Setting::SuccessAndFailure),
            ("Other System Events", Setting::SuccessAndFailure),
            ("Logon", Setting::SuccessAndFailure),
            ("Logoff", Setting::Success),
            ("Account Lockout", Setting::Success),
            // index 4 of Logon/Logoff (%%12548), not after the IPsec modes as its GUID is
            ("Special Logon", Setting::Success),
            ("Network Policy Server", Setting::SuccessAndFailure),
            ("Audit Policy Change", Setting::Success),
            ("Authentication Policy Change", Setting::Success),
            ("User Account Management", Setting::Success),
            ("Security Group Management", Setting::Success),
        ]
    );
    let special = events
        .settings
        .iter()
        .find(|s| s.subcategory == Some("Special Logon"))
        .unwrap();
    assert_eq!(
        (special.subcategory_guid, special.subcategory_id()),
        (Some("0CCE921B-69AE-11D9-BED3-505054503030"), Some(12_548))
    );
    let counts: Vec<usize> = (0..9)
        .map(|c| {
            events
                .settings
                .iter()
                .filter(|s| s.category_index == c)
                .count()
        })
        .collect();
    assert_eq!(counts, [5, 11, 14, 3, 6, 6, 6, 4, 4]);
    assert!(!policy.replayed);
}
