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

//! The LSA secrets and cached logons of regipy's `SECURITY` (MIT; `tests/fixtures/regipy/`):
//! names, times and whether values hold data, never their bytes. Every name, time and size is
//! what python-registry reads for the same hive (and for 7 other public `SECURITY` hives).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::lsa_secrets::{SecretKind, cached_logons, secrets};

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
fn secrets_and_cached_logons() {
    let hive = security();
    let (found, problems) = secrets(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<(&str, SecretKind, Option<u64>, Option<u64>)> = found
        .iter()
        .map(|s| (s.name.as_str(), s.kind, s.current.set, s.old.set))
        .collect();
    assert_eq!(
        got,
        [
            (
                "DefaultPassword",
                SecretKind::Autologon,
                Some(132_726_344_757_163_260),
                Some(132_726_344_735_726_088)
            ),
            (
                "DPAPI_SYSTEM",
                SecretKind::DpapiSystem,
                Some(132_726_339_717_149_318),
                Some(132_726_337_907_711_915)
            ),
            (
                "NL$KM",
                SecretKind::CachedLogonKey,
                Some(132_726_337_891_767_305),
                Some(132_726_337_891_767_305)
            ),
        ]
    );
    let password = &found[0];
    assert_eq!(password.key_last_written, 132_726_340_856_913_072);
    assert_eq!(
        (password.current.size, password.old.size),
        (Some(92), Some(92))
    );
    assert_eq!(
        password.current.key_last_written,
        Some(132_726_344_757_632_054)
    );
    assert!(password.current.has_data() && password.old.has_data());
    assert!(found.iter().all(|s| s.problems.is_empty() && !s.replayed));
    assert!(found.iter().all(|s| s.service_name.is_none()));

    let cache = cached_logons(&hive).unwrap();
    assert_eq!(cache.problems, Vec::<String>::new());
    assert_eq!(
        (cache.slots, cache.in_use, cache.control_count),
        (10, 0, Some(10))
    );
    assert_eq!(cache.key_last_written, 132_726_337_891_923_364);
}
