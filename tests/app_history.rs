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

//! Traces third-party tools leave in public `NTUSER.DAT` hives (`tests/fixtures/`): the DFIR
//! Artifact Museum's Windows 10 APT simulation user (MIT; its dirty hive and logs), whose
//! Sysinternals keys are what regipy's `sysinternals` plugin gives, and regipy's (MIT), whose
//! WinRAR history is what regipy's `winrar_plugin` and Plaso's `winrar_mru` give.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::app_history::{App, ntuser};
use ys_registry_parser::{Hive, LogFile};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// A trace's app, item, `EulaAccepted` or e-mail address, first run and folder.
type Trace<'a> = (App, &'a str, Option<&'a str>, Option<u64>, Option<&'a str>);

#[test]
fn sysinternals_tools_a_user_first_ran() {
    let logs: Vec<LogFile> = ["ntuser.dat.LOG1", "ntuser.dat.LOG2"]
        .iter()
        .map(|name| LogFile {
            name: (*name).to_owned(),
            data: fixture(&format!("museum/w10_apt_{name}")),
        })
        .collect();
    let (hive, recovery) = Hive::open(fixture("museum/w10_apt_NTUSER.DAT"), &logs).unwrap();
    assert!(recovery.dirty && recovery.recovered);
    let (traces, problems) = ntuser(&hive);
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<Trace> = traces
        .iter()
        .map(|t| {
            (
                t.app,
                t.item.as_str(),
                t.value.as_deref(),
                t.first_used,
                t.path.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            // PsExec and Sysmon, each key holding only EulaAccepted: when they first ran
            (
                App::Sysinternals,
                "PsExec",
                Some("1"),
                Some(132_914_158_635_798_226),
                None
            ),
            (
                App::Sysinternals,
                "System Monitor",
                Some("1"),
                Some(132_914_154_770_137_128),
                None
            ),
            (
                App::OneDrive,
                "Personal",
                None,
                None,
                Some(r"C:\Users\TestUser\OneDrive")
            ),
        ]
    );
    assert_eq!(traces[0].key_path, r"SOFTWARE\Sysinternals\PsExec");
    assert_eq!(traces[0].key_last_written, 132_914_158_635_798_226);
    assert!(
        traces
            .iter()
            .all(|t| t.problems.is_empty() && t.data_raw.is_none() && !t.replayed)
    );
}

#[test]
fn winrar_history() {
    let hive = Hive::open(fixture("regipy/NTUSER.DAT"), &[]).unwrap().0;
    let (traces, problems) = ntuser(&hive);
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<String> = traces
        .iter()
        .map(|t| {
            format!(
                "{} {} {} {} {}",
                t.app.name(),
                t.item,
                t.mru_position.unwrap(),
                t.value_name.as_deref().unwrap(),
                t.path.as_deref().unwrap()
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            r"WinRAR ArcHistory 0 0 C:\Users\tony\Downloads\RegistryFinder64.zip",
            r"WinRAR ArcHistory 1 1 C:\temp\token.zip",
            "WinRAR ArcName 0 0 Tools.zip",
            "WinRAR ArcName 1 1 data.zip",
            r"WinRAR ExtrPath 0 0 C:\Users\tony\Downloads",
            r"WinRAR ExtrPath 1 1 C:\temp",
        ]
    );
    assert_eq!(
        (traces[0].key_path.as_str(), traces[0].key_last_written),
        (r"Software\WinRAR\ArcHistory", 132_817_175_448_889_527)
    );
    assert_eq!(
        traces[4].key_path,
        r"Software\WinRAR\DialogEditHistory\ExtrPath"
    );
}
