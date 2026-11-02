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

//! Application compatibility data in public hives (`tests/fixtures/`): the Program
//! Compatibility Assistant's `Store` in regipy's dirty `NTUSER.DAT` (MIT), and a `CIT\System`
//! database of Plaso's Windows 10 `SOFTWARE` hive (Apache-2.0), whose program paths and command
//! lines are those dissect.target's `cit` plugin gives.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::appcompat::{AppCompatSource, lznt1, ntuser};

fn path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A gzipped fixture, unpacked.
fn unpacked(name: &str) -> Vec<u8> {
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path(name)).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn programs_the_compatibility_assistant_saw() {
    let hive = Hive::open(unpacked("regipy/transactions_NTUSER.DAT.gz"), &[])
        .unwrap()
        .0;
    let (entries, problems) = ntuser(&hive);
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<(&str, Vec<(&str, &str)>)> = entries
        .iter()
        .map(|e| {
            (
                e.path.as_deref().unwrap(),
                e.details
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect(),
            )
        })
        .collect();
    let onedrive = r"C:\Users\tony\AppData\Local\Microsoft\OneDrive";
    assert_eq!(
        got,
        [
            (
                &*format!(r"{onedrive}\17.3.6816.0313\FileSyncConfig.exe"),
                vec![]
            ),
            (&*format!(r"{onedrive}\Update\OneDriveSetup.exe"), vec![]),
            (
                &*format!(r"{onedrive}\17.3.6917.0607\FileSyncConfig.exe"),
                vec![]
            ),
            // a program on removable media
            ("setup64.exe", vec![("SignMedia", "6F60F6C")]),
        ]
    );
    assert!(entries.iter().all(|e| e.source == AppCompatSource::PcaStore
        && !e.machine
        && e.problems.is_empty()
        && e.last_seen.is_none()
        && e.data_raw.as_deref().unwrap().starts_with(b"SACP")));
    assert_eq!(
        entries[3].value_name.as_deref(),
        Some("SIGN.MEDIA=6F60F6C setup64.exe")
    );
    assert_eq!(
        entries[0].key_path,
        r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    );
}

#[test]
fn a_cit_database_decompressed() {
    let value = std::fs::read(path("plaso/cit_system_88EDBB9D.bin")).unwrap();
    // the size of the compressed data plus 8, the size uncompressed, then LZNT1
    let compressed = u32::from_le_bytes(value[..4].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(value[4..8].try_into().unwrap()) as usize;
    assert_eq!(compressed, value.len());
    let data = lznt1(&value[8..], size).unwrap();
    assert_eq!(data.len(), size);
}
