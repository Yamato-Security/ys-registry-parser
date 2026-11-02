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

//! Most-recently-used lists in public `NTUSER.DAT` hives: regipy's (MIT; `tests/fixtures/regipy/`)
//! and Plaso's (Apache-2.0; `tests/fixtures/plaso/`). The entries and their order are those
//! Plaso's `mrulist`, `mrulistex`, `typedurls` and `typedurlstime` plugins and regipy's `runmru`,
//! `typed_paths`, `word_wheel_query` and `typed_urls` give for the same hives.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::mru::{MruEntry, MruList, mru_lists};
use ys_registry_parser::{Hive, LogFile};

fn unpack(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// Each entry's list, place, value name and value.
fn lines(entries: &[MruEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| {
            format!(
                "{} {} {} {}",
                e.list.name(),
                e.mru_position.map_or("-".to_owned(), |p| p.to_string()),
                e.value_name,
                e.value.as_deref().unwrap_or("-")
            )
        })
        .collect()
}

#[test]
fn search_terms_and_addresses() {
    let hive = Hive::open(unpack("regipy/NTUSER.DAT"), &[]).unwrap().0;
    let (entries, problems) = mru_lists(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(
        lines(&entries),
        [
            "WordWheelQuery 0 1 alloy",
            "WordWheelQuery 1 5 test-plan",
            "WordWheelQuery 2 4 vibranium",
            "WordWheelQuery 3 3 accounts",
            "WordWheelQuery 4 2 myron maclain",
            "WordWheelQuery 5 0 adamantium",
            "TypedURLs 0 url1 http://199.73.28.114:53/",
            "TypedURLs 1 url2 http://go.microsoft.com/fwlink/?LinkId=69157",
        ]
    );
    assert!(entries.iter().all(|e| e.problems.is_empty()
        && e.data_raw.is_none()
        && e.typed_time.is_none()
        && e.subkey.is_none()));
    // 2012-04-04T15:45:18.5513397Z: when "alloy" was searched for
    assert_eq!(entries[0].key_last_written, 129_780_279_185_513_397);
    assert_eq!(
        entries[0].key_path,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    );
}

#[test]
fn run_dialog_commands_with_and_without_the_logs() {
    let logs = vec![
        LogFile {
            name: "NTUSER.DAT.LOG1".to_owned(),
            data: unpack("regipy/transactions_ntuser.dat.log1"),
        },
        LogFile {
            name: "NTUSER.DAT.LOG2".to_owned(),
            data: unpack("regipy/transactions_ntuser.dat.log2"),
        },
    ];
    let hive = Hive::open(unpack("regipy/transactions_NTUSER.DAT"), &logs)
        .unwrap()
        .0;
    let (entries, problems) = mru_lists(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    // the logs add `b` and put it first
    assert_eq!(
        lines(&entries),
        [
            r"RunMRU 0 b c:\Windows\System32\config",
            "RunMRU 1 a ...",
            "TypedURLs 0 url1 http://go.microsoft.com/fwlink/p/?LinkId=255141",
        ]
    );
    assert!(entries[0].replayed && entries[1].replayed && !entries[2].replayed);
    let hive = Hive::open(unpack("regipy/transactions_NTUSER.DAT"), &[])
        .unwrap()
        .0;
    let (entries, _) = mru_lists(&hive).unwrap();
    assert_eq!(lines(&entries)[0], "RunMRU 0 a ...");
    assert!(!entries[0].replayed);
}

#[test]
fn typed_addresses_with_their_times() {
    let hive = Hive::open(unpack("plaso/NTUSER.DAT"), &[]).unwrap().0;
    let (entries, problems) = mru_lists(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<(&str, Option<&str>, Option<u64>)> = entries
        .iter()
        .map(|e| (e.value_name.as_str(), e.value.as_deref(), e.typed_time))
        .collect();
    assert_eq!(
        got,
        [
            (
                "url1",
                Some("http://www.catnews.com/"),
                Some(131_201_344_709_674_171)
            ),
            (
                "url2",
                Some("http://spotify.com/"),
                Some(131_201_339_028_784_497)
            ),
            (
                "url3",
                Some("http://pintrest.com/"),
                Some(131_201_338_961_259_150)
            ),
            (
                "url4",
                Some("http://webmail.student.greendale.xyz/"),
                Some(131_201_337_046_414_456)
            ),
            // TypedURLsTime's url5 is 0: no time
            (
                "url5",
                Some("http://go.microsoft.com/fwlink/p/?LinkId=255141"),
                None
            ),
        ]
    );
    assert!(
        entries
            .iter()
            .all(|e| e.list == MruList::TypedUrls && e.problems.is_empty())
    );
    // a hive with none of the lists' keys
    let sam = Hive::open(unpack("regipy/SAM"), &[]).unwrap().0;
    assert!(mru_lists(&sam).is_none());
}
