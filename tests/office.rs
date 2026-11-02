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

//! Microsoft Office in public `NTUSER.DAT` hives: regipy's (MIT; `tests/fixtures/regipy/`) and
//! Plaso's Windows 7 one (Apache-2.0; `tests/fixtures/plaso/`). The items, their paths and times
//! are those Plaso's `officemru` and dissect.target's Office MRU parser give, and the trust
//! records those dissect.target's trust record structure gives.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::office::{OfficeEntry, OfficeList, office};

fn unpack(name: &str) -> Hive {
    let path = format!("{}/tests/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

/// Each entry's list, version, application, value name, path and last-opened time.
fn lines(entries: &[OfficeEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| {
            format!(
                "{} {} {} {} | {} | {}",
                e.list.name(),
                e.office_version,
                e.application,
                e.value_name,
                e.path.as_deref().unwrap_or("-"),
                e.last_opened.map_or("-".to_owned(), |t| t.to_string())
            )
        })
        .collect()
}

#[test]
fn excel_documents_and_folders() {
    let (entries, problems) = office(&unpack("regipy/NTUSER.DAT")).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let docs = r"C:\Users\nromanoff\Documents";
    let secret =
        format!(r"{docs}\Undercover Agent-List-Classified\Agents-List-CLASSIFIED-TOP-SECRET");
    let cards = format!(r"{docs}\CC R&D Backstopped Accounts");
    let (lists, others): (Vec<OfficeEntry>, Vec<OfficeEntry>) = entries
        .into_iter()
        .partition(|e| matches!(e.list, OfficeList::FileMru | OfficeList::PlaceMru));
    assert_eq!(
        lines(&lists),
        [
            format!(
                r"File MRU 14.0 Excel Item 1 | {secret}\Undercover-Agents-List-For-United-Kingdom.xls | 129780277968480000"
            ),
            format!(
                r"File MRU 14.0 Excel Item 2 | {secret}\Undercover-Agents-List-For-United-States.xlsx | 129780277772380000"
            ),
            format!(
                r"File MRU 14.0 Excel Item 3 | {cards}\CC-Backstopped-Accounts.xlsx | 129780277391910000"
            ),
            format!(
                r"File MRU 14.0 Excel Item 4 | {cards}\Credit-Card-Numbers-For-Research.xlsx | 129780277213320000"
            ),
            format!(r"Place MRU 14.0 Excel Item 1 | {secret}\ | 129780277968320000"),
            format!(r"Place MRU 14.0 Excel Item 2 | {cards}\ | 129780277391760000"),
        ]
    );
    // Office's default trusted locations: Excel's six, PowerPoint's four, Word's three
    assert_eq!(others.len(), 13);
    assert!(
        others
            .iter()
            .all(|e| e.list == OfficeList::TrustedLocations)
    );
    let entries = lists;
    assert!(entries.iter().all(|e| e.problems.is_empty()
        && e.data_raw.is_none()
        && e.item_flags == Some(0)
        && e.account.is_none()
        && !e.policy));
    let positions: Vec<Option<u32>> = entries.iter().map(|e| e.mru_position).collect();
    assert_eq!(
        positions,
        [Some(0), Some(1), Some(2), Some(3), Some(0), Some(1)]
    );
    assert_eq!(
        entries[0].key_path,
        r"Software\Microsoft\Office\14.0\Excel\File MRU"
    );
}

/// A trust record's name, time, flags and whether its macros were enabled.
type Trusted<'a> = (&'a str, Option<u64>, Option<u32>, Option<bool>);

#[test]
fn word_documents_and_trust_records() {
    let (entries, problems) = office(&unpack("plaso/NTUSER-WIN7.DAT")).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let of = |list: OfficeList| -> Vec<&OfficeEntry> {
        entries.iter().filter(|e| e.list == list).collect()
    };
    assert_eq!(of(OfficeList::FileMru).len(), 5);
    assert_eq!(of(OfficeList::PlaceMru).len(), 2);
    let latest = of(OfficeList::FileMru)[0];
    assert_eq!(
        (
            latest.application.as_str(),
            latest.path.as_deref(),
            latest.last_opened
        ),
        (
            "Word",
            Some(
                r"C:\Users\nfury\Documents\StarFury\StarFury\SA-23E Mitchell-Hyundyne Starfury.docx"
            ),
            Some(129_761_368_350_830_000)
        )
    );
    // three documents trusted for editing, none for macros
    let trusted: Vec<Trusted> = of(OfficeList::TrustRecords)
        .iter()
        .map(|e| {
            (
                e.value_name.as_str(),
                e.trusted_at,
                e.trust_flags,
                e.macros_enabled,
            )
        })
        .collect();
    assert_eq!(
        trusted,
        [
            (
                "%USERPROFILE%/Documents/StarFury/StarFury/StarFury.docx",
                Some(129_760_698_220_000_000),
                Some(1),
                Some(false)
            ),
            (
                "%USERPROFILE%/Documents/StarFury/StarFury/Earthforce%20SA-26%20Thunderbolt%20Star%20Fury.docx",
                Some(129_760_591_200_000_000),
                Some(1),
                Some(false)
            ),
            (
                "%USERPROFILE%/Documents/StarFury/StarFury/SA-23E%20Mitchell-Hyundyne%20Starfury.docx",
                Some(129_760_591_200_000_000),
                Some(1),
                Some(false)
            ),
        ]
    );
    // Office's default trusted locations: Excel's six, PowerPoint's four, Word's three
    let locations = of(OfficeList::TrustedLocations);
    assert_eq!(locations.len(), 13);
    let word_startup = locations
        .iter()
        .find(|e| e.application == "Word" && e.value_name == "Location2")
        .unwrap();
    assert_eq!(
        (word_startup.path.as_deref(), word_startup.value.as_deref()),
        (
            Some(r"%APPDATA%\Microsoft\Word\Startup"),
            Some("Description=2")
        )
    );
    assert_eq!(of(OfficeList::Security), Vec::<&OfficeEntry>::new());
    assert!(
        entries
            .iter()
            .all(|e| e.problems.is_empty() && e.office_version == "14.0")
    );
}

#[test]
fn a_hive_without_office() {
    assert!(office(&unpack("regipy/SAM")).is_none());
}
