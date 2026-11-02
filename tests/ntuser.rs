//! The `NTUSER.DAT` of regipy's test data (MIT; `tests/fixtures/regipy/`): its recent documents
//! and profile; and its `UsrClass.dat`'s `MuiCache`. The items, their order and their shortcuts' names are those a reader built on
//! yarp and libfwsi gives for the same hive (and for 8 other public `NTUSER.DAT` hives).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::ntuser::{MUI_CACHE, mui_cache, profile_name, recent_docs, user_assist};
use ys_registry_parser::{Hive, LogFile};

fn ntuser() -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/NTUSER.DAT.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

#[test]
fn recent_documents_in_their_order() {
    let hive = ntuser();
    assert_eq!(profile_name(&hive).as_deref(), Some("vibranium"));
    let (lists, problems) = recent_docs(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let extensions: Vec<Option<&str>> = lists.iter().map(|l| l.extension.as_deref()).collect();
    assert_eq!(
        extensions,
        [
            None,
            Some(".JPG"),
            Some(".xls"),
            Some(".xlsx"),
            Some("Folder")
        ]
    );
    assert!(lists.iter().all(|l| l.problems.is_empty()));
    let all = &lists[0];
    assert_eq!(all.last_written, 129_780_277_971_607_147);
    let items: Vec<(Option<u32>, u32, &str, &str)> = all
        .items
        .iter()
        .map(|i| {
            assert!(i.problems.is_empty() && i.raw.is_none() && !i.replayed);
            (
                i.mru_position,
                i.value_index,
                i.name.as_deref().unwrap(),
                i.link_name.as_deref().unwrap(),
            )
        })
        .collect();
    assert_eq!(items.len(), 11);
    assert_eq!(
        items[..3],
        [
            (
                Some(0),
                9,
                "Agents-List-CLASSIFIED-TOP-SECRET",
                "Agents-List-CLASSIFIED-TOP-SECRET.lnk"
            ),
            (
                Some(1),
                10,
                "Undercover-Agents-List-For-United-Kingdom.xls",
                // the shortcut is named without the document's extension
                "Undercover-Agents-List-For-United-Kingdom.lnk"
            ),
            (
                Some(2),
                8,
                "Undercover-Agents-List-For-United-States.xlsx",
                "Undercover-Agents-List-For-United-States.lnk"
            ),
        ]
    );
    assert_eq!(items[10], (Some(10), 0, "Downloads", "Downloads.lnk"));
    let jpg = &lists[1];
    assert_eq!(jpg.last_written, 129_780_274_317_075_897);
    let names: Vec<&str> = jpg
        .items
        .iter()
        .map(|i| i.name.as_deref().unwrap())
        .collect();
    assert_eq!(names, ["hq-1.JPG", "clp-2 - Fuel Hookup.JPG", "clp-1.JPG"]);
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/regipy/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// `UserAssist` as Plaso's `userassist` reads it (and regipy's `user_assist`, but for its
/// duplicates): the same items with the same counts, focus and last-run times. 641 items of 12
/// public `NTUSER.DAT` hives agree the same way.
#[test]
fn user_assist_of_regipy_hives() {
    let (entries, problems) = user_assist(&ntuser()).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(entries.len(), 29);
    assert!(
        entries
            .iter()
            .all(|e| e.problems.is_empty() && e.format == Some(5))
    );
    let welcome = entries
        .iter()
        .find(|e| e.name.ends_with(r"\Welcome Center.lnk"))
        .unwrap();
    assert_eq!(
        (
            welcome.kind,
            welcome.path.as_deref(),
            welcome.run_count,
            welcome.focus_count,
            welcome.focus_time_ms,
            welcome.last_run
        ),
        (
            "shortcut",
            Some(
                r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Welcome Center.lnk"
            ),
            Some(14),
            Some(0),
            Some(14),
            Some(129_779_644_181_242_823)
        )
    );
    let cmd = entries
        .iter()
        .find(|e| e.name.ends_with(r"\cmd.exe"))
        .unwrap();
    assert_eq!(
        (
            cmd.kind,
            cmd.path.as_deref(),
            cmd.run_count,
            cmd.focus_time_ms
        ),
        (
            "executable",
            Some(r"%windir%\SysWOW64\cmd.exe"),
            Some(2),
            Some(611_562)
        )
    );

    // the dirty hive: its logs add 3 items
    let plain = Hive::open(fixture("transactions_NTUSER.DAT"), &[])
        .unwrap()
        .0;
    assert_eq!(user_assist(&plain).unwrap().0.len(), 18);
    let logs = [LogFile {
        name: "transactions_ntuser.dat.log1".to_owned(),
        data: fixture("transactions_ntuser.dat.log1"),
    }];
    let replayed = Hive::open(fixture("transactions_NTUSER.DAT"), &logs)
        .unwrap()
        .0;
    let (entries, problems) = user_assist(&replayed).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(entries.len(), 21);
    assert!(entries.iter().any(|e| e.replayed));
}

/// `MuiCache` of regipy's dirty Windows 10 `UsrClass.dat`: the same programs, names and companies
/// as dissect.target's `muicache` and regipy's values give (827 values of 36 public hives agree
/// the same way). Its logs add 4 programs; only those are said to be replayed.
#[test]
fn mui_cache_of_regipy_usrclass() {
    let plain = Hive::open(fixture("UsrClass.dat"), &[]).unwrap().0;
    let cache = mui_cache(&plain).unwrap();
    assert_eq!(
        (
            cache.entries.len(),
            cache.resource_strings,
            cache.problems.len()
        ),
        (15, 0, 0)
    );
    let logs: Vec<LogFile> = ["UsrClass.dat.LOG1", "UsrClass.dat.LOG2"]
        .iter()
        .map(|&name| LogFile {
            name: name.to_owned(),
            data: fixture(name),
        })
        .collect();
    let replayed = Hive::open(fixture("UsrClass.dat"), &logs).unwrap().0;
    let cache = mui_cache(&replayed).unwrap();
    assert_eq!(cache.problems, Vec::<String>::new());
    assert_eq!(cache.entries.len(), 19);
    assert!(cache.entries.iter().all(|e| e.key_path == MUI_CACHE
        && e.key_last_written == 131_674_912_241_941_985
        && e.problems.is_empty()
        && e.friendly_app_name_raw.is_none()
        && e.application_company_raw.is_none()));
    let first = &cache.entries[0];
    assert_eq!(
        (
            first.path.as_str(),
            first.friendly_app_name.as_deref(),
            first.application_company.as_deref()
        ),
        (
            r"C:\Windows\Explorer.exe",
            Some("Windows Explorer"),
            Some("Microsoft Corporation")
        )
    );
    let added: Vec<(&str, Option<&str>, Option<&str>)> = cache
        .entries
        .iter()
        .filter(|e| e.replayed)
        .map(|e| {
            (
                e.path.as_str(),
                e.friendly_app_name.as_deref(),
                e.application_company.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        added,
        [
            (
                r"C:\Users\jcloudy\Downloads\installbackupandsync.exe",
                Some("Google Update Setup"),
                Some("Google Inc.")
            ),
            (
                r"C:\Users\jcloudy\Downloads\DropboxInstaller.exe",
                Some("Dropbox Update Setup"),
                Some("Dropbox, Inc.")
            ),
            (
                r"C:\Users\jcloudy\Downloads\BoxSyncSetup.exe",
                Some("Box Sync"),
                Some("Box Inc.")
            ),
            (
                r"C:\Program Files (x86)\Microsoft Office\Root\Office16\EXCEL.EXE",
                Some("Excel 2016"),
                Some("Microsoft Corporation")
            ),
        ]
    );
    // Windows 7 keeps it in UsrClass.dat: its NTUSER.DAT has none
    assert_eq!(mui_cache(&ntuser()), None);
}
