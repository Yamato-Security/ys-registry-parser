//! The `NTUSER.DAT` of regipy's test data (MIT; `tests/fixtures/regipy/`): its recent documents
//! and profile. The items, their order and their shortcuts' names are those a reader built on
//! yarp and libfwsi gives for the same hive (and for 8 other public `NTUSER.DAT` hives).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::ntuser::{profile_name, recent_docs, user_assist};
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
