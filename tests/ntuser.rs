//! The `NTUSER.DAT` of regipy's test data (MIT; `tests/fixtures/regipy/`): its recent documents
//! and profile; Explorer's use counts, recent apps and pins in it and two of its other hives. The items, their order and their shortcuts' names are those a reader built on
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

/// Explorer's pins and programs cache in regipy's Windows 7 `NTUSER.DAT`, and its pins and
/// recent apps in the dirty Windows 10 one: the same `ProgramsCache` items as Plaso's
/// `explorer_programscache`, and the same `Favorites` and `FavoritesResolve` paths and packaged
/// app IDs as libyal's shell item, property store and link readers (152 and 70 items of 10
/// public hives agree the same way).
#[test]
#[allow(clippy::too_many_lines)]
fn explorer_pins_and_programs_cache() {
    use ys_registry_parser::ntuser::{feature_usage, programs_cache, recent_apps, taskband};
    let hive = ntuser();
    assert!(feature_usage(&hive).is_none() && recent_apps(&hive).is_none());
    let (pins, problems) = taskband(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<(&str, Option<&str>, Option<&str>)> = pins
        .iter()
        .map(|p| {
            assert!(p.problems.is_empty() && p.data_raw.is_none());
            (
                p.value_name.as_str(),
                p.item_path.as_deref(),
                p.application.as_deref(),
            )
        })
        .collect();
    let lnk = r"C:\Users\vibranium\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Windows Explorer.lnk";
    assert_eq!(
        got[1..5],
        [
            (
                "FavoritesResolve",
                Some(lnk),
                Some(r"{F38BF404-1D43-42F2-9305-67DE0B28FC23}\explorer.exe")
            ),
            (
                "FavoritesResolve",
                Some(
                    r"C:\Users\vibranium\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Windows Media Player.lnk"
                ),
                Some("Microsoft.Windows.MediaPlayer32")
            ),
            (
                "Favorites",
                Some(r"User Pinned\TaskBar\Internet Explorer.lnk"),
                Some("Microsoft.InternetExplorer.Default")
            ),
            (
                "Favorites",
                Some(r"User Pinned\TaskBar\Windows Explorer.lnk"),
                Some(r"{F38BF404-1D43-42F2-9305-67DE0B28FC23}\explorer.exe")
            ),
        ]
    );
    assert_eq!(pins.len(), 6);
    assert!(
        pins.iter()
            .all(|p| p.key_last_written == 129_779_645_274_301_576)
    );

    let (cache, problems) = programs_cache(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let count = |value: &str| cache.iter().filter(|c| c.value_name == value).count();
    assert_eq!(
        [
            count("ProgramsCache"),
            count("ProgramsCacheSMP"),
            count("ProgramsCacheTBP")
        ],
        [19, 0, 3]
    );
    // in the hive's value order: ProgramsCacheTBP, then ProgramsCache
    let paths: Vec<&str> = cache[3..8]
        .iter()
        .map(|c| c.item_path.as_deref().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "Programs",
            "Internet Explorer.lnk",
            r"Programs\Accessories",
            "Command Prompt.lnk",
            "Notepad.lnk"
        ]
    );
    assert!(cache.iter().all(|c| c.problems.is_empty()));
    assert_eq!(
        (cache[2].value_name.as_str(), cache[2].item_path.as_deref()),
        (
            "ProgramsCacheTBP",
            Some(r"User Pinned\TaskBar\Windows Media Player.lnk")
        )
    );
    assert_eq!(cache.last().unwrap().item_path.as_deref(), Some("Help.lnk"));

    // the dirty Windows 10 hive: a recent app, and packaged apps pinned
    let hive = Hive::open(fixture("transactions_NTUSER.DAT"), &[])
        .unwrap()
        .0;
    let (apps, problems) = recent_apps(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(apps.len(), 1);
    assert_eq!(
        (
            apps[0].application.as_deref(),
            apps[0].count,
            apps[0].last_accessed,
            apps[0].item_path.as_deref()
        ),
        (
            Some(r"D:\setup64.exe"),
            Some(1),
            Some(131_443_184_721_780_000),
            None
        )
    );
    let (pins, _) = taskband(&hive).unwrap();
    let favorites: Vec<(Option<&str>, Option<&str>)> = pins
        .iter()
        .filter(|p| p.value_name == "Favorites")
        .map(|p| (p.item_path.as_deref(), p.pin_type.as_deref()))
        .collect();
    assert_eq!(
        favorites,
        [
            (
                Some(r"Applications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge"),
                None
            ),
            (
                Some(r"User Pinned\TaskBar\File Explorer.lnk"),
                Some("SystemPinned")
            ),
            (
                Some(r"Applications\Microsoft.WindowsStore_8wekyb3d8bbwe!App"),
                None
            ),
            (
                Some(
                    r"Applications\microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"
                ),
                None
            ),
        ]
    );
}

/// `FeatureUsage` of regipy's Windows 10 `NTUSER_BAGMRU.DAT`: every count the same as libyal's
/// regf reader gives (228 counts of 5 public hives agree the same way).
#[test]
fn feature_usage_counts() {
    use ys_registry_parser::ntuser::{feature_usage, feature_usage_created};
    let hive = Hive::open(fixture("NTUSER_BAGMRU.DAT"), &[]).unwrap().0;
    let (entries, problems) = feature_usage(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    assert!(
        entries
            .iter()
            .all(|e| e.problems.is_empty() && e.count.is_some())
    );
    let count = |source: &str| entries.iter().filter(|e| e.source == source).count();
    assert_eq!(
        [
            count("AppBadgeUpdated"),
            count("AppLaunch"),
            count("AppSwitched"),
            count("ShowJumpView"),
            count("TrayButtonClicked")
        ],
        [11, 5, 57, 10, 5]
    );
    let of = |source: &str, application: &str| {
        entries
            .iter()
            .find(|e| e.source == source && e.application.as_deref() == Some(application))
            .and_then(|e| e.count)
    };
    assert_eq!(of("AppSwitched", "Microsoft.Windows.Explorer"), Some(410));
    assert_eq!(
        of(
            "AppSwitched",
            r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
        ),
        Some(185)
    );
    assert_eq!(of("TrayButtonClicked", "StartButton"), Some(33));
    assert_eq!(of("AppLaunch", "MSEdge"), Some(3));
    let switched = entries.iter().find(|e| e.source == "AppSwitched").unwrap();
    assert_eq!(switched.key_last_written, 132_982_894_092_004_591);
    assert_eq!(feature_usage_created(&hive), Some(132_653_766_568_771_977));
}
