//! Recovery on regipy's test hives (MIT; `tests/fixtures/regipy/`): deleted keys and values in
//! free cells and in the data past the hive bins, as yarp's scanner finds them (each record
//! once), and what the transaction logs alone kept: the hive before their replay (as yarp's
//! recovery gives what they changed) and their entries.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::{Hive, LogFile, Recovered, RecoveredKey, RecoveredStatus as St, Source};

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

fn recover(name: &str, logs: &[&str]) -> Recovered {
    let logs: Vec<LogFile> = logs
        .iter()
        .map(|&l| LogFile {
            name: l.to_owned(),
            data: fixture(l),
        })
        .collect();
    Hive::open(fixture(name), &logs).unwrap().0.recover()
}

/// Keys of `status` found only in places `only` allows.
fn keys<'a>(
    found: &'a Recovered,
    status: St,
    only: impl Fn(&Source) -> bool + 'a,
) -> impl Iterator<Item = &'a RecoveredKey> + 'a {
    found
        .keys
        .iter()
        .filter(move |k| k.status == status && !k.in_use && k.sources.iter().all(&only))
}

fn is_log(s: &Source) -> bool {
    matches!(s, Source::LogEntry { .. })
}

#[test]
fn free_cells_and_remnant_data() {
    let sam = recover("SAM", &[]);
    assert_eq!(sam.keys.len(), 3);
    assert!(
        sam.keys
            .iter()
            .all(|k| k.status == St::DeletedComplete && k.sources == [Source::FreeCell])
    );
    assert!(
        sam.keys[0]
            .values
            .iter()
            .all(|v| v.status == St::DeletedComplete)
    );
    assert_eq!(sam.values.len(), 1);
    assert_eq!(sam.values[0].status, St::ResidualValueOnly);

    // an NTUSER.DAT whose file goes on past its hive bins: the keys and values left there
    let ntuser = recover("NTUSER.DAT", &[]);
    assert_eq!(ntuser.keys.len(), 99);
    assert!(ntuser.keys.iter().all(|k| k.status == St::DeletedPartial
        && k.sources == [Source::RemnantData]
        && k.path.starts_with("[unknown]")));
    let from = |s: Source| {
        ntuser
            .values
            .iter()
            .filter(|v| v.sources == [s.clone()])
            .count()
    };
    assert_eq!(
        (from(Source::FreeCell), from(Source::RemnantData)),
        (29, 219)
    );
}

#[test]
fn what_only_the_logs_kept() {
    let found = recover(
        "transactions_NTUSER.DAT",
        &[
            "transactions_ntuser.dat.log1",
            "transactions_ntuser.dat.log2",
        ],
    );
    // the keys the replay removed, and the values it removed or changed (yarp's recovery
    // changes the same 6 keys and 147 values)
    let before = |s: &Source| matches!(s, Source::BeforeReplay) || is_log(s);
    let removed: Vec<&RecoveredKey> = keys(&found, St::TransactionLogRecovered, before)
        .filter(|k| k.sources.contains(&Source::BeforeReplay))
        .collect();
    assert_eq!(removed.len(), 6);
    let changed: usize = found
        .keys
        .iter()
        .flat_map(|k| &k.values)
        .filter(|v| v.sources.contains(&Source::BeforeReplay))
        .count();
    assert_eq!(changed, 147);
    // keys only log entries hold: made and deleted within the logs' time
    let logged: Vec<&RecoveredKey> = keys(&found, St::TransactionLogRecovered, is_log).collect();
    assert_eq!(logged.len(), 3);
    let media = logged.iter().find(|k| k.name == "Current Media").unwrap();
    assert!(media.path.starts_with(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\CD Burning\Drives\Volume{"
    ));
    assert!(media.path_complete);
    assert_eq!(media.values.len(), 11);
    assert_eq!(
        media.sources,
        [Source::LogEntry {
            log: "transactions_ntuser.dat.log1".into(),
            sequence: Some(567)
        }]
    );
    assert_eq!(media.sources[0].name(), "transactions_ntuser.dat.log1#567");

    let usrclass = recover("UsrClass.dat", &["UsrClass.dat.LOG1", "UsrClass.dat.LOG2"]);
    // the replayed hive's free cells: complete or partial; also in the file before the replay
    // or in log entries, which doesn't make them less deleted
    let free: Vec<&RecoveredKey> = usrclass
        .keys
        .iter()
        .filter(|k| k.sources.contains(&Source::FreeCell))
        .collect();
    assert_eq!(free.len(), 36);
    let complete = free
        .iter()
        .filter(|k| k.status == St::DeletedComplete)
        .count();
    assert_eq!((complete, free.len() - complete), (8, 28));
    let logged: Vec<&RecoveredKey> = keys(&usrclass, St::TransactionLogRecovered, is_log).collect();
    assert_eq!(logged.len(), 1);
    assert!(logged[0].name.starts_with("Microsoft.Office.OneNote_"));
}
