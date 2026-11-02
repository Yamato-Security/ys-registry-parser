//! The `NTUSER.DAT` of Plaso's test data (Apache-2.0; `tests/fixtures/plaso/`): the common
//! dialogs' history. The entries, their order and their programs are those Plaso's `mrulistex`
//! plugins give for the same hive (and for 17 other public `NTUSER.DAT` hives).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::comdlg32::{COMDLG32, DialogList, dialogs, item_list_problem};

fn plaso_ntuser() -> Hive {
    let path = format!(
        "{}/tests/fixtures/plaso/NTUSER.DAT.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

/// `name` in UTF-16, as a file entry's long name is.
fn utf16(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// An entry's list, extension, place, value and program.
type Entry<'a> = (
    DialogList,
    Option<&'a str>,
    Option<u32>,
    &'a str,
    Option<&'a str>,
);

#[test]
fn every_list_in_its_order() {
    let hive = plaso_ntuser();
    let (entries, problems) = dialogs(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<Entry> = entries
        .iter()
        .map(|e| {
            (
                e.list,
                e.extension.as_deref(),
                e.mru_position,
                e.value_name.as_str(),
                e.program.as_deref(),
            )
        })
        .collect();
    let iexplore = Some("iexplore.exe");
    assert_eq!(
        got,
        [
            (DialogList::OpenSavePidlMru, Some("*"), Some(0), "1", None),
            (DialogList::OpenSavePidlMru, Some("*"), Some(1), "0", None),
            (DialogList::OpenSavePidlMru, Some("png"), Some(0), "1", None),
            (DialogList::OpenSavePidlMru, Some("png"), Some(1), "0", None),
            (DialogList::LastVisitedPidlMru, None, Some(0), "0", iexplore),
            (DialogList::CidSizeMru, None, Some(0), "0", iexplore),
            (
                DialogList::FirstFolder,
                None,
                Some(0),
                "0",
                Some(r"C:\Program Files\Internet Explorer\iexplore.exe")
            ),
        ]
    );
    assert!(
        entries.iter().all(|e| e.problems.is_empty()
            && e.data_raw.is_none()
            && e.path.is_none()
            && !e.replayed)
    );
    // the files' shell item lists: This PC, Pictures, then the file, its long name in UTF-16
    let latest = &entries[0];
    let items = latest.shell_items.as_deref().unwrap();
    assert_eq!(item_list_problem(items), None);
    assert!(items.windows(18).any(|w| w == utf16("ash_0.png")));
    assert_eq!(latest.key_path, format!(r"{COMDLG32}\OpenSavePidlMRU\*"));
    // 2016-10-09T19:59:17.7345970Z: when ash_0.png was opened or saved
    assert_eq!(latest.key_last_written, 131_205_167_577_345_970);
    // the folder iexplore.exe last used: This PC, Pictures
    let folder = entries[4].shell_items.as_deref().unwrap();
    assert_eq!(folder.len(), 42);
    assert_eq!(item_list_problem(folder), None);
    assert!(entries[5].shell_items.is_none() && entries[6].shell_items.is_none());
}

#[test]
fn a_hive_without_comdlg32() {
    let path = format!(
        "{}/tests/fixtures/regipy/NTUSER.DAT.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    assert!(dialogs(&Hive::open(data, &[]).unwrap().0).is_none());
}
