//! Hives built here, for what real ones seldom hold: every kind of subkey list, big data,
//! damage that must not hide what's next to it, loops, a root found by its flag, and deleted keys
//! and values with their parents in use, deleted or lost.
#![allow(clippy::unwrap_used, clippy::cast_possible_wrap)]

use std::fmt::Write as _;

use ys_registry_parser::installed::{self, Program, ProgramSource, Scope};
use ys_registry_parser::ntuser::{
    classes_sid, recent_docs, rot13, user_assist, user_assist_settings,
};
use ys_registry_parser::persistence::{self, Autostart, MachineClasses, Mechanism};
use ys_registry_parser::remote_access::connections;
use ys_registry_parser::sam::{accounts, machine_sid};
use ys_registry_parser::shellbags::shell_bags;
use ys_registry_parser::software::{TaskAction, profile_list, task_cache};
use ys_registry_parser::system::{Moderator, bam};
use ys_registry_parser::system_info::{domains, software, system};
use ys_registry_parser::usb;
use ys_registry_parser::{Data, Hive, RecoveredStatus, Source, Status, decode};

/// 2022-02-08T21:03:52Z.
const WHEN: u64 = 132_888_278_320_000_000;
const NONE: u32 = u32::MAX;

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[test]
fn dialog_mru_letters_use_registry_case_comparisons() {
    use ys_registry_parser::comdlg32::{COMDLG32, dialogs};
    let path = format!(r"{COMDLG32}\OpenSaveMRU\txt");
    let mut tree = Tree::default();
    tree.set(&path, "MRUList", 1, &utf16z("Σ"))
        .set(&path, "ς", 1, &utf16z(r"C:\report.txt"));
    let (entries, problems) = dialogs(&tree.hive("ROOT")).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].value_name, "ς");
    assert_eq!(entries[0].mru_position, Some(0));
    assert_eq!(entries[0].problems, Vec::<String>::new());

    // These letters have the same lowercase form, but Windows registry uppercasing
    // does not join the Kelvin sign to an ASCII K.
    let mut tree = Tree::default();
    tree.set(&path, "MRUList", 1, &utf16z("K\u{212a}"))
        .set(&path, "k", 1, &utf16z(r"C:\one.txt"))
        .set(&path, "\u{212a}", 1, &utf16z(r"C:\two.txt"));
    let (entries, problems) = dialogs(&tree.hive("ROOT")).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].mru_position, Some(0));
    assert_eq!(entries[1].mru_position, Some(1));
    assert_eq!(entries[1].value_name, "\u{212a}");
}

#[test]
fn damaged_dialog_mru_does_not_promote_a_later_entry_to_most_recent() {
    use ys_registry_parser::comdlg32::{COMDLG32, dialogs};
    let path = format!(r"{COMDLG32}\OpenSaveMRU\txt");
    let order: Vec<u8> = [0xd800, 0x0061, 0x0000]
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut tree = Tree::default();
    tree.set(&path, "MRUList", 1, &order)
        .set(&path, "a", 1, &utf16z(r"C:\report.txt"));
    let (entries, problems) = dialogs(&tree.hive("ROOT")).unwrap();
    assert!(problems.iter().any(|p| p.contains("not valid UTF-16")));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].mru_position, Some(1));
}

#[test]
fn damaged_dialog_mru_text_is_reported() {
    use ys_registry_parser::comdlg32::{COMDLG32, dialogs};
    let path = format!(r"{COMDLG32}\OpenSaveMRU\txt");
    for data in [vec![b'a', 0], vec![b'a', 0, 0, 0, 7]] {
        let mut tree = Tree::default();
        tree.set(&path, "MRUList", 1, &data)
            .set(&path, "a", 1, &utf16z(r"C:\report.txt"));
        let (_, problems) = dialogs(&tree.hive("ROOT")).unwrap();
        assert!(
            !problems.is_empty(),
            "silently accepted malformed MRUList: {data:?}"
        );
    }
}

/// The cells of one hive bin, and the hive around them.
struct Builder {
    bin: Vec<u8>,
}

impl Builder {
    fn new() -> Self {
        Builder { bin: vec![0; 32] }
    }

    /// A cell holding `data`, in use or free; its offset.
    fn put(&mut self, data: &[u8], free: bool) -> u32 {
        let offset = self.bin.len();
        let size = (4 + data.len()).next_multiple_of(8);
        let field = if free { size as i32 } else { -(size as i32) };
        self.bin.extend(field.to_le_bytes());
        self.bin.extend(data);
        self.bin.resize(offset + size, 0);
        offset as u32
    }

    /// A value, its data in a cell when it doesn't fit in the value; the cells in use or free.
    fn value(&mut self, name: &str, kind: u32, data: &[u8], free: bool) -> u32 {
        let (len, offset) = if data.len() <= 4 {
            let mut d = [0u8; 4];
            d[..data.len()].copy_from_slice(data);
            (0x8000_0000 | data.len() as u32, u32::from_le_bytes(d))
        } else {
            (data.len() as u32, self.put(data, free))
        };
        self.put(&vk(name, kind, len, offset), free)
    }

    fn list(&mut self, offsets: &[u32], free: bool) -> u32 {
        let bytes: Vec<u8> = offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
        self.put(&bytes, free)
    }

    fn lf(&mut self, offsets: &[u32]) -> u32 {
        let mut lf = b"lf".to_vec();
        lf.extend((offsets.len() as u16).to_le_bytes());
        for o in offsets {
            lf.extend(o.to_le_bytes());
            lf.extend(0u32.to_le_bytes());
        }
        self.put(&lf, false)
    }

    /// A key under `parent` with `subkeys` (an `lf` list) and `values`; the key and its value
    /// list in use or free.
    fn key(&mut self, name: &str, parent: u32, subkeys: &[u32], values: &[u32], free: bool) -> u32 {
        let sub = if subkeys.is_empty() {
            (0, NONE)
        } else {
            (subkeys.len() as u32, self.lf(subkeys))
        };
        let val = if values.is_empty() {
            (0, NONE)
        } else {
            (values.len() as u32, self.list(values, free))
        };
        self.put(&nk(name, parent, sub, val, 0x20), free)
    }

    /// The root key, with `subkeys`.
    fn root(&mut self, subkeys: &[u32]) -> u32 {
        self.root_named("ROOT", subkeys)
    }

    /// The root key, named `name`, with `subkeys`.
    fn root_named(&mut self, name: &str, subkeys: &[u32]) -> u32 {
        let list = self.lf(subkeys);
        self.put(
            &nk(name, NONE, (subkeys.len() as u32, list), (0, NONE), 0x2c),
            false,
        )
    }

    /// The hive, its root at `root`.
    fn hive(mut self, root: u32) -> Vec<u8> {
        let size = (self.bin.len() + 8).next_multiple_of(4096);
        let left = size - self.bin.len();
        self.bin.extend((left as i32).to_le_bytes());
        self.bin.resize(size, 0);
        self.bin[..4].copy_from_slice(b"hbin");
        self.bin[8..12].copy_from_slice(&(size as u32).to_le_bytes());
        let mut base = vec![0u8; 4096];
        base[..4].copy_from_slice(b"regf");
        for (at, v) in [(4, 1u32), (8, 1), (20, 1), (24, 5), (32, 1)] {
            base[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        base[12..20].copy_from_slice(&WHEN.to_le_bytes());
        base[36..40].copy_from_slice(&root.to_le_bytes());
        base[40..44].copy_from_slice(&(size as u32).to_le_bytes());
        let sum = (0..508).step_by(4).fold(0u32, |x, i| {
            x ^ u32::from_le_bytes(base[i..i + 4].try_into().unwrap())
        });
        base[508..512].copy_from_slice(&sum.to_le_bytes());
        base.extend(self.bin);
        base
    }
}

/// A key record: (subkey count, list), (value count, list), flags.
fn nk(name: &str, parent: u32, subkeys: (u32, u32), values: (u32, u32), flags: u16) -> Vec<u8> {
    let mut nk = vec![0u8; 0x4c];
    nk[..2].copy_from_slice(b"nk");
    nk[2..4].copy_from_slice(&flags.to_le_bytes());
    nk[4..12].copy_from_slice(&WHEN.to_le_bytes());
    for (at, v) in [
        (0x10, parent),
        (0x14, subkeys.0),
        (0x1c, subkeys.1),
        (0x20, NONE),
        (0x24, values.0),
        (0x28, values.1),
        (0x2c, NONE),
        (0x30, NONE),
    ] {
        nk[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    nk[0x48..0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
    nk.extend(name.as_bytes());
    nk
}

fn vk(name: &str, kind: u32, len: u32, offset: u32) -> Vec<u8> {
    let raw_name = if name.is_ascii() {
        name.as_bytes().to_vec()
    } else {
        name.encode_utf16().flat_map(u16::to_le_bytes).collect()
    };
    let mut vk = vec![0u8; 0x14];
    vk[..2].copy_from_slice(b"vk");
    vk[2..4].copy_from_slice(&(raw_name.len() as u16).to_le_bytes());
    vk[4..8].copy_from_slice(&len.to_le_bytes());
    vk[8..12].copy_from_slice(&offset.to_le_bytes());
    vk[12..16].copy_from_slice(&kind.to_le_bytes());
    vk[16..18].copy_from_slice(&u16::from(name.is_ascii()).to_le_bytes());
    vk.extend(raw_name);
    vk
}

/// Every key's path, and each value as `path\name = data`.
fn read(hive: &Hive) -> (Vec<String>, Vec<String>) {
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for entry in hive.walk() {
        keys.push(entry.path.clone());
        for v in entry.key.values().0 {
            let data = decode(v.data_type(), &v.data().unwrap_or_default());
            values.push(format!("{}\\{} = {data:?}", entry.path, v.name()));
        }
    }
    (keys, values)
}

#[test]
fn keys_values_and_their_types() {
    let mut b = Builder::new();
    let values = [
        b.value("", 1, &utf16z("the default"), false),
        b.value("Path", 2, &utf16z("%SystemRoot%\\x.exe"), false),
        b.value("Items", 7, &utf16z("a\0b\0"), false),
        b.value("Count", 4, &7u32.to_le_bytes(), false),
        b.value("Time", 11, &WHEN.to_le_bytes(), false),
        b.value("Blob", 3, &[1, 2, 3, 4, 5], false),
    ];
    let run = b.key("Run", 0, &[], &values, false);
    let empty = b.key("Empty", 0, &[], &[], false);
    let software = b.key("Software", 0, &[run, empty], &[], false);
    let root = b.root(&[software]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();
    let (keys, values) = read(&hive);
    assert_eq!(keys, ["", "Software", r"Software\Run", r"Software\Empty"]);
    assert_eq!(
        values,
        [
            r#"Software\Run\ = Text { value: "the default", lossy: false }"#,
            r#"Software\Run\Path = Text { value: "%SystemRoot%\\x.exe", lossy: false }"#,
            r#"Software\Run\Items = MultiText { values: ["a", "b"], lossy: false }"#,
            r"Software\Run\Count = Number(7)",
            r"Software\Run\Time = Number(132888278320000000)",
            r"Software\Run\Blob = Bytes",
        ]
    );
    let run = hive.key(r"software\RUN").unwrap();
    assert_eq!(run.last_written(), WHEN);
    assert_eq!(run.status(), Status::Allocated);
    assert_eq!(run.value("blob").unwrap().data().unwrap(), [1, 2, 3, 4, 5]);
    assert_eq!(run.value("").unwrap().value_type().name(), "REG_SZ");
    assert!(hive.key(r"Software\Missing").is_none());
}

#[test]
fn big_data_and_index_roots() {
    let mut b = Builder::new();
    // 40,000 bytes in three segments listed by a db record
    let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let segments: Vec<u32> = data.chunks(16_344).map(|c| b.put(c, false)).collect();
    let list = b.list(&segments, false);
    let mut db = b"db".to_vec();
    db.extend((segments.len() as u16).to_le_bytes());
    db.extend(list.to_le_bytes());
    let db = b.put(&db, false);
    let big = b.put(&vk("Big", 3, 40_000, db), false);
    let a = b.key("A", 0, &[], &[big], false);
    let c = b.key("C", 0, &[], &[], false);
    // an ri list of two lf lists
    let (lf1, lf2) = (b.lf(&[a]), b.lf(&[c]));
    let mut ri = b"ri".to_vec();
    ri.extend(2u16.to_le_bytes());
    ri.extend(lf1.to_le_bytes());
    ri.extend(lf2.to_le_bytes());
    let ri = b.put(&ri, false);
    let root = b.put(&nk("ROOT", NONE, (2, ri), (0, NONE), 0x2c), false);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();
    assert_eq!(read(&hive).0, ["", "A", "C"]);
    let value = hive.key("A").unwrap().value("Big").unwrap();
    assert_eq!(value.size(), 40_000);
    assert_eq!(value.data().unwrap(), data);
}

#[test]
fn damage_does_not_hide_the_rest() {
    let mut b = Builder::new();
    let good = b.value("Good", 4, &[1, 0, 0, 0], false);
    let short = b.value("Short", 4, &[1, 2, 3], false);
    let lost = b.put(&vk("Lost", 1, 64, 0x7fff_fff8), false);
    let not_a_value = b.put(b"zz not a value", false);
    let kept = b.key("Kept", 0, &[], &[not_a_value, good, short, lost], false);
    let not_a_key = b.put(b"zz not a key", false);
    // the list holds a cell that isn't a key, an offset past the hive, and a good key
    let root = b.root(&[not_a_key, 0x7fff_0000, kept]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();
    let (subkeys, problems) = hive.root().unwrap().subkeys();
    assert_eq!(subkeys.len(), 1);
    assert_eq!(
        problems,
        [
            format!("subkey 0x{not_a_key:x} is not a key"),
            "subkey 0x7fff0000 is not a key".to_owned(),
        ]
    );
    let key = hive.key("Kept").unwrap();
    let (values, problems) = key.values();
    let names: Vec<String> = values.iter().map(ys_registry_parser::Value::name).collect();
    assert_eq!(names, ["Good", "Short", "Lost"]);
    assert_eq!(
        problems,
        [format!("value 0x{not_a_value:x} is not a value")]
    );
    assert_eq!(
        decode(4, &values[1].data().unwrap()),
        Data::Malformed("REG_DWORD of 3 bytes".into())
    );
    assert_eq!(
        values[2].data(),
        Err("its data cell 0x7ffffff8 is not allocated".to_owned())
    );
}

#[test]
fn active_records_do_not_follow_free_cells() {
    let mut b = Builder::new();

    // An allocated value whose external data cell has already been freed.
    let stale_data = b.put(&[1, 2, 3, 4, 5], true);
    let stale = b.put(&vk("StaleData", 3, 5, stale_data), false);
    // A value record which itself has been freed but remains in an allocated value list.
    let deleted_value = b.value("DeletedValue", 4, &7u32.to_le_bytes(), true);
    let active = b.key("Active", 0, &[], &[stale, deleted_value], false);

    // A free value list referenced by an allocated key.
    let live = b.value("Live", 4, &1u32.to_le_bytes(), false);
    let free_list = b.list(&[live], true);
    let free_list_key = b.put(&nk("FreeList", 0, (0, NONE), (1, free_list), 0x20), false);

    // A free key left in the allocated root's subkey list.
    let deleted_key = b.key("DeletedKey", 0, &[], &[], true);
    let root = b.root(&[active, free_list_key, deleted_key]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();

    let entries: Vec<_> = hive.walk().collect();
    assert_eq!(
        entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
        ["", "Active", "FreeList"]
    );
    assert!(entries[0].problems.iter().any(|p| p.contains("not a key")));

    let active = hive.key("Active").unwrap();
    let (values, problems) = active.values();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name(), "StaleData");
    assert!(problems.iter().any(|p| p.contains("not a value")));
    assert_eq!(
        values[0].read_data(),
        (
            Vec::new(),
            Some(format!("its data cell 0x{stale_data:x} is not allocated"))
        )
    );

    let (values, problems) = hive.key("FreeList").unwrap().values();
    assert!(values.is_empty());
    assert!(problems.iter().any(|p| p.contains("can't be read")));

    let deleted = hive.deleted();
    assert!(deleted.keys.iter().any(|k| k.offset == deleted_key));
    assert!(deleted.values.iter().any(|v| v.offset == deleted_value));
}

#[test]
fn a_loop_is_read_once() {
    let mut b = Builder::new();
    // A lists the root as its subkey (its list written first, then pointed at the root)
    let a_list = b.lf(&[0]);
    let a = b.put(&nk("A", 0, (1, a_list), (0, NONE), 0x20), false);
    let root = b.root(&[a]);
    let entry = a_list as usize + 8;
    b.bin[entry..entry + 4].copy_from_slice(&root.to_le_bytes());
    let hive = Hive::from_bytes(b.hive(root)).unwrap();
    let entries: Vec<(String, Vec<String>)> = hive.walk().map(|e| (e.path, e.problems)).collect();
    assert_eq!(
        entries,
        [
            (String::new(), Vec::new()),
            (
                "A".to_owned(),
                vec!["subkey ROOT is listed again (a loop)".to_owned()]
            ),
        ]
    );
}

#[test]
fn the_root_is_found_by_its_flag() {
    let mut b = Builder::new();
    let a = b.key("A", 0, &[], &[], false);
    let root = b.root(&[a]);
    // the base block points into the hive bin's header: not a key
    let mut bytes = b.hive(root);
    bytes[36..40].copy_from_slice(&8u32.to_le_bytes());
    let hive = Hive::from_bytes(bytes).unwrap();
    assert_eq!(hive.root().unwrap().name(), "ROOT");
    assert!(Hive::from_bytes(vec![0; 8192]).is_err());
}

#[test]
fn deleted_keys_and_values() {
    let mut b = Builder::new();
    let software = b.key("Software", 0, &[], &[], false);
    let root = b.root(&[software]);
    // a deleted key under Software, with its value; a deleted key under it
    let run = b.value("Run", 1, &utf16z(r"C:\evil.exe"), true);
    let gone = b.key("Gone", software, &[], &[run], true);
    let child = b.key("Child", gone, &[], &[], true);
    // a deleted key whose parent is lost, and one whose value is in use again
    let orphan = b.key("Orphan", 0x10, &[], &[], true);
    let reused = b.value("Reused", 4, &[1, 0, 0, 0], false);
    let reusing = b.key("Reusing", software, &[], &[reused], true);
    // A deleted key whose list has room for one of the two values it declares.
    let partial_value = b.value("Partial", 4, &[2, 0, 0, 0], true);
    let partial_list = b.list(&[partial_value], true);
    let partial = b.put(
        &nk("PartialKey", software, (0, NONE), (2, partial_list), 0x20),
        true,
    );
    // a deleted value no deleted key lists
    let leftover = b.value("Leftover", 4, &[9, 0, 0, 0], true);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();
    // the keys in use are as they were
    assert_eq!(read(&hive).0, ["", "Software"]);
    let deleted = hive.deleted();
    let keys: Vec<(u32, &str, bool, usize, usize)> = deleted
        .keys
        .iter()
        .map(|k| {
            (
                k.offset,
                k.path.as_str(),
                k.path_complete,
                k.values.len(),
                k.problems.len(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        [
            (gone, r"Software\Gone", true, 1, 0),
            (child, r"Software\Gone\Child", true, 0, 0),
            (orphan, r"[unknown]\Orphan", false, 0, 0),
            (reusing, r"Software\Reusing", true, 0, 1),
            (partial, r"Software\PartialKey", true, 1, 1),
        ]
    );
    let value = &deleted.keys[0].values[0];
    assert_eq!(
        (value.offset, value.name.as_str(), value.data_type),
        (run, "Run", 1)
    );
    assert_eq!(
        decode(1, &value.data),
        Data::Text {
            value: r"C:\evil.exe".into(),
            lossy: false
        }
    );
    assert_eq!(deleted.keys[0].last_written, WHEN);
    assert_eq!(
        deleted.keys[3].problems,
        [format!("value 0x{reused:x} is in use again")]
    );
    assert_eq!(
        deleted.keys[4].problems,
        [format!(
            "its value list 0x{partial_list:x} is cut short (1 of 2 values)"
        )]
    );
    let leftovers: Vec<(u32, &str, &[u8])> = deleted
        .values
        .iter()
        .map(|v| (v.offset, v.name.as_str(), v.data.as_slice()))
        .collect();
    assert_eq!(leftovers, [(leftover, "Leftover", &[9u8, 0, 0, 0][..])]);
}

/// The MRU list of the values `list`, ended.
fn mru(list: &[u32]) -> Vec<u8> {
    list.iter()
        .chain(&[u32::MAX])
        .flat_map(|n| n.to_le_bytes())
        .collect()
}

/// A recent document's place, value, name and problems.
type Item<'a> = (Option<u32>, u32, Option<&'a str>, Vec<String>);

#[test]
fn recent_docs_that_dont_add_up() {
    let mut b = Builder::new();
    let doc = |name: &str| utf16z(name);
    // RecentDocs: its list names a value that isn't there, a value it doesn't list, duplicate
    // numbered and list values, a value that isn't numbered, an item of the wrong type; .txt:
    // no MRUListEx
    let values = [
        b.value("MRUListEx", 3, &mru(&[2, 5, 0, 2]), false),
        b.value("0", 3, &doc("a.txt"), false),
        b.value("2", 3, &doc("b.docx"), false),
        b.value("2", 3, &doc("duplicate.docx"), false),
        b.value("3", 1, &doc("c.pdf"), false),
        b.value("ViewStream", 3, &[1, 2, 3, 4, 5], false),
        b.value("MRULISTEX", 3, &mru(&[0]), false),
    ];
    let txt_values = [b.value("0", 3, &doc("a.txt"), false)];
    let txt = b.key(".txt", 0, &[], &txt_values, false);
    let mut key = b.key("RecentDocs", 0, &[txt], &values, false);
    for name in [
        "Explorer",
        "CurrentVersion",
        "Windows",
        "Microsoft",
        "Software",
    ] {
        key = b.key(name, 0, &[key], &[], false);
    }
    let root = b.root(&[key]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();
    let (lists, _) = recent_docs(&hive).unwrap();
    let all = &lists[0];
    assert_eq!(
        all.problems,
        [
            "MRUListEx: 2 is listed twice",
            "numbered value 2 is present more than once",
            r#"value "ViewStream" is not a numbered item"#,
            "MRUListEx is present more than once"
        ]
    );
    let items: Vec<Item> = all
        .items
        .iter()
        .map(|i| {
            (
                i.mru_position,
                i.value_index,
                i.name.as_deref(),
                i.problems.clone(),
            )
        })
        .collect();
    assert_eq!(
        items,
        [
            (Some(0), 2, Some("b.docx"), vec![]),
            (
                Some(1),
                5,
                None,
                vec!["MRUListEx lists value 5, which is not there".to_owned()]
            ),
            (Some(2), 0, Some("a.txt"), vec![]),
            (
                None,
                2,
                Some("duplicate.docx"),
                vec!["another value named 2 already occupies its MRUListEx position".to_owned()]
            ),
            (
                None,
                3,
                Some("c.pdf"),
                vec![
                    "MRUListEx doesn't list it".to_owned(),
                    "is REG_SZ, not REG_BINARY".to_owned()
                ]
            ),
        ]
    );
    // the bytes of what doesn't decode are kept
    assert!(all.items[4].raw.is_some() && all.items[0].raw.is_none());
    let txt = &lists[1];
    assert_eq!(txt.extension.as_deref(), Some(".txt"));
    assert_eq!(
        txt.problems,
        ["it has no MRUListEx: its items' order is unknown"]
    );
    assert_eq!(txt.items[0].mru_position, None);
}

/// Bytes from hex.
fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// `Actions` and `DynamicInfo` of two tasks of the DFIR Artifact Museum's Windows 11 `SOFTWARE`
/// hive (MIT): `Time Synchronization\SynchronizeTime` (exec) and `WDI\ResolutionHost` (COM).
const SYNC_ACTIONS: &str = "0300180000004c006f00630061006c005300650072007600690063006500666600000000300000002500770069006e0064006900720025005c00730079007300740065006d00330032005c00730063002e0065007800650034000000730074006100720074002000770033003200740069006d00650020007400610073006b005f007300740061007200740065006400000000000000";
const SYNC_DYNAMIC: &str =
    "0300000042bed253da1ad801d6e9726c8d20d8010000000020040000573f4d6f8d20d801";
const WDI_ACTIONS: &str =
    "03000a000000550073006500720073007777000000009de30b90e86b1a46bc4db0fa71f5ecb100000000";

#[test]
#[allow(clippy::too_many_lines)]
fn a_task_cache() {
    let sync_guid = "{CC75EC31-F3E4-4F10-8279-0ECC1C1C37CD}";
    let wdi_guid = "{65BDF6F5-C21D-48A0-B348-55233C383652}";
    let gone_guid = "{8C1BA5F6-61DE-43AE-A3F2-37AA03E817CD}";
    let orphan_guid = "{11111111-2222-3333-4444-555555555555}";
    let mut b = Builder::new();
    // Tree: a task, a task without its SD (hidden), an Index 0 task without a Tasks key
    let tree_task =
        |b: &mut Builder, name: &str, guid: &str, index: u32, sd: bool, duplicate_id: bool| {
            let mut values = vec![
                b.value("Id", 1, &utf16z(guid), false),
                b.value("Index", 4, &index.to_le_bytes(), false),
            ];
            if duplicate_id {
                values.push(b.value("ID", 1, &utf16z(orphan_guid), false));
            }
            if sd {
                values.push(b.value("SD", 3, &[1, 0, 4, 0x80, 0, 0, 0, 0], false));
            }
            b.key(name, 0, &[], &values, false)
        };
    let sync = tree_task(&mut b, "SynchronizeTime", sync_guid, 3, true, false);
    let time = b.key("Time Synchronization", 0, &[sync], &[], false);
    let wdi = tree_task(&mut b, "ResolutionHost", wdi_guid, 2, false, false);
    let wdi = b.key("WDI", 0, &[wdi], &[], false);
    let gone = tree_task(&mut b, "ScheduledDefrag", gone_guid, 0, true, true);
    let defrag = b.key("Defrag", 0, &[gone], &[], false);
    let windows = b.key("Windows", 0, &[defrag, time, wdi], &[], false);
    let microsoft = b.key("Microsoft", 0, &[windows], &[], false);
    let tree = b.key("Tree", 0, &[microsoft], &[], false);
    // Tasks: the two tasks' keys, the second's Path not its Tree name, and a key no Tree entry
    // names, its Actions cut short
    let task = |b: &mut Builder,
                guid: &str,
                path: &str,
                actions: &[u8],
                actions_type: u32,
                dynamic: Option<(u32, &[u8])>,
                duplicate_actions: Option<&[u8]>| {
        let mut values = vec![
            b.value("Path", 1, &utf16z(path), false),
            b.value("URI", 1, &utf16z(path), false),
            b.value("Actions", actions_type, actions, false),
        ];
        if let Some((value_type, d)) = dynamic {
            values.push(b.value("DynamicInfo", value_type, d, false));
        }
        if let Some(duplicate) = duplicate_actions {
            values.push(b.value("ACTIONS", 3, duplicate, false));
        }
        b.key(guid, 0, &[], &values, false)
    };
    let sync_task = task(
        &mut b,
        sync_guid,
        r"\Microsoft\Windows\Time Synchronization\SynchronizeTime",
        &unhex(SYNC_ACTIONS),
        3,
        Some((3, &unhex(SYNC_DYNAMIC))),
        None,
    );
    let wdi_task = task(
        &mut b,
        wdi_guid,
        r"\Microsoft\Windows\WDI\Renamed",
        &unhex(WDI_ACTIONS),
        3,
        Some((1, &[0; 20])),
        None,
    );
    let cut = &unhex(SYNC_ACTIONS)[..60];
    let orphan = task(
        &mut b,
        orphan_guid,
        r"\Hidden\Orphan",
        cut,
        1,
        None,
        Some(&unhex(SYNC_ACTIONS)),
    );
    let tasks = b.key("Tasks", 0, &[sync_task, wdi_task, orphan], &[], false);
    let in_list = |b: &mut Builder, list: &str, guids: &[&str]| {
        let keys: Vec<u32> = guids.iter().map(|g| b.key(g, 0, &[], &[], false)).collect();
        b.key(list, 0, &keys, &[], false)
    };
    let plain = in_list(&mut b, "Plain", &[sync_guid]);
    let logon = in_list(&mut b, "Logon", &[wdi_guid]);
    let maintenance = in_list(&mut b, "Maintenance", &[sync_guid]);
    let mut key = b.key(
        "TaskCache",
        0,
        &[tree, tasks, plain, logon, maintenance],
        &[],
        false,
    );
    for name in ["Schedule", "CurrentVersion", "Windows NT", "Microsoft"] {
        key = b.key(name, 0, &[key], &[], false);
    }
    let root = b.root(&[key]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();

    let (found, problems) = task_cache(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let names: Vec<&str> = found.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        [
            r"\Microsoft\Windows\Defrag\ScheduledDefrag",
            r"\Microsoft\Windows\Time Synchronization\SynchronizeTime",
            r"\Microsoft\Windows\WDI\ResolutionHost",
            r"\Hidden\Orphan",
        ]
    );
    // an Index 0 entry without a Tasks key
    let gone = &found[0];
    assert_eq!(
        (gone.index, gone.in_tree, gone.in_tasks),
        (Some(0), true, false)
    );
    assert!(gone.actions.is_none());
    assert_eq!(gone.problems, [r#"value "Id" is present more than once"#]);

    let sync = &found[1];
    assert_eq!(sync.guid.as_deref(), Some(sync_guid));
    assert_eq!(sync.index, Some(3));
    assert_eq!(sync.lists, ["Plain", "Maintenance"]);
    assert_eq!(sync.has_security_descriptor, Some(true));
    assert_eq!(
        (sync.tree_last_written, sync.task_last_written),
        (Some(WHEN), Some(WHEN))
    );
    let actions = sync.actions.as_ref().unwrap();
    assert_eq!(
        (actions.version, actions.context.as_deref()),
        (3, Some("LocalService"))
    );
    assert_eq!(
        actions.actions,
        [TaskAction::Exec {
            id: String::new(),
            command: r"%windir%\system32\sc.exe".into(),
            arguments: "start w32time task_started".into(),
            working_directory: String::new(),
        }]
    );
    let dynamic = sync.dynamic_info.unwrap();
    assert_eq!(dynamic.last_registered, 132_885_714_018_942_530);
    assert_eq!(dynamic.last_run, 132_891_980_789_377_494);
    assert_eq!(dynamic.last_result, 0x420);
    assert_eq!(dynamic.last_successful_run, Some(132_891_980_837_240_663));
    assert_eq!(sync.problems, Vec::<String>::new());

    // no SD: the Task Scheduler doesn't show it; its Path is not its Tree name
    let wdi = &found[2];
    assert_eq!(wdi.has_security_descriptor, Some(false));
    assert_eq!(wdi.lists, ["Logon"]);
    assert_eq!(
        wdi.actions.as_ref().unwrap().actions,
        [TaskAction::ComHandler {
            id: String::new(),
            class_id: "{900BE39D-6BE8-461A-BC4D-B0FA71F5ECB1}".into(),
            data: String::new(),
        }]
    );
    assert_eq!(
        wdi.problems,
        [
            "DynamicInfo: is REG_SZ, not REG_BINARY",
            "DynamicInfo: DynamicInfo of 20 bytes, not 28 or 36",
            r"its Tasks key's Path is \Microsoft\Windows\WDI\Renamed, not its Tree name",
        ]
    );
    // a Tasks key no Tree entry names: named by its Path; its cut Actions kept
    let orphan = &found[3];
    assert_eq!((orphan.in_tree, orphan.in_tasks), (false, true));
    assert_eq!(orphan.has_security_descriptor, None);
    assert_eq!(orphan.guid.as_deref(), Some(orphan_guid));
    assert_eq!(
        orphan.problems,
        [
            "Actions: is REG_SZ, not REG_BINARY",
            "Actions: a string of 48 bytes at 36 is cut short (20 bytes left)",
            r#"value "ACTIONS" is present more than once"#,
        ]
    );
    assert_eq!(orphan.actions_raw.as_deref(), Some(cut));
}

/// A SAM account's `F`: its last logon, RID and flags.
fn sam_f(last_logon: u64, rid: u32, flags: u16) -> Vec<u8> {
    let mut f = vec![0u8; 80];
    f[0x08..0x10].copy_from_slice(&last_logon.to_le_bytes());
    f[0x30..0x34].copy_from_slice(&rid.to_le_bytes());
    f[0x38..0x3A].copy_from_slice(&flags.to_le_bytes());
    f
}

/// A SAM account's `V` with its user name.
fn sam_v(name: &str) -> Vec<u8> {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut v = vec![0u8; 0xCC];
    v[12..16].copy_from_slice(&0u32.to_le_bytes());
    v[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
    v.extend(name);
    v
}

#[test]
fn sam_accounts_that_dont_add_up() {
    let mut b = Builder::new();
    let hint: Vec<u8> = "the usual"
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let mail: Vec<u8> = "alice@example.com"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    // alice: a hint, a Microsoft account, hidden from the sign-in screen
    let alice_values = [
        b.value("F", 3, &sam_f(WHEN, 1001, 0x10), false),
        b.value("V", 3, &sam_v("alice"), false),
        b.value("UserPasswordHint", 3, &hint, false),
        b.value("InternetUserName", 3, &mail, false),
        b.value("UserDontShowInLogonUI", 3, &1u32.to_le_bytes(), false),
    ];
    let alice = b.key("000003E9", 0, &[], &alice_values, false);
    // bob: F has the wrong type and says another RID, Names another name; carol: V cut short
    let bob_values = [
        b.value("F", 1, &sam_f(0, 2000, 0x10), false),
        b.value("V", 3, &sam_v("bob"), false),
        b.value("UserPasswordHint", 3, b"a", false),
        b.value("UserDontShowInLogonUI", 3, &[1, 0], false),
    ];
    let bob = b.key("000003EA", 0, &[], &bob_values, false);
    let mut short = sam_v("carol");
    short.truncate(0xCC + 4);
    let carol_values = [
        b.value("F", 3, &sam_f(0, 1003, 0x11), false),
        b.value("V", 3, &short, false),
    ];
    let carol = b.key("000003EB", 0, &[], &carol_values, false);
    // eve: an account key whose F and V are missing
    let eve = b.key("000003ED", 0, &[], &[], false);
    // Names: alice's, "robert" for bob's RID, carol's, eve's, and dave's without a Users key
    let name = |b: &mut Builder, name: &str, rid: u32| {
        let default = [b.value("", rid, &[], false)];
        b.key(name, 0, &[], &default, false)
    };
    let names = [
        name(&mut b, "alice", 1001),
        name(&mut b, "carol", 1003),
        name(&mut b, "dave", 1004),
        name(&mut b, "eve", 1005),
        name(&mut b, "robert", 1002),
    ];
    let names = b.key("Names", 0, &names, &[], false);
    let mut key = b.key("Users", 0, &[alice, bob, carol, eve, names], &[], false);
    for name in ["Account", "Domains", "SAM"] {
        key = b.key(name, 0, &[key], &[], false);
    }
    let root = b.root(&[key]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();

    let (found, problems) = accounts(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let alice = &found[0];
    assert_eq!(
        (alice.rid, alice.username.as_deref()),
        (Some(1001), Some("alice"))
    );
    assert_eq!(alice.password_hint.as_deref(), Some("the usual"));
    assert_eq!(
        alice.internet_user_name.as_deref(),
        Some("alice@example.com")
    );
    assert_eq!(alice.hidden_from_logon_ui, Some(true));
    assert_eq!(alice.f.unwrap().last_logon, WHEN);
    assert_eq!(alice.problems, Vec::<String>::new());
    let bob = &found[1];
    assert_eq!(
        bob.problems,
        [
            "F: is REG_SZ, not REG_BINARY",
            "F's RID is 2000, not its key's",
            "UserPasswordHint: is not valid UTF-16: decoded lossily",
            "UserDontShowInLogonUI: is 2 bytes, not 4",
            "its Names entry is robert, not its user name"
        ]
    );
    assert_eq!(bob.hidden_from_logon_ui, None);
    let carol = &found[2];
    assert_eq!(carol.username, Some("carol".into()));
    assert_eq!(
        carol.problems,
        ["V: its user name of 10 bytes at 0 is past its end"]
    );
    let eve = &found[3];
    assert_eq!(
        (eve.rid, eve.username.as_deref(), eve.f),
        (Some(1005), Some("eve"), None)
    );
    assert_eq!(eve.problems, ["F is not there", "V is not there"]);
    // a Names entry without its Users key
    let dave = &found[4];
    assert_eq!(
        (dave.rid, dave.username.as_deref(), dave.key_name.as_deref()),
        (Some(1004), Some("dave"), None)
    );
    assert_eq!(dave.problems, ["its Users key is not there"]);
}

#[test]
fn a_sam_without_its_names_key_keeps_the_accounts() {
    let mut b = Builder::new();
    let values = [
        b.value("F", 3, &sam_f(0, 1001, 0x10), false),
        b.value("V", 3, &sam_v("alice"), false),
    ];
    let alice = b.key("000003E9", 0, &[], &values, false);
    let mut key = b.key("Users", 0, &[alice], &[], false);
    for name in ["Account", "Domains", "SAM"] {
        key = b.key(name, 0, &[key], &[], false);
    }
    let root = b.root(&[key]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();

    let (found, problems) = accounts(&hive).unwrap();
    assert_eq!(problems, ["the Names key is not there"]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].username.as_deref(), Some("alice"));
    assert_eq!(found[0].problems, Vec::<String>::new());
}

#[test]
fn recovered_records_said_complete_or_partial() {
    let mut b = Builder::new();
    // a value's data cell with a key record past the data (its slack); its parent set below
    let mut cell = b"data".to_vec();
    cell.resize(8, 0);
    cell.extend(nk("InSlack", 0, (0, NONE), (0, NONE), 0x20));
    let data = b.put(&cell, false);
    let blob = b.put(&vk("Blob", 3, 4, data), false);
    let keep = b.key("Keep", 0, &[], &[blob], false);
    let software = b.key("Software", 0, &[keep], &[], false);
    // a deleted key under a key in use, and one under it (its parent deleted too)
    let run = b.value("Run", 1, &utf16z(r"C:\evil.exe"), true);
    let gone = b.key("Gone", software, &[], &[run], true);
    b.key("Child", gone, &[], &[], true);
    // its parent lost; its value list in use again
    b.key("Orphan", 0x10, &[], &[], true);
    let reused = b.value("Reused", 4, &[1, 0, 0, 0], false);
    b.key("Reusing", software, &[], &[reused], true);
    let root = b.root(&[software]);
    let mut bytes = b.hive(root);
    let at = bytes.windows(7).position(|w| w == b"InSlack").unwrap() - 0x4c;
    bytes[at + 0x10..at + 0x14].copy_from_slice(&software.to_le_bytes());
    // a key record past the hive bins
    let mut remnant = vec![0u8; 8];
    remnant.extend(nk("PastTheBins", software, (0, NONE), (0, NONE), 0x20));
    bytes.extend(remnant);
    let hive = Hive::from_bytes(bytes).unwrap();
    assert!(hive.key(r"Software\Keep").is_some());

    let found = hive.recover();
    let keys: Vec<(&str, RecoveredStatus, Vec<Source>)> = found
        .keys
        .iter()
        .map(|k| (k.path.as_str(), k.status, k.sources.clone()))
        .collect();
    assert_eq!(
        keys,
        [
            (
                r"Software\Gone",
                RecoveredStatus::DeletedComplete,
                vec![Source::FreeCell]
            ),
            (
                r"Software\Gone\Child",
                RecoveredStatus::DeletedComplete,
                vec![Source::FreeCell]
            ),
            (
                r"[unknown]\Orphan",
                RecoveredStatus::DeletedPartial,
                vec![Source::FreeCell]
            ),
            (
                r"Software\Reusing",
                RecoveredStatus::DeletedPartial,
                vec![Source::FreeCell]
            ),
            (
                r"Software\InSlack",
                RecoveredStatus::DeletedComplete,
                vec![Source::CellSlack]
            ),
            (
                r"Software\PastTheBins",
                RecoveredStatus::DeletedComplete,
                vec![Source::RemnantData]
            ),
        ]
    );
    assert_eq!(
        found.keys[0].values[0].status,
        RecoveredStatus::DeletedComplete
    );
    assert_eq!(
        found.keys[3].problems,
        [format!("value 0x{reused:x} is in use again")]
    );
    assert_eq!(found.values, Vec::new());
    assert_eq!(Source::CellSlack.name(), "cell_slack");
    assert_eq!(RecoveredStatus::DeletedPartial.name(), "deleted_partial");
}

/// Keys and values by their paths, for hives of deep keys.
#[derive(Default)]
struct Tree {
    keys: Vec<(String, Tree)>,
    values: Vec<(String, u32, Vec<u8>)>,
}

impl Tree {
    /// The key at `path`, made when it isn't there.
    fn at(&mut self, path: &str) -> &mut Tree {
        let mut tree = self;
        for part in path.split('\\') {
            let i = if let Some(i) = tree.keys.iter().position(|(name, _)| name == part) {
                i
            } else {
                tree.keys.push((part.to_owned(), Tree::default()));
                tree.keys.len() - 1
            };
            tree = &mut tree.keys[i].1;
        }
        tree
    }

    /// Value `name` of the key at `path`.
    fn set(&mut self, path: &str, name: &str, kind: u32, data: &[u8]) -> &mut Self {
        self.at(path)
            .values
            .push((name.to_owned(), kind, data.to_vec()));
        self
    }

    /// A `REG_SZ` value.
    fn sz(&mut self, path: &str, name: &str, text: &str) -> &mut Self {
        self.set(path, name, 1, &utf16z(text))
    }

    /// A `REG_MULTI_SZ` value.
    fn multi(&mut self, path: &str, name: &str, items: &[&str]) -> &mut Self {
        let mut data: Vec<u8> = items.iter().flat_map(|i| utf16z(i)).collect();
        data.extend([0, 0]);
        self.set(path, name, 7, &data)
    }

    /// A `REG_DWORD` value.
    fn dword(&mut self, path: &str, name: &str, n: u32) -> &mut Self {
        self.set(path, name, 4, &n.to_le_bytes())
    }

    fn build(&self, b: &mut Builder, name: &str) -> u32 {
        let subkeys: Vec<u32> = self.keys.iter().map(|(n, t)| t.build(b, n)).collect();
        let values: Vec<u32> = self
            .values
            .iter()
            .map(|(n, kind, data)| b.value(n, *kind, data, false))
            .collect();
        b.key(name, 0, &subkeys, &values, false)
    }

    /// The hive, its root named `root`.
    fn hive(&self, root: &str) -> Hive {
        let mut b = Builder::new();
        let subkeys: Vec<u32> = self.keys.iter().map(|(n, t)| t.build(&mut b, n)).collect();
        let root = b.root_named(root, &subkeys);
        Hive::from_bytes(b.hive(root)).unwrap()
    }
}

/// `StartupApproved`'s 12 bytes: enabled, or disabled at `WHEN`.
fn approval(enabled: bool) -> Vec<u8> {
    let mut b = vec![0u8; 12];
    if enabled {
        b[0] = 2;
    } else {
        b[0] = 3;
        b[4..].copy_from_slice(&WHEN.to_le_bytes());
    }
    b
}

/// Each record as `mechanism key\value = data | image | arguments`, with what else is set.
fn lines(records: &[Autostart]) -> Vec<String> {
    records
        .iter()
        .map(|r| {
            let mut line = format!(
                r"{} {}\{} = {} | {} | {}",
                r.mechanism.name(),
                r.key_path,
                r.value_name,
                r.data.as_deref().unwrap_or("-"),
                r.image_path.as_deref().unwrap_or("-"),
                r.arguments.as_deref().unwrap_or("-"),
            );
            if let Some(enabled) = r.enabled {
                let _ = write!(line, " enabled={enabled}");
            }
            if let Some(at) = r.disabled_at {
                let _ = write!(line, " disabled_at={at}");
            }
            if let Some(o) = r.overrides_machine {
                let _ = write!(line, " overrides={o}");
            }
            if r.wow64 {
                line.push_str(" wow64");
            }
            if let Some(d) = &r.details {
                let _ = write!(line, " ({d})");
            }
            if r.data_raw.is_some() {
                line.push_str(" raw");
            }
            for p in &r.problems {
                let _ = write!(line, " [{p}]");
            }
            line
        })
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn software_autostarts() {
    let cv = r"Microsoft\Windows\CurrentVersion";
    let nt = r"Microsoft\Windows NT\CurrentVersion";
    let approved = format!(r"{cv}\Explorer\StartupApproved");
    let mut t = Tree::default();
    t.sz(
        &format!(r"{cv}\Run"),
        "Updater",
        r#""C:\Program Files\Up\up.exe" /bg"#,
    )
    .sz(&format!(r"{cv}\Run"), "Off", r"C:\Tools\off.exe")
    .sz(&format!(r"{cv}\Run"), "Empty", "")
    .set(&format!(r"{cv}\Run"), "Bytes", 3, &[0x41, 0x42])
    .sz(&format!(r"Wow6432Node\{cv}\Run"), "Tray", "tray.exe")
    .sz(
        &format!(r"{cv}\RunOnce\Setup"),
        "Once",
        r"C:\Tools\once.exe",
    )
    .sz(&format!(r"{cv}\RunOnceEx"), "Title", "Installing")
    .sz(&format!(r"{cv}\RunOnceEx\0001"), "", "Section")
    .sz(
        &format!(r"{cv}\RunOnceEx\0001"),
        "1",
        r"||C:\Tools\a.dll|Go",
    )
    .sz(
        &format!(r"{cv}\Policies\Explorer\Run"),
        "1",
        r"C:\Tools\policy.exe",
    )
    .set(&format!(r"{approved}\Run"), "Updater", 3, &approval(true))
    .set(&format!(r"{approved}\Run"), "off", 3, &approval(false))
    .set(&format!(r"{approved}\Run"), "Gone", 3, &approval(false))
    .set(&format!(r"{approved}\Run32"), "Tray", 3, &[3, 0])
    .set(
        &format!(r"{approved}\StartupFolder"),
        "notes.lnk",
        3,
        &approval(true),
    )
    .sz(
        &format!(r"{nt}\Winlogon"),
        "Userinit",
        r"C:\Windows\system32\userinit.exe,C:\Tools\evil.exe,",
    )
    .sz(&format!(r"{nt}\Winlogon"), "Shell", "explorer.exe")
    .sz(&format!(r"{nt}\Winlogon"), "Taskman", "")
    .sz(
        &format!(r"{nt}\Winlogon\Notify\pkg"),
        "DLLName",
        "notify.dll",
    )
    .sz(
        &format!(r"{nt}\Windows"),
        "AppInit_DLLs",
        "a.dll,b.dll c.dll",
    )
    .dword(&format!(r"{nt}\Windows"), "LoadAppInit_DLLs", 1)
    .sz(&format!(r"Wow6432Node\{nt}\Windows"), "AppInit_DLLs", "")
    .sz(
        &format!(r"{nt}\Image File Execution Options\sethc.exe"),
        "Debugger",
        r"C:\Windows\System32\cmd.exe",
    )
    .sz(
        &format!(r"{nt}\Image File Execution Options\notepad.exe"),
        "GlobalFlag",
        "0x200",
    )
    .dword(
        &format!(r"{nt}\Image File Execution Options\calc.exe"),
        "GlobalFlag",
        0x100,
    )
    .sz(
        &format!(r"{nt}\Image File Execution Options\calc.exe"),
        "VerifierDlls",
        "v1.dll v2.dll",
    )
    .dword(
        &format!(r"{nt}\Image File Execution Options\mspaint.exe"),
        "UseFilter",
        1,
    )
    .sz(
        &format!(r"{nt}\Image File Execution Options\mspaint.exe\one"),
        "FilterFullPath",
        r"C:\Apps\mspaint.exe",
    )
    .sz(
        &format!(r"{nt}\Image File Execution Options\mspaint.exe\one"),
        "Debugger",
        "dbg.exe",
    )
    .sz(
        &format!(r"{nt}\SilentProcessExit\notepad.exe"),
        "MonitorProcess",
        r"C:\Tools\monitor.exe -q",
    )
    .dword(
        &format!(r"{nt}\SilentProcessExit\notepad.exe"),
        "ReportingMode",
        1,
    )
    .sz(
        &format!(r"{nt}\SilentProcessExit\write.exe"),
        "MonitorProcess",
        r"C:\Tools\monitor.exe",
    )
    .sz(
        r"Microsoft\Active Setup\Installed Components\{0001}",
        "",
        "Component",
    )
    .sz(
        r"Microsoft\Active Setup\Installed Components\{0001}",
        "StubPath",
        r"C:\Tools\stub.exe /user",
    )
    .dword(
        r"Microsoft\Active Setup\Installed Components\{0001}",
        "IsInstalled",
        0,
    )
    .sz(
        r"Microsoft\Active Setup\Installed Components\{0002}",
        "StubPath",
        "U",
    )
    .sz(
        r"Microsoft\Active Setup\Installed Components\{0002}",
        "ShellComponent",
        "shell32.dll",
    )
    .sz(r"Microsoft\NetSh", "helper", "helper.dll")
    .sz(
        r"Microsoft\Command Processor",
        "AutoRun",
        r"C:\Tools\auto.bat",
    )
    .sz(
        r"Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1-2-3-1001",
        "ProfileImagePath",
        r"C:\Users\alice",
    );
    let hive = t.hive("ROOT");
    let (records, problems) = persistence::software(&hive);
    assert_eq!(problems, Vec::<String>::new());
    let ifeo = r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    let setup = r"Microsoft\Active Setup\Installed Components";
    assert_eq!(
        lines(&records),
        [
            format!(
                r#"run {cv}\Run\Updater = "C:\Program Files\Up\up.exe" /bg | C:\Program Files\Up\up.exe | /bg enabled=true"#
            ),
            format!(
                r"run {cv}\Run\Off = C:\Tools\off.exe | C:\Tools\off.exe | - enabled=false disabled_at={WHEN}"
            ),
            format!(r"run {cv}\Run\Bytes = - | - | - raw [is REG_BINARY, not a string]"),
            format!(r"run_once {cv}\RunOnce\Setup\Once = C:\Tools\once.exe | C:\Tools\once.exe | -"),
            format!(r"run_once_ex {cv}\RunOnceEx\0001\1 = ||C:\Tools\a.dll|Go | - | -"),
            format!(
                r"policies_run {cv}\Policies\Explorer\Run\1 = C:\Tools\policy.exe | C:\Tools\policy.exe | -"
            ),
            format!(
                r"run Wow6432Node\{cv}\Run\Tray = tray.exe | tray.exe | - wow64 [StartupApproved\Run32: 2 bytes, not 12]"
            ),
            format!(
                r"run {approved}\Run\Gone = - | - | - enabled=false disabled_at={WHEN} (only in StartupApproved: the Run key has no value of this name)"
            ),
            format!(
                r"startup_folder {approved}\StartupFolder\notes.lnk = - | - | - enabled=true (a file in the Startup folder)"
            ),
            format!(r"winlogon {nt}\Winlogon\Shell = explorer.exe | explorer.exe | -"),
            format!(
                r"winlogon {nt}\Winlogon\Userinit = C:\Windows\system32\userinit.exe | C:\Windows\system32\userinit.exe | - (one of the Userinit programs, comma-separated)"
            ),
            format!(
                r"winlogon {nt}\Winlogon\Userinit = C:\Tools\evil.exe | C:\Tools\evil.exe | - (one of the Userinit programs, comma-separated)"
            ),
            format!(r"winlogon_notify {nt}\Winlogon\Notify\pkg\DLLName = notify.dll | notify.dll | -"),
            format!(r"appinit_dlls {nt}\Windows\AppInit_DLLs = a.dll | a.dll | - enabled=true"),
            format!(r"appinit_dlls {nt}\Windows\AppInit_DLLs = b.dll | b.dll | - enabled=true"),
            format!(r"appinit_dlls {nt}\Windows\AppInit_DLLs = c.dll | c.dll | - enabled=true"),
            format!(
                r"ifeo_debugger {ifeo}\sethc.exe\Debugger = C:\Windows\System32\cmd.exe | C:\Windows\System32\cmd.exe | -"
            ),
            format!(r"ifeo_verifier_dlls {ifeo}\calc.exe\VerifierDlls = v1.dll | v1.dll | - enabled=true"),
            format!(r"ifeo_verifier_dlls {ifeo}\calc.exe\VerifierDlls = v2.dll | v2.dll | - enabled=true"),
            format!(
                r"ifeo_debugger {ifeo}\mspaint.exe\one\Debugger = dbg.exe | dbg.exe | - enabled=true (for C:\Apps\mspaint.exe (FilterFullPath))"
            ),
            format!(
                r"silent_process_exit {nt}\SilentProcessExit\notepad.exe\MonitorProcess = C:\Tools\monitor.exe -q | C:\Tools\monitor.exe | -q enabled=true (ReportingMode 1 (launch MonitorProcess))"
            ),
            format!(
                r"silent_process_exit {nt}\SilentProcessExit\write.exe\MonitorProcess = C:\Tools\monitor.exe | C:\Tools\monitor.exe | - enabled=false (ReportingMode 0)"
            ),
            format!(
                r"active_setup {setup}\{{0001}}\StubPath = C:\Tools\stub.exe /user | C:\Tools\stub.exe | /user enabled=false (Component)"
            ),
            format!(
                r"active_setup {setup}\{{0002}}\StubPath = U | shell32.dll | U (StubPath is ShellComponent's argument)"
            ),
            r"netsh_helper Microsoft\NetSh\helper = helper.dll | helper.dll | -".to_owned(),
            r"command_processor_autorun Microsoft\Command Processor\AutoRun = C:\Tools\auto.bat | C:\Tools\auto.bat | -".to_owned(),
        ]
    );
    assert!(
        records
            .iter()
            .all(|r| r.last_written == WHEN && !r.replayed)
    );
    assert_eq!(
        profile_list(&hive),
        [(
            "S-1-5-21-1-2-3-1001".to_owned(),
            r"C:\Users\alice".to_owned()
        )]
    );
    assert_eq!(Mechanism::Winlogon.attack_technique(), Some("T1547.004"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn system_autostarts() {
    let manager = r"ControlSet001\Control\Session Manager";
    let mut t = Tree::default();
    t.dword("Select", "Current", 1)
        .multi(
            manager,
            "BootExecute",
            &["autocheck autochk *", r"C:\Tools\native.exe"],
        )
        .multi(
            manager,
            "PendingFileRenameOperations",
            &[r"\??\C:\a.dll", r"!\??\C:\b.dll", r"\??\C:\c.tmp", ""],
        )
        .sz(&format!(r"{manager}\KnownDLLs"), "kernel32", "kernel32.dll")
        .sz(
            &format!(r"{manager}\KnownDLLs"),
            "DllDirectory",
            r"%SystemRoot%\system32",
        )
        .sz(
            &format!(r"{manager}\AppCertDlls"),
            "cert",
            r"C:\Tools\cert.dll",
        )
        .sz(&format!(r"{manager}\Environment"), "COR_PROFILER", "{0001}")
        .sz(
            &format!(r"{manager}\Environment"),
            "COR_PROFILER_PATH",
            r"C:\Tools\p.dll",
        )
        .sz(&format!(r"{manager}\Environment"), "Path", r"C:\Windows")
        .multi(
            r"ControlSet001\Control\Lsa",
            "Authentication Packages",
            &["msv1_0", "auth"],
        )
        .multi(
            r"ControlSet001\Control\Lsa",
            "Notification Packages",
            &["scecli"],
        )
        .multi(
            r"ControlSet001\Control\Lsa\OSConfig",
            "Security Packages",
            &["kerberos"],
        )
        .sz(
            r"ControlSet001\Control\SecurityProviders",
            "SecurityProviders",
            "credssp.dll, sp.dll",
        )
        .sz(
            r"ControlSet001\Control\Print\Monitors\Port",
            "Driver",
            "port.dll",
        )
        .sz(
            r"ControlSet001\Control\Print\Providers\Net",
            "Name",
            "net.dll",
        )
        .sz(
            r"ControlSet001\Control\Print\Environments\Windows x64\Print Processors\proc",
            "Driver",
            "proc.dll",
        )
        .sz(
            r"ControlSet001\Services\W32Time\TimeProviders\Ntp",
            "DllName",
            "w32time.dll",
        )
        .dword(
            r"ControlSet001\Services\W32Time\TimeProviders\Ntp",
            "Enabled",
            0,
        )
        .multi(
            r"ControlSet002\Control\Lsa",
            "Authentication Packages",
            &["other"],
        );
    let hive = t.hive("ROOT");
    let (records, problems) = persistence::system(&hive, 1);
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(
        lines(&records),
        [
            format!(r"boot_execute {manager}\BootExecute = autocheck autochk * | autocheck | autochk *"),
            format!(r"boot_execute {manager}\BootExecute = C:\Tools\native.exe | C:\Tools\native.exe | -"),
            format!(
                r"pending_file_rename {manager}\PendingFileRenameOperations = \??\C:\a.dll | \??\C:\a.dll | - (to be moved to !\??\C:\b.dll)"
            ),
            format!(
                r"pending_file_rename {manager}\PendingFileRenameOperations = \??\C:\c.tmp | \??\C:\c.tmp | - (to be deleted)"
            ),
            format!(r"known_dlls {manager}\KnownDLLs\kernel32 = kernel32.dll | kernel32.dll | -"),
            format!(r"appcert_dlls {manager}\AppCertDlls\cert = C:\Tools\cert.dll | C:\Tools\cert.dll | -"),
            format!(r"dotnet_profiler {manager}\Environment\COR_PROFILER = {{0001}} | - | -"),
            format!(
                r"dotnet_profiler {manager}\Environment\COR_PROFILER_PATH = C:\Tools\p.dll | C:\Tools\p.dll | -"
            ),
            r"lsa_authentication_package ControlSet001\Control\Lsa\Authentication Packages = msv1_0 | - | -".to_owned(),
            r"lsa_authentication_package ControlSet001\Control\Lsa\Authentication Packages = auth | - | -".to_owned(),
            r"lsa_notification_package ControlSet001\Control\Lsa\Notification Packages = scecli | - | -".to_owned(),
            r"lsa_security_package ControlSet001\Control\Lsa\OSConfig\Security Packages = kerberos | - | -".to_owned(),
            r"security_provider ControlSet001\Control\SecurityProviders\SecurityProviders = credssp.dll | credssp.dll | -".to_owned(),
            r"security_provider ControlSet001\Control\SecurityProviders\SecurityProviders = sp.dll | sp.dll | -".to_owned(),
            r"print_monitor ControlSet001\Control\Print\Monitors\Port\Driver = port.dll | port.dll | -".to_owned(),
            r"print_provider ControlSet001\Control\Print\Providers\Net\Name = net.dll | net.dll | -".to_owned(),
            r"print_processor ControlSet001\Control\Print\Environments\Windows x64\Print Processors\proc\Driver = proc.dll | proc.dll | -".to_owned(),
            r"time_provider ControlSet001\Services\W32Time\TimeProviders\Ntp\DllName = w32time.dll | w32time.dll | - enabled=false".to_owned(),
        ]
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn user_autostarts() {
    let mut machine = Tree::default();
    machine
        .sz(r"Classes\CLSID\{AAAA}", "", "Shell thing")
        .sz(r"Classes\Wow6432Node\CLSID\{CCCC}", "", "32-bit thing")
        .sz(r"Classes\exefile\shell\open\command", "", r#""%1" %*"#);
    let machine = MachineClasses::read(&machine.hive("ROOT"));

    let mut user = Tree::default();
    user.sz(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "Sync",
        r"C:\Users\alice\sync.exe /background",
    )
    .sz(
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "Load",
        r"C:\Tools\load.exe",
    )
    .sz(
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "Run",
        "",
    )
    .sz(
        "Environment",
        "UserInitMprLogonScript",
        r"C:\Tools\logon.bat",
    )
    .dword("Environment", "COR_ENABLE_PROFILING", 1)
    .sz(
        r"Control Panel\Desktop",
        "SCRNSAVE.EXE",
        r"C:\Tools\saver.scr",
    )
    .sz(r"Control Panel\Desktop", "ScreenSaveActive", "1")
    .sz(
        r"Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\App_1.0_x64__abc",
        "",
        r"C:\Tools\debugger.exe",
    )
    .sz(
        r"Software\Classes\ms-settings\shell\open\command",
        "",
        r"C:\Windows\System32\cmd.exe",
    )
    .sz(
        r"Software\Classes\ms-settings\shell\open\command",
        "DelegateExecute",
        "",
    );
    let (records, problems) = persistence::ntuser(&user.hive("ROOT"), Some(&machine));
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(
        lines(&records),
        [
            r"run Software\Microsoft\Windows\CurrentVersion\Run\Sync = C:\Users\alice\sync.exe /background | C:\Users\alice\sync.exe | /background",
            r"windows_load Software\Microsoft\Windows NT\CurrentVersion\Windows\Load = C:\Tools\load.exe | C:\Tools\load.exe | -",
            r"logon_script Environment\UserInitMprLogonScript = C:\Tools\logon.bat | C:\Tools\logon.bat | -",
            r"dotnet_profiler Environment\COR_ENABLE_PROFILING = 1 | - | -",
            r"appx_debugger Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\App_1.0_x64__abc\ = C:\Tools\debugger.exe | C:\Tools\debugger.exe | -",
            r"screensaver Control Panel\Desktop\SCRNSAVE.EXE = C:\Tools\saver.scr | C:\Tools\saver.scr | - enabled=true",
            r"uac_bypass_command Software\Classes\ms-settings\shell\open\command\ = C:\Windows\System32\cmd.exe | C:\Windows\System32\cmd.exe | - overrides=false (with a DelegateExecute value)",
        ]
    );

    let mut classes = Tree::default();
    classes
        .sz(r"CLSID\{AAAA}", "", "Hijacked")
        .sz(r"CLSID\{aaaa}\InprocServer32", "", r"C:\Users\alice\h.dll")
        .sz(
            r"CLSID\{BBBB}\LocalServer32",
            "",
            r#""C:\Users\alice\own.exe" -Embedding"#,
        )
        .sz(
            r"Wow6432Node\CLSID\{AAAA}\InprocServer32",
            "",
            r"C:\x86\h.dll",
        )
        .sz(
            r"Wow6432Node\CLSID\{CCCC}\InProcServer32",
            "",
            r"C:\x86\c.dll",
        )
        .sz(r"exefile\shell\open\command", "", r"C:\Tools\wrap.exe %1")
        .sz(
            r"ActivatableClasses\Package\App_1.0_x64__abc\DebugInformation\App.Class",
            "DebugPath",
            r"C:\Tools\appdebug.exe",
        );
    let hive = classes.hive("S-1-5-21-1-2-3-1001_Classes");
    assert_eq!(classes_sid(&hive).as_deref(), Some("S-1-5-21-1-2-3-1001"));
    let (records, problems) = persistence::usrclass(&hive, Some(&machine));
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(
        lines(&records),
        [
            r"com_server CLSID\{aaaa}\InprocServer32\ = C:\Users\alice\h.dll | C:\Users\alice\h.dll | - overrides=true",
            r#"com_server CLSID\{BBBB}\LocalServer32\ = "C:\Users\alice\own.exe" -Embedding | C:\Users\alice\own.exe | -Embedding overrides=false"#,
            r"com_server Wow6432Node\CLSID\{AAAA}\InprocServer32\ = C:\x86\h.dll | C:\x86\h.dll | - overrides=false wow64",
            r"com_server Wow6432Node\CLSID\{CCCC}\InProcServer32\ = C:\x86\c.dll | C:\x86\c.dll | - overrides=true wow64",
            r"file_association exefile\shell\open\command\ = C:\Tools\wrap.exe %1 | C:\Tools\wrap.exe | %1 overrides=true",
            r"appx_debugger ActivatableClasses\Package\App_1.0_x64__abc\DebugInformation\App.Class\DebugPath = C:\Tools\appdebug.exe | C:\Tools\appdebug.exe | -",
        ]
    );
    // without the machine's classes, nothing says what they override
    let (records, _) = persistence::usrclass(&hive, None);
    assert!(records.iter().all(|r| r.overrides_machine.is_none()));
    assert_eq!(classes_sid(&user.hive("ROOT")), None);
}

/// A `SilentProcessExit` record: its program, whether it is enabled, its details and problems.
type Row = (String, Option<bool>, Option<String>, Vec<String>);

#[test]
fn silent_process_exit_reporting_modes() {
    // MonitorProcess starts with GlobalFlag's 0x200 and ReportingMode's 0x1 only: 0x2 asks for a
    // dump, 0x4 for a notification
    let nt = r"Microsoft\Windows NT\CurrentVersion";
    let mut t = Tree::default();
    for (program, mode) in [
        ("m0.exe", Some(0)),
        ("m1.exe", Some(1)),
        ("m2.exe", Some(2)),
        ("m4.exe", Some(4)),
        ("m7.exe", Some(7)),
        ("none.exe", None),
        ("text.exe", None),
        ("unflagged.exe", Some(7)),
    ] {
        if program != "unflagged.exe" {
            t.dword(
                &format!(r"{nt}\Image File Execution Options\{program}"),
                "GlobalFlag",
                0x200,
            );
        }
        let key = format!(r"{nt}\SilentProcessExit\{program}");
        t.sz(&key, "MonitorProcess", r"C:\Tools\monitor.exe");
        if let Some(mode) = mode {
            t.dword(&key, "ReportingMode", mode);
        }
    }
    t.sz(
        &format!(r"{nt}\SilentProcessExit\text.exe"),
        "ReportingMode",
        "1",
    );
    let (records, problems) = persistence::software(&t.hive("ROOT"));
    assert_eq!(problems, Vec::<String>::new());
    let found: Vec<Row> = records
        .iter()
        .map(|r| {
            (
                r.key_path.rsplit('\\').next().unwrap().to_owned(),
                r.enabled,
                r.details.clone(),
                r.problems.clone(),
            )
        })
        .collect();
    let expected =
        |program: &str, enabled: Option<bool>, details: Option<&str>, problems: &[&str]| {
            (
                program.to_owned(),
                enabled,
                details.map(str::to_owned),
                problems.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>(),
            )
        };
    assert_eq!(
        found,
        [
            expected("m0.exe", Some(false), Some("ReportingMode 0"), &[]),
            expected(
                "m1.exe",
                Some(true),
                Some("ReportingMode 1 (launch MonitorProcess)"),
                &[]
            ),
            expected(
                "m2.exe",
                Some(false),
                Some("ReportingMode 2 (local dump)"),
                &[]
            ),
            expected(
                "m4.exe",
                Some(false),
                Some("ReportingMode 4 (notification)"),
                &[]
            ),
            expected(
                "m7.exe",
                Some(true),
                Some("ReportingMode 7 (launch MonitorProcess, local dump, notification)"),
                &[]
            ),
            expected("none.exe", Some(false), Some("ReportingMode 0"), &[]),
            // a mode that can't be read leaves it unknown
            expected(
                "text.exe",
                None,
                None,
                &["ReportingMode: is REG_SZ, not REG_DWORD"]
            ),
            expected(
                "unflagged.exe",
                Some(false),
                Some("ReportingMode 7 (launch MonitorProcess, local dump, notification)"),
                &[]
            ),
        ]
    );
}

/// `UserAssist` version 5 data: a run count, focus count and time, and the last run.
fn ua5(count: u32, focus: u32, focus_ms: u32, last_run: u64) -> Vec<u8> {
    let mut b = vec![0u8; 72];
    b[4..8].copy_from_slice(&count.to_le_bytes());
    b[8..12].copy_from_slice(&focus.to_le_bytes());
    b[12..16].copy_from_slice(&focus_ms.to_le_bytes());
    b[0x3c..0x44].copy_from_slice(&last_run.to_le_bytes());
    b
}

#[test]
#[allow(clippy::too_many_lines)]
fn user_assist_of_both_versions() {
    let ua = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    let programs = format!(r"{ua}\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}");
    let desktop = format!(r"{ua}\{{75048700-EF1F-11D0-9888-006097DEACF9}}");
    let other = format!(r"{ua}\{{0D6D4F41-2994-4BA0-8FEF-620E43CD2812}}");
    let mut v3 = vec![0u8; 16];
    v3[4..8].copy_from_slice(&8u32.to_le_bytes());
    v3[8..16].copy_from_slice(&WHEN.to_le_bytes());
    let mut t = Tree::default();
    t.dword(&programs, "Version", 5)
        .set(
            &format!(r"{programs}\Count"),
            &rot13(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe"),
            3,
            &ua5(4, 6, 61_000, WHEN),
        )
        .set(
            &format!(r"{programs}\Count"),
            &rot13("Microsoft.Windows.Explorer"),
            3,
            &ua5(0, 2, 900, 0),
        )
        .set(
            &format!(r"{programs}\Count"),
            &rot13("UEME_CTLSESSION"),
            3,
            &[0; 1612],
        )
        .set(
            &format!(r"{programs}\Count"),
            &rot13(r"C:\Tools\short.exe"),
            3,
            &[1, 2, 3],
        )
        .set(
            &format!(r"{programs}\Count"),
            &rot13(r"C:\Tools\old.exe"),
            3,
            &v3,
        )
        .dword(&desktop, "Version", 3)
        .set(
            &format!(r"{desktop}\Count"),
            &rot13(r"UEME_RUNPATH:C:\WINDOWS\system32\notepad.exe"),
            3,
            &v3,
        )
        .set(
            &format!(r"{desktop}\Count"),
            &rot13("UEME_CTLCUACount:ctor"),
            3,
            &[0; 16],
        )
        .set(
            &format!(r"{other}\Count"),
            &rot13(r"C:\Tools\x.exe"),
            3,
            &ua5(1, 1, 1, 0),
        )
        .dword(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackProgs",
            0,
        );
    let hive = t.hive("ROOT");
    let (entries, problems) = user_assist(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let found: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{} {} {} | {} | {:?} {:?} {:?} {:?} {:?} {:?} {}{:?}",
                e.kind,
                e.version.map_or_else(|| "-".to_owned(), |v| v.to_string()),
                e.name,
                e.path.as_deref().unwrap_or("-"),
                e.format,
                e.run_count,
                e.focus_count,
                e.focus_time_ms,
                e.last_run,
                e.session_id,
                if e.data_raw.is_some() { "raw " } else { "" },
                e.problems
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            format!(
                r"executable 5 {{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\cmd.exe | %windir%\system32\cmd.exe | Some(5) Some(4) Some(6) Some(61000) Some({WHEN}) Some(0) []"
            ),
            "executable 5 Microsoft.Windows.Explorer | - | Some(5) Some(0) Some(2) Some(900) None Some(0) []".to_owned(),
            r#"executable 5 C:\Tools\short.exe | C:\Tools\short.exe | None None None None None None raw ["3 bytes: neither 72 (version 5) nor 16 (version 3)"]"#.to_owned(),
            format!(
                r#"executable 5 C:\Tools\old.exe | C:\Tools\old.exe | Some(3) Some(3) None None Some({WHEN}) Some(0) raw ["16 bytes (version 3), but the key's Version is 5"]"#
            ),
            format!(
                r"active_desktop 3 UEME_RUNPATH:C:\WINDOWS\system32\notepad.exe | C:\WINDOWS\system32\notepad.exe | Some(3) Some(3) None None Some({WHEN}) Some(0) []"
            ),
            r"other - C:\Tools\x.exe | C:\Tools\x.exe | Some(5) Some(1) Some(1) Some(1) None Some(0) []".to_owned(),
        ]
    );
    assert!(
        entries
            .iter()
            .all(|e| e.last_written == WHEN && !e.replayed)
    );
    assert_eq!(
        entries[0].name_rot13,
        r"{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr"
    );
    let settings = user_assist_settings(&hive);
    assert_eq!(
        settings.tracking_off(),
        [r"Explorer\Advanced Start_TrackProgs is 0"]
    );
    // a hive without UserAssist
    assert!(user_assist(&Tree::default().hive("ROOT")).is_none());
}

#[test]
fn user_assist_names_without_rot13_and_times_out_of_range() {
    // NoEncrypt: every item says its name may not be ROT13; a last run past 9999 is no time, its
    // bytes kept
    let ua = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    let count = format!(r"{ua}\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\Count");
    let corrupt = ua5(1, 1, 1, u64::MAX);
    let mut t = Tree::default();
    t.set(&count, r"C:\Tools\payload.exe", 3, &ua5(2, 1, 10, WHEN))
        .set(&count, &rot13(r"C:\Tools\corrupt.exe"), 3, &corrupt)
        .dword(&format!(r"{ua}\Settings"), "NoEncrypt", 1);
    let (entries, problems) = user_assist(&t.hive("ROOT")).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let no_encrypt = r"UserAssist\Settings NoEncrypt is 1: a name written while it was set is not ROT13, and decodes wrongly";
    assert_eq!(entries[0].name, r"P:\Gbbyf\cnlybnq.rkr");
    assert_eq!(entries[0].problems, [no_encrypt]);
    // the data decodes: no bytes kept for it
    assert_eq!(
        (entries[0].last_run, &entries[0].data_raw),
        (Some(WHEN), &None)
    );
    assert_eq!(entries[1].last_run, None);
    assert_eq!(
        entries[1].problems,
        [
            "last run FILETIME 0xffffffffffffffff is past 9999",
            no_encrypt
        ]
    );
    assert_eq!(entries[1].data_raw.as_deref(), Some(&corrupt[..]));
    assert_eq!(entries[1].run_count, Some(1));
}

/// BAM's data: the time a program last ran, then 16 bytes Windows writes after it.
fn bam_data(when: u64) -> Vec<u8> {
    let mut data = when.to_le_bytes().to_vec();
    data.extend([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]);
    data
}

#[test]
#[allow(clippy::too_many_lines)]
fn bam_and_dam_keys_in_both_layouts() {
    let user = "S-1-5-21-1-2-3-1001";
    let new = format!(r"ControlSet001\Services\bam\State\UserSettings\{user}");
    let old = r"ControlSet001\Services\bam\UserSettings\S-1-5-18";
    let dam = format!(r"ControlSet001\Services\dam\State\UserSettings\{user}");
    let dam_old = format!(r"ControlSet001\Services\dam\UserSettings\{user}");
    let mut t = Tree::default();
    t.dword(&new, "Version", 1)
        .dword(&new, "SequenceNumber", 7)
        .set(
            &new,
            r"\Device\HarddiskVolume3\Windows\explorer.exe",
            3,
            &bam_data(WHEN),
        )
        .set(
            &new,
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
            3,
            &bam_data(WHEN + 1),
        )
        // damaged: fewer than 8 bytes, a string; their bytes kept, no time guessed
        .set(
            &new,
            r"\Device\HarddiskVolume3\Tools\short.exe",
            3,
            &[1, 2, 3],
        )
        .sz(&new, r"\Device\HarddiskVolume3\Tools\text.exe", "12345678")
        .set(
            old,
            r"\Device\HarddiskVolume2\Windows\System32\svchost.exe",
            3,
            &bam_data(WHEN + 2),
        )
        .set(
            &dam,
            r"\Device\HarddiskVolume3\Windows\notepad.exe",
            3,
            &bam_data(WHEN + 3),
        )
        .dword(&dam_old, "Version", 1)
        .dword("Select", "Current", 1);
    let hive = t.hive("ROOT");
    let (entries, problems) = bam(&hive, 1).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let got: Vec<(Moderator, &str, &str, Option<u64>)> = entries
        .iter()
        .map(|e| {
            (
                e.moderator,
                e.key_path.as_str(),
                e.program.as_str(),
                e.last_run,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                Moderator::Bam,
                new.as_str(),
                r"\Device\HarddiskVolume3\Windows\explorer.exe",
                Some(WHEN)
            ),
            (
                Moderator::Bam,
                new.as_str(),
                "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
                Some(WHEN + 1)
            ),
            (
                Moderator::Bam,
                new.as_str(),
                r"\Device\HarddiskVolume3\Tools\short.exe",
                None
            ),
            (
                Moderator::Bam,
                new.as_str(),
                r"\Device\HarddiskVolume3\Tools\text.exe",
                None
            ),
            (
                Moderator::Bam,
                old,
                r"\Device\HarddiskVolume2\Windows\System32\svchost.exe",
                Some(WHEN + 2)
            ),
            (
                Moderator::Dam,
                dam.as_str(),
                r"\Device\HarddiskVolume3\Windows\notepad.exe",
                Some(WHEN + 3)
            ),
        ]
    );
    assert_eq!(entries[0].user_sid, user);
    assert_eq!(entries[4].user_sid, "S-1-5-18");
    assert!(entries[0].key_last_written > 0 && !entries[0].replayed);
    assert_eq!(
        (
            entries[2].problems.as_slice(),
            entries[2].data_raw.as_deref()
        ),
        (
            &["3 data bytes, fewer than the 8 of a time it last ran".to_owned()][..],
            Some(&[1u8, 2, 3][..])
        )
    );
    assert_eq!(entries[3].problems, ["is REG_SZ, not REG_BINARY"]);
    assert_eq!(
        entries[3].data_raw.as_deref(),
        Some(&utf16z("12345678")[..])
    );
    assert!(entries[0].problems.is_empty() && entries[0].data_raw.is_none());
    // another control set without these keys; a hive without any
    assert!(bam(&hive, 2).is_none());
    assert!(bam(&Tree::default().hive("ROOT"), 1).is_none());
}

#[test]
fn machine_sid_from_the_end_of_account_v() {
    let path = r"SAM\Domains\Account";
    let sid = |subs: [u32; 4]| {
        let mut b = vec![1, 4, 0, 0, 0, 0, 0, 5];
        b.extend(subs.iter().flat_map(|s| s.to_le_bytes()));
        b
    };
    let mut v = vec![0xaa; 40];
    v.extend(sid([21, 1_760_460_187, 1_592_185_332, 161_725_925]));
    let mut t = Tree::default();
    t.set(path, "V", 3, &v);
    assert_eq!(
        machine_sid(&t.hive("ROOT")).as_deref(),
        Some("S-1-5-21-1760460187-1592185332-161725925")
    );
    // not a domain SID at the end, too short, no V
    for bad in [sid([32, 544, 0, 0]), vec![1, 4, 0, 0], Vec::new()] {
        let mut t = Tree::default();
        if bad.is_empty() {
            t.at(path);
        } else {
            t.set(path, "V", 3, &bad);
        }
        assert_eq!(machine_sid(&t.hive("ROOT")), None);
    }
}

/// A device property's FILETIME as Windows 8 and later write it (type `0xffff0010`).
fn devprop(t: &mut Tree, instance: &str, id: &str, time: u64) {
    t.set(
        &format!(r"{instance}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}\{id}"),
        "",
        0xffff_0010,
        &time.to_le_bytes(),
    );
}

/// `MountedDevices` data: a device path in UTF-16.
fn device_path(path: &str) -> Vec<u8> {
    path.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn usb_devices_with_their_times() {
    let stick = r"ControlSet001\Enum\USBSTOR\Disk&Ven_Acme&Prod_Stick&Rev_1.00\SER123&0";
    let old = r"ControlSet001\Enum\USBSTOR\CdRom&Ven_Old&Prod_Drive&Rev_2\7&1c2d3e4f&0";
    let bad = r"ControlSet001\Enum\USBSTOR\Disk&Ven_Bad&Prod_Times&Rev_1\BAD1&0";
    let mut t = Tree::default();
    t.sz(stick, "FriendlyName", "Acme Stick USB Device")
        .sz(
            stick,
            "ContainerID",
            "{11111111-2222-3333-4444-555555555555}",
        )
        .sz(
            stick,
            "Driver",
            r"{4d36e967-e325-11ce-bfc1-08002be10318}\0007",
        )
        .sz(stick, "Service", "disk");
    for (id, time) in [
        ("0064", WHEN + 4),
        ("0065", WHEN + 5),
        ("0066", WHEN + 6),
        ("0067", WHEN + 7),
    ] {
        devprop(&mut t, stick, id, time);
    }
    // Windows 7: Data (and Type) in 000000NN\00000000; only the install times
    for id in ["00000064", "00000065"] {
        let at =
            format!(r"{old}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}\{id}\00000000");
        t.dword(&at, "Type", 0x10)
            .set(&at, "Data", 3, &WHEN.to_le_bytes());
    }
    // damage: 4 bytes, a time past 9999, a property that isn't a time, a FriendlyName not a string
    t.set(
        &format!(r"{bad}\Properties\{{83da6326-97a6-4088-9453-a1923f573b29}}\0066"),
        "",
        0xffff_0010,
        &[1, 2, 3, 4],
    );
    devprop(&mut t, bad, "0067", u64::MAX);
    devprop(&mut t, bad, "0002", WHEN);
    t.dword(bad, "FriendlyName", 7);
    t.sz(
        r"ControlSet001\Enum\USB\VID_1234&PID_5678\SER123",
        "ContainerID",
        "{11111111-2222-3333-4444-555555555555}",
    )
    .sz(r"ControlSet001\Enum\USB\VID_1234&PID_5678&MI_00\6&abc&0&0000", "Service", "HidUsb")
    .sz(
        r"ControlSet001\Enum\SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_Acme&Prod_Stick&Rev_1.00#SER123&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
        "FriendlyName",
        "ACME_VOL",
    );
    let hive = t.hive("ROOT");
    let (devices, problems) = usb::devices(&hive, 1).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let lines: Vec<String> = devices
        .iter()
        .map(|d| {
            format!(
                "{} {:?} {:?}/{:?}/{:?}/{:?} {:?}:{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
                d.class.name(),
                d.reference.as_ref().map(|r| r.enumerator.as_str()),
                d.kind,
                d.vendor,
                d.product,
                d.revision,
                d.vid,
                d.pid,
                d.serial,
                d.friendly_name,
                d.driver_last_installed.map(|t| t - WHEN),
                d.device_first_install.map(|t| t - WHEN),
                d.last_arrival.map(|t| t - WHEN),
                d.last_removal.map(|t| t - WHEN),
                d.problems,
            )
        })
        .collect();
    assert_eq!(
        lines,
        [
            // in the order the keys were written
            r#"usbstor Some("USBSTOR") Some("Disk")/Some("Acme")/Some("Stick")/Some("1.00") None:None Some("SER123") Some("Acme Stick USB Device") Some(4) Some(5) Some(6) Some(7) []"#,
            r#"usbstor Some("USBSTOR") Some("CdRom")/Some("Old")/Some("Drive")/Some("2") None:None None None Some(0) Some(0) None None []"#,
            r#"usbstor Some("USBSTOR") Some("Disk")/Some("Bad")/Some("Times")/Some("1") None:None Some("BAD1") None None None None None ["FriendlyName: is REG_DWORD, not a string", "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066: type 0xffff0010 of 4 bytes, not a FILETIME (01020304)", "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067: FILETIME 0xffffffffffffffff is past 9999"]"#,
            r#"usb Some("USB") None/None/None/None Some("1234"):Some("5678") Some("SER123") None None None None None []"#,
            r#"usb Some("USB") None/None/None/None Some("1234"):Some("5678") None None None None None None []"#,
            r#"wpdbusenum Some("USBSTOR") Some("Disk")/Some("Acme")/Some("Stick")/Some("1.00") None:None Some("SER123") Some("ACME_VOL") None None None None []"#,
        ]
    );
    assert_eq!(
        devices[0].path,
        r"ControlSet001\Enum\USBSTOR\Disk&Ven_Acme&Prod_Stick&Rev_1.00\SER123&0"
    );
    assert!(
        devices
            .iter()
            .all(|d| d.last_written == WHEN && !d.replayed)
    );
    // no Enum in that control set
    assert!(usb::devices(&hive, 2).is_none());
}

#[test]
#[allow(clippy::too_many_lines)]
fn usb_history_joins_devices_volumes_names_and_users() {
    let stick = r"ControlSet001\Enum\USBSTOR\Disk&Ven_Acme&Prod_Stick&Rev_1.00\SER123&0";
    let stick_path = r"_??_USBSTOR#Disk&Ven_Acme&Prod_Stick&Rev_1.00#SER123&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    let gone_path = r"\??\USBSTOR#Disk&Ven_Gone&Prod_Drive&Rev_9#GONE77&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    let (vol_a, vol_b, vol_c, vol_d) = (
        "{aaaaaaaa-0000-0000-0000-000000000001}",
        "{bbbbbbbb-0000-0000-0000-000000000002}",
        "{cccccccc-0000-0000-0000-000000000003}",
        "{dddddddd-0000-0000-0000-000000000004}",
    );
    let mut mbr = 0x1234_5678_u32.to_le_bytes().to_vec();
    mbr.extend(1_048_576_u64.to_le_bytes());
    let mut gpt = b"DMIO:ID:".to_vec();
    gpt.extend([7u8; 16]);
    let mut system = Tree::default();
    system
        .sz(
            stick,
            "ContainerID",
            "{11111111-2222-3333-4444-555555555555}",
        )
        .sz(
            r"ControlSet001\Enum\USB\VID_1234&PID_5678\SER123",
            "ContainerID",
            "{11111111-2222-3333-4444-555555555555}",
        )
        .sz(
            &format!(r"ControlSet001\Enum\SWD\WPDBUSENUM\{stick_path}"),
            "FriendlyName",
            "ACME_VOL",
        )
        .set(
            "MountedDevices",
            &format!(r"\??\Volume{vol_a}"),
            3,
            &device_path(stick_path),
        )
        .set(
            "MountedDevices",
            r"\DosDevices\E:",
            3,
            &device_path(stick_path),
        )
        .set("MountedDevices", &format!(r"\??\Volume{vol_b}"), 3, &mbr)
        .set("MountedDevices", r"\DosDevices\C:", 3, &mbr)
        .set(
            "MountedDevices",
            &format!(r"\??\Volume{vol_c}"),
            3,
            &device_path(gone_path),
        )
        .set(
            "MountedDevices",
            "#{eeeeeeee-0000-0000-0000-000000000005}",
            3,
            &mbr,
        )
        // a GPT system volume's letter, without a volume GUID value
        .set("MountedDevices", r"\DosDevices\F:", 3, &gpt);
    let mut software = Tree::default();
    let pd = r"Microsoft\Windows Portable Devices\Devices";
    let emd = r"Microsoft\Windows NT\CurrentVersion\EMDMgmt";
    software
        .sz(
            &format!(r"{pd}\WPDBUSENUMROOT#UMB#2&37C186B&1&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_ACME&PROD_STICK&REV_1.00#SER123&0#"),
            "FriendlyName",
            r"E:\",
        )
        .sz(&format!(r"{pd}\USB#VID_0781&PID_7400#0781005B300304C7"), "FriendlyName", "Sansa m240")
        .dword(
            &format!(r"{emd}\{stick_path}ACME_VOL_305419896"),
            "CacheSizeInMB",
            0,
        )
        .dword(
            &format!(r"{emd}\{}GONE_42", gone_path.replace(r"\??\", "_??_")),
            "CacheSizeInMB",
            0,
        )
        .dword(&format!(r"{emd}\BW_Q___1893742278"), "CacheSizeInMB", 0);
    let mp2 = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2";
    let mut alice = Tree::default();
    alice
        .dword(&format!(r"{mp2}\{vol_a}"), "BaseClass", 0)
        .dword(&format!(r"{mp2}\{vol_d}"), "BaseClass", 0)
        .sz(
            &format!(r"{mp2}\##fileserver#share#docs"),
            "_LabelFromReg",
            "Docs",
        );
    let mut bob = Tree::default();
    bob.dword(&format!(r"{mp2}\{}", vol_a.to_uppercase()), "BaseClass", 0)
        .dword(&format!(r"{mp2}\{vol_d}"), "BaseClass", 0);

    let (system, software) = (system.hive("ROOT"), software.hive("ROOT"));
    let devices = usb::devices(&system, 1).unwrap().0;
    let mounted = usb::mounted_devices(&system).unwrap().0;
    let portable = usb::portable_devices(&software).unwrap().0;
    let boost = usb::ready_boost(&software).unwrap().0;
    let points = |t: &Tree| usb::mount_points(&t.hive("ROOT")).unwrap().0;
    let users = vec![
        ("alice".to_owned(), points(&alice)),
        ("bob".to_owned(), points(&bob)),
    ];
    assert_eq!(
        users[0]
            .1
            .iter()
            .find(|p| p.server.as_deref() == Some("fileserver"))
            .and_then(|p| p.share.as_deref().zip(p.label.as_deref())),
        Some((r"\share\docs", "Docs"))
    );
    assert_eq!(boost[2].volume_serial, Some(1_893_742_278));
    let history = usb::history(&usb::Sources {
        devices: &devices,
        mounted: &mounted,
        portable: &portable,
        ready_boost: &boost,
        users: &users,
    });
    let lines: Vec<String> = history
        .iter()
        .map(|h| {
            format!(
                "{} {} {:?} {:?} {} {:?} {:?} {:?} {:?} {:?}",
                h.device.as_ref().map_or("volume", |d| d.class.name()),
                h.named
                    .as_ref()
                    .map_or(String::new(), |r| format!("{}|{}", r.device, r.instance)),
                h.vid_pid,
                h.volume_guid,
                h.drive_letters.iter().collect::<String>(),
                h.volume_names,
                h.volume_serials,
                h.users.iter().map(|u| u.user.as_str()).collect::<Vec<_>>(),
                h.found_in,
                h.problems,
            )
        })
        .collect();
    assert_eq!(
        lines,
        [
            // the stick, its USB device's IDs (by container), its volume, letter, names, serial, users
            r#"usbstor  Some((Some("1234"), Some("5678"))) Some("{aaaaaaaa-0000-0000-0000-000000000001}") E ["ACME_VOL", "E:\\"] [305419896] ["alice", "bob"] ["Enum", "Windows Portable Devices", "EMDMgmt", "MountedDevices", "MountPoints2"] []"#,
            r#"usb  None None  [] [] [] ["Enum"] []"#,
            r#"wpdbusenum  None Some("{aaaaaaaa-0000-0000-0000-000000000001}") E ["E:\\", "ACME_VOL"] [305419896] ["alice", "bob"] ["Enum", "Windows Portable Devices", "EMDMgmt", "MountedDevices", "MountPoints2"] []"#,
            // C:, an internal disk's volume
            r#"volume  None Some("{bbbbbbbb-0000-0000-0000-000000000002}") C [] [] [] ["MountedDevices"] []"#,
            // a USB storage device whose Enum key is gone, known by its volume and ReadyBoost
            r#"volume Disk&Ven_Gone&Prod_Drive&Rev_9|GONE77&0 None Some("{cccccccc-0000-0000-0000-000000000003}")  ["GONE"] [42] [] ["EMDMgmt", "MountedDevices"] []"#,
            // F:, a drive letter without a volume GUID value
            r#"volume  None None F [] [] [] ["MountedDevices"] []"#,
            // a volume only users had
            r#"volume  None Some("{dddddddd-0000-0000-0000-000000000004}")  [] [] ["alice", "bob"] ["MountPoints2"] []"#,
            // a phone only SOFTWARE names, and a ReadyBoost device of no USB storage
            r#"volume VID_0781&PID_7400|0781005B300304C7 None None  ["Sansa m240"] [] [] ["Windows Portable Devices"] []"#,
            r#"volume  None None  ["BW_Q__"] [1893742278] [] ["EMDMgmt"] []"#,
        ]
    );
    // where each was found
    assert_eq!(
        history[0].keys,
        [
            format!("SYSTEM {stick}"),
            r"SYSTEM ControlSet001\Enum\USB\VID_1234&PID_5678\SER123".to_owned(),
            format!(r"SYSTEM ControlSet001\Enum\SWD\WPDBUSENUM\{stick_path}"),
            format!(
                r"SOFTWARE {pd}\WPDBUSENUMROOT#UMB#2&37C186B&1&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_ACME&PROD_STICK&REV_1.00#SER123&0#"
            ),
            format!(r"SOFTWARE {emd}\{stick_path}ACME_VOL_305419896"),
            format!(r"SYSTEM MountedDevices: \??\Volume{vol_a}"),
            r"SYSTEM MountedDevices: \DosDevices\E:".to_owned(),
            format!(r"NTUSER.DAT (alice) {mp2}\{vol_a}"),
            format!(r"NTUSER.DAT (bob) {mp2}\{}", vol_a.to_uppercase()),
        ]
    );
    assert_eq!(
        history[6].keys,
        [
            format!(r"NTUSER.DAT (alice) {mp2}\{vol_d}"),
            format!(r"NTUSER.DAT (bob) {mp2}\{vol_d}"),
        ]
    );
}

/// Each `BagMRU` item as `key: place, slot, data, problems`.
fn bag_lines(hive: &Hive) -> (Vec<String>, Vec<String>) {
    let (bags, problems) = shell_bags(hive).unwrap();
    let lines = bags
        .iter()
        .map(|b| {
            format!(
                "{} parent={:?} mru={:?} slot={:?} data={:?} own_key={} {:?}",
                b.key_path(),
                b.parent,
                b.mru_position,
                b.node_slot,
                b.data,
                b.last_written.is_some(),
                b.problems
            )
        })
        .collect();
    (lines, problems)
}

#[test]
fn shell_bags_follow_mru_order_down_each_tree() {
    const BAG: &str = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU";
    let mut t = Tree::default();
    // BagMRU: 1 then 0 then 3 (no such value); 2 isn't listed; 5 is a subkey without a value;
    // `x` is no item at all.
    t.set(BAG, "MRUListEx", 3, &mru(&[1, 0, 3]))
        .set(BAG, "0", 3, &[1, 0])
        .set(BAG, "1", 3, &[2, 0])
        .set(BAG, "2", 3, &[3, 0])
        .set(BAG, "NodeSlots", 3, &[2, 2]);
    t.dword(&format!(r"{BAG}\0"), "NodeSlot", 4)
        .set(&format!(r"{BAG}\0"), "MRUListEx", 3, &mru(&[0]))
        .set(&format!(r"{BAG}\0"), "0", 1, &utf16z("text"));
    t.sz(&format!(r"{BAG}\1"), "NodeSlot", "seven");
    t.dword(&format!(r"{BAG}\5"), "NodeSlot", 9);
    t.at(&format!(r"{BAG}\x"));
    // Windows XP's tree, in the same hive for the test.
    t.set(
        r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
        "MRUListEx",
        3,
        &mru(&[0]),
    )
    .set(
        r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
        "0",
        3,
        &[4, 0],
    );
    let hive = t.hive("ROOT");
    let (lines, problems) = bag_lines(&hive);
    assert_eq!(
        problems,
        [format!(r#"{BAG}: subkey "x" is not a numbered item"#)]
    );
    assert_eq!(
        lines,
        [
            format!(r#"{BAG}\1 parent=None mru=Some(0) slot=None data=Some([2, 0]) own_key=true ["NodeSlot: is REG_SZ of 12 bytes, not a REG_DWORD"]"#),
            format!(r"{BAG}\0 parent=None mru=Some(1) slot=Some(4) data=Some([1, 0]) own_key=true []"),
            format!(r#"{BAG}\0\0 parent=Some(1) mru=Some(0) slot=None data=Some([116, 0, 101, 0, 120, 0, 116, 0, 0, 0]) own_key=false ["is REG_SZ, not REG_BINARY"]"#),
            format!(r#"{BAG}\3 parent=None mru=Some(2) slot=None data=None own_key=false ["MRUListEx lists value 3, which is not there"]"#),
            format!(r#"{BAG}\2 parent=None mru=None slot=None data=Some([3, 0]) own_key=false ["MRUListEx doesn't list it"]"#),
            format!(r#"{BAG}\5 parent=None mru=None slot=Some(9) data=None own_key=true ["no value 5 in its parent key: its shell item is unknown"]"#),
            r"Software\Microsoft\Windows\ShellNoRoam\BagMRU\0 parent=None mru=Some(0) slot=None data=Some([4, 0]) own_key=false []".to_owned(),
        ]
    );
    let (bags, _) = shell_bags(&hive).unwrap();
    assert_eq!(bags[2].parent_key_path(), format!(r"{BAG}\0"));
    assert!(
        bags.iter()
            .all(|b| b.parent_last_written == WHEN && !b.replayed)
    );
    assert!(shell_bags(&Tree::default().hive("ROOT")).is_none());
}

#[test]
fn a_shell_bag_subkey_that_loops_back_is_read_once() {
    let mut b = Builder::new();
    // BagMRU\0\0's subkey list holds BagMRU\0: the walk would go round for ever.
    let item = b.value("0", 3, &[1, 0], false);
    let list = b.value("MRUListEx", 3, &mru(&[0]), false);
    let mid_item = b.value("0", 3, &[2, 0], false);
    let mid_list = b.value("MRUListEx", 3, &mru(&[0]), false);
    let mid_values = b.list(&[mid_list, mid_item], false);
    let inner_item = b.value("0", 3, &[3, 0], false);
    let inner_list = b.value("MRUListEx", 3, &mru(&[0]), false);
    let inner_values = b.list(&[inner_list, inner_item], false);
    let inner_subkeys = b.lf(&[0]);
    let inner = b.put(
        &nk("0", 0, (1, inner_subkeys), (2, inner_values), 0x20),
        false,
    );
    let zero_subkeys = b.lf(&[inner]);
    let zero = b.put(&nk("0", 0, (1, zero_subkeys), (2, mid_values), 0x20), false);
    let bag = b.key("BagMRU", 0, &[zero], &[list, item], false);
    let entry = inner_subkeys as usize + 8;
    b.bin[entry..entry + 4].copy_from_slice(&zero.to_le_bytes());
    let mut parent = bag;
    for name in ["Shell", "Windows", "Microsoft", "Software"] {
        parent = b.key(name, 0, &[parent], &[], false);
    }
    let root = b.root(&[parent]);
    let hive = Hive::from_bytes(b.hive(root)).unwrap();
    let (bags, problems) = shell_bags(&hive).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    let keys: Vec<String> = bags
        .iter()
        .map(ys_registry_parser::shellbags::ShellBag::key_path)
        .collect();
    assert_eq!(
        keys,
        [
            r"Software\Microsoft\Windows\Shell\BagMRU\0",
            r"Software\Microsoft\Windows\Shell\BagMRU\0\0",
            r"Software\Microsoft\Windows\Shell\BagMRU\0\0\0",
        ]
    );
    assert!(bags[..2].iter().all(|b| b.problems.is_empty()));
    assert_eq!(bags[2].data.as_deref(), Some(&[3, 0][..]));
    assert_eq!(
        bags[2].problems,
        [
            "its subkey is a key already read (the hive's subkey lists loop): the items under it are not read again"
        ]
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn mui_cache_in_each_form() {
    use ys_registry_parser::ntuser::{MUI_CACHE, MUI_CACHE_XP, MuiCacheEntry, mui_cache};
    let mut lossy = utf16z("Ac");
    lossy[2..4].copy_from_slice(&0xd800u16.to_le_bytes());
    let mut t = Tree::default();
    t.set(MUI_CACHE, "LangID", 3, &[9, 4])
        // Windows 8 and later: two values per program, joined in any case
        .sz(MUI_CACHE, r"C:\Tools\a.exe.FriendlyAppName", "A tool")
        .sz(MUI_CACHE, r"c:\tools\A.EXE.applicationcompany", "Acme")
        // Windows 7: the path alone; its friendly name is already given, so another entry
        .sz(MUI_CACHE, r"C:\Tools\a.exe", "A tool, older")
        .set(
            MUI_CACHE,
            r"%ProgramFiles%\x.exe.FriendlyAppName",
            2,
            &utf16z("Expanded"),
        )
        .sz(MUI_CACHE, "@shell32.dll,-22019", "Calculator")
        // damaged: not a string; not valid UTF-16
        .set(
            MUI_CACHE,
            r"C:\Tools\bin.exe.FriendlyAppName",
            3,
            &[1, 2, 3],
        )
        .set(MUI_CACHE, r"C:\Tools\bin.exe.ApplicationCompany", 1, &lossy);
    let cache = mui_cache(&t.hive("S-1-5-21-1-2-3-1001_Classes")).unwrap();
    assert_eq!((cache.resource_strings, cache.problems.len()), (1, 0));
    let entry = |path: &str, name: Option<&str>, company: Option<&str>| MuiCacheEntry {
        key_path: MUI_CACHE,
        key_last_written: WHEN,
        path: path.to_owned(),
        friendly_app_name: name.map(str::to_owned),
        application_company: company.map(str::to_owned),
        ..MuiCacheEntry::default()
    };
    let mut bin = entry(r"C:\Tools\bin.exe", None, Some("A\u{fffd}"));
    bin.friendly_app_name_raw = Some(vec![1, 2, 3]);
    bin.application_company_raw = Some(lossy.clone());
    bin.problems = vec![
        "FriendlyAppName: is REG_BINARY, not a string".to_owned(),
        "ApplicationCompany: is not valid UTF-16: decoded lossily".to_owned(),
    ];
    assert_eq!(
        cache.entries,
        [
            entry(r"C:\Tools\a.exe", Some("A tool"), Some("Acme")),
            entry(r"C:\Tools\a.exe", Some("A tool, older"), None),
            entry(r"%ProgramFiles%\x.exe", Some("Expanded"), None),
            bin,
        ]
    );

    // Windows XP: NTUSER.DAT's ShellNoRoam, with resource strings
    let mut t = Tree::default();
    t.set(MUI_CACHE_XP, "LangID", 3, &[9, 4])
        .sz(MUI_CACHE_XP, "@xpsp1res.dll,-11004", "Outlook Express")
        .sz(
            MUI_CACHE_XP,
            r"@C:\WINDOWS\system32\SHELL32.dll,-9216",
            "My Computer",
        )
        .sz(MUI_CACHE_XP, r"C:\WINDOWS\system32\notepad.exe", "Notepad");
    let cache = mui_cache(&t.hive("ROOT")).unwrap();
    assert_eq!(cache.resource_strings, 2);
    assert_eq!(
        cache.entries,
        [MuiCacheEntry {
            key_path: MUI_CACHE_XP,
            ..entry(r"C:\WINDOWS\system32\notepad.exe", Some("Notepad"), None)
        }]
    );

    // an empty key; no key
    let mut t = Tree::default();
    t.at(MUI_CACHE);
    assert_eq!(mui_cache(&t.hive("ROOT")).map(|c| c.entries.len()), Some(0));
    let mut t = Tree::default();
    t.dword(r"Software\Microsoft\Windows\ShellNoRoam", "x", 1);
    assert_eq!(mui_cache(&t.hive("ROOT")), None);
}

#[test]
fn mui_cache_does_not_join_distinct_unicode_paths() {
    use ys_registry_parser::ntuser::{MUI_CACHE, mui_cache};
    let mut tree = Tree::default();
    tree.sz(
        MUI_CACHE,
        r"C:\Tools\straße.exe.FriendlyAppName",
        "Street tool",
    )
    .sz(
        MUI_CACHE,
        r"C:\Tools\STRASSE.EXE.ApplicationCompany",
        "Another company",
    )
    .sz(MUI_CACHE, r"C:\Tools\café.exe.FriendlyAppName", "Cafe tool")
    .sz(
        MUI_CACHE,
        r"c:\tools\CAFÉ.EXE.ApplicationCompany",
        "Cafe company",
    );
    let cache = mui_cache(&tree.hive("ROOT")).unwrap();
    assert_eq!(cache.entries.len(), 3);
    assert_eq!(cache.entries[0].path, r"C:\Tools\straße.exe");
    assert_eq!(
        cache.entries[0].friendly_app_name.as_deref(),
        Some("Street tool")
    );
    assert_eq!(cache.entries[0].application_company, None);
    assert_eq!(cache.entries[1].path, r"C:\Tools\STRASSE.EXE");
    assert_eq!(cache.entries[1].friendly_app_name, None);
    assert_eq!(
        cache.entries[1].application_company.as_deref(),
        Some("Another company")
    );
    assert_eq!(
        cache.entries[2].friendly_app_name.as_deref(),
        Some("Cafe tool")
    );
    assert_eq!(
        cache.entries[2].application_company.as_deref(),
        Some("Cafe company")
    );
}

#[test]
fn value_lookup_does_not_expand_unicode_names() {
    let mut tree = Tree::default();
    tree.sz("Names", "straße", "first")
        .sz("Names", "STRASSE", "second")
        .sz("Names", "café", "third");
    let hive = tree.hive("ROOT");
    let names = hive.key("Names").unwrap();
    assert_eq!(names.value("STRASSE").unwrap().name(), "STRASSE");
    assert_eq!(names.value("straße").unwrap().name(), "straße");
    assert_eq!(names.value("CAFÉ").unwrap().name(), "café");
}

/// Each program as `source scope key | name version | date | location | source`, with what
/// else is set.
fn programs(records: &[Program]) -> Vec<String> {
    let text = |t: &Option<String>| t.clone().unwrap_or_else(|| "-".to_owned());
    records
        .iter()
        .map(|p| {
            let mut line = format!(
                "{} {} {} | {} {} | {} | {} | {}",
                p.source.name(),
                p.scope.name(),
                p.key_path.rsplit('\\').next().unwrap(),
                text(&p.name),
                text(&p.version),
                text(&p.install_date),
                text(&p.install_location),
                text(&p.install_source),
            );
            for (k, v) in &p.details {
                let _ = write!(line, " {k}={v}");
            }
            if let Some(a) = &p.architecture {
                let _ = write!(line, " arch={a}");
            }
            if let Some(sid) = &p.user_sid {
                let _ = write!(line, " sid={sid}");
            }
            for (name, _) in &p.data_raw {
                let _ = write!(line, " raw:{name}");
            }
            for problem in &p.problems {
                let _ = write!(line, " [{problem}]");
            }
            line
        })
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn installed_software_of_a_software_hive() {
    let cv = r"Microsoft\Windows\CurrentVersion";
    let msi = format!(r"{cv}\Uninstall\{{8E9D8F3C-6B7A-4D5C-3E2F-1A0B9C8D7E6F}}");
    let tool = format!(r"{cv}\Uninstall\Tool");
    let old = format!(r"Wow6432Node\{cv}\Uninstall\Old32");
    let product = r"Classes\Installer\Products\c3f8d9e8a7b6c5d4e3f2a1b0c9d8e7f6";
    let bad_product = r"Classes\Installer\Products\NotPacked";
    let store = format!(r"{cv}\Appx\AppxAllUserStore");
    let calc = "Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe";
    let user = "S-1-5-21-1-2-3-1001";
    let mut lossy = utf16z("Tool");
    lossy.splice(2..2, [0x00, 0xd8]);
    let mut t = Tree::default();
    t.sz(&msi, "DisplayName", "Agent")
        .sz(&msi, "DisplayVersion", "2.1.0")
        .sz(&msi, "Publisher", "Example Corp")
        .sz(&msi, "InstallDate", "20220208")
        .sz(&msi, "InstallLocation", r"C:\Program Files\Agent\")
        .sz(&msi, "InstallSource", r"C:\Users\alice\Downloads\")
        .sz(
            &msi,
            "UninstallString",
            "MsiExec.exe /X{8E9D8F3C-6B7A-4D5C-3E2F-1A0B9C8D7E6F}",
        )
        .dword(&msi, "EstimatedSize", 2048)
        .dword(&msi, "SystemComponent", 0)
        .dword(&msi, "WindowsInstaller", 1)
        .sz(&msi, "Inno Setup: User", "alice")
        // damaged or unusual: a date written otherwise, a size as text, an empty flag, a name
        // that isn't valid UTF-16
        .set(&tool, "DisplayName", 1, &lossy)
        .sz(&tool, "InstallDate", "2022-02-08")
        .sz(&tool, "EstimatedSize", "12")
        .sz(&tool, "SystemComponent", "")
        .sz(
            &tool,
            "QuietUninstallString",
            r#""C:\Tool\unins000.exe" /SILENT"#,
        )
        .sz(&tool, "InstallLocation", "")
        .sz(&old, "DisplayName", "Old 32-bit")
        .dword(&old, "SystemComponent", 1)
        .sz(product, "ProductName", "Agent")
        .dword(product, "Version", 0x0201_0000)
        .sz(product, "PackageCode", "1d5c3b2a4f6e8d7c9b0a1f2e3d4c5b6a")
        .sz(
            &format!(r"{product}\SourceList"),
            "PackageName",
            "agent.msi",
        )
        .sz(
            &format!(r"{product}\SourceList"),
            "LastUsedSource",
            r"n;1;C:\Users\alice\Downloads\",
        )
        .sz(bad_product, "ProductName", "Unpacked")
        .sz(
            &format!(r"{bad_product}\SourceList"),
            "LastUsedSource",
            r"C:\setup\",
        )
        .sz(
            &format!(r"{cv}\App Paths\tool.exe"),
            "",
            r"C:\Tool\tool.exe",
        )
        .sz(&format!(r"{cv}\App Paths\tool.exe"), "Path", r"C:\Tool")
        .sz(
            &format!(r"Wow6432Node\{cv}\App Paths\old.exe"),
            "",
            r"C:\Old\old.exe",
        )
        .sz(
            &format!(r"{store}\Applications\{calc}"),
            "Path",
            r"C:\Program Files\WindowsApps\x",
        )
        .at(&format!(r"{store}\Applications\NotAPackage"));
    t.at(&format!(
        r"{store}\InboxApplications\Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy"
    ));
    t.at(&format!(
        r"{store}\Deprovisioned\Microsoft.BingNews_8wekyb3d8bbwe"
    ));
    t.at(&format!(r"{store}\Config\Microsoft.BingNews_8wekyb3d8bbwe"));
    t.at(&format!(
        r"{store}\{user}\Tool.Package_1.0.0.0_arm64_en-us_abcdefghijkmn"
    ));
    t.at(&format!(r"{store}\EndOfLife\{user}\{calc}"));
    let hive = t.hive("ROOT");
    let (records, problems) = installed::software(&hive);
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(
        programs(&records),
        [
            r"uninstall machine {8E9D8F3C-6B7A-4D5C-3E2F-1A0B9C8D7E6F} | Agent 2.1.0 | 2022-02-08 | C:\Program Files\Agent\ | C:\Users\alice\Downloads\ Inno Setup: User=alice",
            "uninstall machine Tool | T\u{fffd}ool - | - | - | - raw:DisplayName raw:EstimatedSize [DisplayName: is not valid UTF-16: decoded lossily] [EstimatedSize: is REG_SZ, not REG_DWORD]",
            "uninstall machine Old32 | Old 32-bit - | - | - | - arch=x86",
            r"msi_product machine c3f8d9e8a7b6c5d4e3f2a1b0c9d8e7f6 | Agent 2.1.0 | - | - | C:\Users\alice\Downloads\ PackageCode={A2B3C5D1-E6F4-C7D8-B9A0-F1E2D3C4B5A6} PackageName=agent.msi",
            r#"msi_product machine NotPacked | Unpacked - | - | - | - [LastUsedSource: "C:\\setup\\" is not <type>;<index>;<source>]"#,
            r"app_path machine tool.exe | tool.exe - | - | C:\Tool | -",
            "app_path machine old.exe | old.exe - | - | - | - arch=x86",
            r"package machine Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe | Microsoft.WindowsCalculator 10.1906.55.0 | - | C:\Program Files\WindowsApps\x | - List=Applications PublisherId=8wekyb3d8bbwe arch=x64",
            r#"package machine NotAPackage | - - | - | - | - List=Applications ["NotAPackage" is not a package full name or family name]"#,
            "package machine Microsoft.Windows.Search_1.14.0.19041_neutral_neutral_cw5n1h2txyewy | Microsoft.Windows.Search 1.14.0.19041 | - | - | - List=InboxApplications ResourceId=neutral PublisherId=cw5n1h2txyewy arch=neutral",
            "package machine Microsoft.BingNews_8wekyb3d8bbwe | Microsoft.BingNews - | - | - | - List=Deprovisioned PublisherId=8wekyb3d8bbwe",
            "package user Tool.Package_1.0.0.0_arm64_en-us_abcdefghijkmn | Tool.Package 1.0.0.0 | - | - | - List=User ResourceId=en-us PublisherId=abcdefghijkmn arch=arm64 sid=S-1-5-21-1-2-3-1001",
            "package user Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe | Microsoft.WindowsCalculator 10.1906.55.0 | - | - | - List=EndOfLife PublisherId=8wekyb3d8bbwe arch=x64 sid=S-1-5-21-1-2-3-1001",
        ]
    );
    let agent = &records[0];
    assert_eq!(
        agent.product_code.as_deref(),
        Some("{8E9D8F3C-6B7A-4D5C-3E2F-1A0B9C8D7E6F}")
    );
    assert_eq!(
        (
            agent.publisher.as_deref(),
            agent.size_kb,
            agent.system_component,
            agent.windows_installer
        ),
        (Some("Example Corp"), Some(2048), Some(false), Some(true))
    );
    assert_eq!(agent.key_last_written, WHEN);
    assert_eq!(agent.key_path, msi);
    let tool = &records[1];
    assert_eq!(tool.install_date_raw.as_deref(), Some("2022-02-08"));
    assert_eq!(tool.data_raw[1].1, utf16z("12"));
    assert_eq!(tool.data_raw[0].1, lossy);
    assert_eq!(
        (tool.system_component, tool.install_location.as_deref()),
        (None, None)
    );
    assert_eq!(
        tool.quiet_uninstall_command.as_deref(),
        Some(r#""C:\Tool\unins000.exe" /SILENT"#)
    );
    assert!(records[2].wow64 && records[2].system_component == Some(true));
    assert_eq!(records[2].key_path, old);
    assert_eq!(
        records[3].product_code.as_deref(),
        Some("{8E9D8F3C-6B7A-4D5C-3E2F-1A0B9C8D7E6F}")
    );
    assert_eq!(records[4].product_code, None);
    assert_eq!(records[5].program.as_deref(), Some(r"C:\Tool\tool.exe"));
    assert!(records[6].wow64 && records[6].program.as_deref() == Some(r"C:\Old\old.exe"));
    assert!(records.iter().all(|p| !p.replayed));
    assert!(
        records
            .iter()
            .filter(|p| p.source == ProgramSource::Package)
            .all(|p| p.scope
                == if p.user_sid.is_some() {
                    Scope::User
                } else {
                    Scope::Machine
                })
    );
    // the same keys are a user's in NTUSER.DAT only under Software
    assert_eq!(installed::ntuser(&hive), (Vec::new(), Vec::new()));
}

#[test]
fn installed_software_of_an_ntuser_hive() {
    let cv = r"Software\Microsoft\Windows\CurrentVersion";
    let lxss = format!(r"{cv}\Lxss");
    let docker = format!(r"{lxss}\{{36E0AFE5-9CCD-424F-B8C5-F4437FF99040}}");
    let ubuntu = format!(r"{lxss}\{{70E495E1-D4D3-4B8D-BBE8-79FDC01E50EA}}");
    let mut t = Tree::default();
    t.sz(
        &format!(r"{cv}\Uninstall\Portable"),
        "DisplayName",
        "Portable",
    )
    .sz(
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Old",
        "DisplayName",
        "Old",
    )
    .sz(
        r"Software\Microsoft\Installer\Products\00005109110000000000000000F01FEC",
        "ProductName",
        "Office",
    )
    .sz(&format!(r"{cv}\App Paths\p.exe"), "", r"C:\Users\a\p.exe")
    .sz(
        &lxss,
        "DefaultDistribution",
        "{70e495e1-d4d3-4b8d-bbe8-79fdc01e50ea}",
    )
    .sz(&docker, "DistributionName", "docker-desktop")
    .dword(&docker, "Flags", 15)
    .dword(&docker, "Version", 2)
    .sz(
        &docker,
        "BasePath",
        r"\\?\C:\Users\a\AppData\Local\Docker\wsl\distro",
    )
    .sz(&ubuntu, "DistributionName", "Ubuntu")
    .dword(&ubuntu, "Flags", 7)
    .sz(&ubuntu, "DefaultUid", "1000")
    .at(&format!(r"{lxss}\AppxInstallerCache"));
    let (records, problems) = installed::ntuser(&t.hive("ROOT"));
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(
        programs(&records),
        [
            "uninstall user Portable | Portable - | - | - | -",
            "uninstall user Old | Old - | - | - | - arch=x86",
            "msi_product user 00005109110000000000000000F01FEC | Office - | - | - | -",
            "app_path user p.exe | p.exe - | - | - | -",
            r"wsl user {36E0AFE5-9CCD-424F-B8C5-F4437FF99040} | docker-desktop 2 | - | \\?\C:\Users\a\AppData\Local\Docker\wsl\distro | - Flags=0xf Version=2",
            "wsl user {70E495E1-D4D3-4B8D-BBE8-79FDC01E50EA} | Ubuntu 1 | - | - | - Flags=0x7 Default=true raw:DefaultUid [DefaultUid: is REG_SZ, not REG_DWORD]",
        ]
    );
    assert_eq!(
        records[2].product_code.as_deref(),
        Some("{90150000-0011-0000-0000-0000000FF1CE}")
    );
    assert!(records.iter().all(|p| p.scope == Scope::User));
    // without Flags, no WSL version
    let mut t = Tree::default();
    t.sz(&docker, "DistributionName", "x");
    let (records, _) = installed::ntuser(&t.hive("ROOT"));
    assert_eq!((records.len(), records[0].version.as_deref()), (1, None));
}

#[test]
fn installed_malformed_empty_values_keep_diagnostics_and_bytes() {
    let root = r"Microsoft\Windows\CurrentVersion\Uninstall";
    let bad = format!(r"{root}\Broken");
    let clean = format!(r"{root}\Clean");
    let mut tree = Tree::default();
    tree.set(&bad, "EstimatedSize", 4, &[])
        .set(&bad, "WindowsInstaller", 4, &[1, 2])
        .set(&bad, "SystemComponent", 1, &[0])
        .set(&bad, "Publisher", 3, &[])
        .dword(&clean, "EstimatedSize", 0)
        .sz(&clean, "SystemComponent", "");
    let (records, problems) = installed::software(&tree.hive("ROOT"));
    assert_eq!(problems, Vec::<String>::new());
    let broken = records.iter().find(|r| r.key_path == bad).unwrap();
    assert_eq!(broken.problems.len(), 4, "{:?}", broken.problems);
    for field in [
        "EstimatedSize",
        "WindowsInstaller",
        "SystemComponent",
        "Publisher",
    ] {
        assert!(
            broken
                .problems
                .iter()
                .any(|problem| problem.starts_with(field)),
            "{field}"
        );
        assert!(
            broken.data_raw.iter().any(|(name, _)| name == field),
            "{field}"
        );
    }
    assert_eq!(
        broken
            .data_raw
            .iter()
            .find(|(name, _)| name == "Publisher")
            .unwrap()
            .1,
        Vec::<u8>::new()
    );
    let clean = records.iter().find(|r| r.key_path == clean).unwrap();
    assert_eq!(clean.size_kb, Some(0));
    assert!(
        clean.system_component.is_none() && clean.problems.is_empty() && clean.data_raw.is_empty()
    );
}

#[test]
fn installed_package_names_require_four_bounded_version_components() {
    assert!(installed::package_name("Example.App_0.65535.1.0_x64__8wekyb3d8bbwe").is_some());
    assert!(installed::package_name("Example.App_8wekyb3d8bbwe").is_some());
    for version in [
        "1.2",
        "1.2.3.4.5",
        "1..3.4",
        "...",
        "65536.0.0.0",
        "1.2.3.65536",
    ] {
        let full = format!("Example.App_{version}_x64__8wekyb3d8bbwe");
        assert!(installed::package_name(&full).is_none(), "{full}");
    }
}

#[test]
fn installed_wsl_parent_default_damage_is_retained() {
    let lxss = r"Software\Microsoft\Windows\CurrentVersion\Lxss";
    let distribution = format!(r"{lxss}\{{17A1BA00-E5D7-44BA-AF5F-194A2677FBB6}}");
    let mut tree = Tree::default();
    tree.set(lxss, "DefaultDistribution", 3, &[1, 2, 3])
        .sz(&distribution, "DistributionName", "Example")
        .dword(&distribution, "Flags", 0x0f);
    let (records, problems) = installed::ntuser(&tree.hive("ROOT"));
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(records.len(), 1);
    assert!(
        records[0]
            .problems
            .iter()
            .any(|problem| problem.starts_with("DefaultDistribution:"))
    );
    assert_eq!(
        records[0].data_raw,
        [("DefaultDistribution".to_string(), vec![1, 2, 3])]
    );
    assert!(!records[0].details.iter().any(|(name, _)| name == "Default"));
}

/// A shell item list: each item's bytes after its size, ended by a size of 0.
fn shell_items(items: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend((item.len() as u16 + 2).to_le_bytes());
        out.extend(*item);
    }
    out.extend([0, 0]);
    out
}

/// UTF-16 strings, each with its NUL, one after the other.
fn strings(texts: &[&str]) -> Vec<u8> {
    texts.iter().flat_map(|t| utf16z(t)).collect()
}

/// An entry's list, extension, place, value, program, path and problems.
type Dialog<'a> = (
    &'static str,
    Option<&'a str>,
    Option<u32>,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Vec<String>,
);

#[test]
#[allow(clippy::too_many_lines)]
fn common_dialog_lists_of_each_layout() {
    use ys_registry_parser::comdlg32::{COMDLG32, dialogs};
    let at = |list: &str| format!(r"{COMDLG32}\{list}");
    // This PC, then a file entry
    let file = shell_items(&[
        b"\x1f\x50\xe0\x4f\xd0\x20\xea\x3a\x69\x10\xa2\xd8\x08\x00\x2b\x30\x30\x9d",
        b"\x32\x00report.docx\x00",
    ]);
    let mut cut = file.clone();
    cut.truncate(25);
    let mut trailing = file.clone();
    trailing.extend([0, 0, 7]);
    let program_and = |program: &str, items: &[u8]| {
        let mut b = utf16z(program);
        b.extend(items);
        b
    };
    let mut cid_size = utf16z("app.exe");
    cid_size.resize(0x208, 0);
    cid_size.extend([1, 2, 3, 4]);
    let all = at(r"OpenSavePidlMRU\*");
    let docx = at(r"OpenSavePidlMRU\docx");
    let xp = at("OpenSaveMRU");
    let mut t = Tree::default();
    t.at(&at("OpenSavePidlMRU"));
    // *: value 3 listed but missing, value 2 not listed
    t.set(&all, "MRUListEx", 3, &mru(&[1, 0, 3]))
        .set(&all, "0", 3, &file)
        .set(&all, "1", 3, &trailing)
        .set(&all, "2", 3, &file)
        // docx: a list cut short, a list of the wrong type
        .set(&docx, "MRUListEx", 3, &mru(&[0, 1]))
        .set(&docx, "0", 3, &cut)
        .set(&docx, "1", 1, &file)
        // txt: no MRUListEx
        .set(&at(r"OpenSavePidlMRU\txt"), "0", 3, &file)
        .set(&at("LastVisitedPidlMRU"), "MRUListEx", 3, &mru(&[1, 0]))
        .set(
            &at("LastVisitedPidlMRU"),
            "0",
            3,
            &program_and("notepad.exe", &file),
        )
        // a program's name without its NUL; a name without a list after it
        .set(&at("LastVisitedPidlMRU"), "1", 3, &utf16z("cut.exe")[..8])
        .set(&at("LastVisitedPidlMRU"), "2", 3, &utf16z("bare.exe"))
        .set(&at("LastVisitedPidlMRULegacy"), "MRUListEx", 3, &mru(&[0]))
        .set(
            &at("LastVisitedPidlMRULegacy"),
            "0",
            3,
            &program_and("old.exe", &[0, 0]),
        )
        .set(&at("CIDSizeMRU"), "MRUListEx", 3, &mru(&[0]))
        .set(&at("CIDSizeMRU"), "0", 3, &cid_size)
        .set(&at("FirstFolder"), "MRUListEx", 3, &mru(&[1, 0]))
        .set(
            &at("FirstFolder"),
            "0",
            3,
            &strings(&[r"C:\Windows\explorer.exe", r"C:\Users\alice\Pictures"]),
        )
        .set(
            &at("FirstFolder"),
            "1",
            3,
            &strings(&[r"C:\Tools\x.exe", ""]),
        )
        // Windows XP: lettered values in MRUList order, in the key and an extension's subkey
        .sz(&xp, "MRUList", "ba")
        .sz(&xp, "a", r"C:\a.txt")
        .sz(&xp, "b", r"D:\b.log")
        .sz(&at(r"OpenSaveMRU\txt"), "MRUList", "A")
        .sz(&at(r"OpenSaveMRU\txt"), "a", r"C:\a.txt")
        // *: a letter listed but missing, a letter not listed, a path of the wrong type
        .sz(&at(r"OpenSaveMRU\*"), "MRUList", "ca")
        .set(&at(r"OpenSaveMRU\*"), "a", 3, &utf16z(r"C:\c.bin"))
        .sz(&at(r"OpenSaveMRU\*"), "b", r"C:\d.bin")
        .sz(&at("LastVisitedMRU"), "MRUList", "a")
        .set(
            &at("LastVisitedMRU"),
            "a",
            3,
            &strings(&["notepad.exe", r"C:\Temp"]),
        );
    let hive = t.hive("ROOT");
    let (entries, problems) = dialogs(&hive).unwrap();
    assert_eq!(
        problems,
        [format!(
            r"{COMDLG32}\OpenSavePidlMRU\txt: it has no MRUListEx: its items' order is unknown"
        )]
    );
    let got: Vec<Dialog> = entries
        .iter()
        .map(|e| {
            (
                e.list.name(),
                e.extension.as_deref(),
                e.mru_position,
                e.value_name.as_str(),
                e.program.as_deref(),
                e.path.as_deref(),
                e.problems.clone(),
            )
        })
        .collect();
    let none = Vec::new;
    let one = |p: &str| vec![p.to_owned()];
    let pidl = "OpenSavePidlMRU";
    assert_eq!(
        got,
        [
            (
                pidl,
                Some("*"),
                Some(0),
                "1",
                None,
                None,
                one("3 bytes after the end of its shell item list")
            ),
            (pidl, Some("*"), Some(1), "0", None, None, none()),
            (
                pidl,
                Some("*"),
                Some(2),
                "3",
                None,
                None,
                one("MRUListEx lists value 3, which is not there")
            ),
            (
                pidl,
                Some("*"),
                None,
                "2",
                None,
                None,
                one("MRUListEx doesn't list it")
            ),
            (
                pidl,
                Some("docx"),
                Some(0),
                "0",
                None,
                None,
                one("its shell item at offset 20 of 16 bytes is cut short")
            ),
            (
                pidl,
                Some("docx"),
                Some(1),
                "1",
                None,
                None,
                one("is REG_SZ, not REG_BINARY")
            ),
            (
                pidl,
                Some("txt"),
                None,
                "0",
                None,
                None,
                one("MRUListEx doesn't list it")
            ),
            (
                "LastVisitedPidlMRU",
                None,
                Some(0),
                "1",
                None,
                None,
                one("its program's name has no NUL: the data is cut short")
            ),
            (
                "LastVisitedPidlMRU",
                None,
                Some(1),
                "0",
                Some("notepad.exe"),
                None,
                none()
            ),
            (
                "LastVisitedPidlMRU",
                None,
                None,
                "2",
                Some("bare.exe"),
                None,
                vec![
                    "MRUListEx doesn't list it".to_owned(),
                    "no shell item list after the program's name".to_owned()
                ]
            ),
            (
                "LastVisitedPidlMRULegacy",
                None,
                Some(0),
                "0",
                Some("old.exe"),
                None,
                none()
            ),
            (
                "CIDSizeMRU",
                None,
                Some(0),
                "0",
                Some("app.exe"),
                None,
                none()
            ),
            (
                "FirstFolder",
                None,
                Some(0),
                "1",
                Some(r"C:\Tools\x.exe"),
                None,
                none()
            ),
            (
                "FirstFolder",
                None,
                Some(1),
                "0",
                Some(r"C:\Windows\explorer.exe"),
                Some(r"C:\Users\alice\Pictures"),
                none()
            ),
            (
                "OpenSaveMRU",
                None,
                Some(0),
                "b",
                None,
                Some(r"D:\b.log"),
                none()
            ),
            (
                "OpenSaveMRU",
                None,
                Some(1),
                "a",
                None,
                Some(r"C:\a.txt"),
                none()
            ),
            (
                "OpenSaveMRU",
                Some("txt"),
                Some(0),
                "a",
                None,
                Some(r"C:\a.txt"),
                none()
            ),
            (
                "OpenSaveMRU",
                Some("*"),
                Some(0),
                "c",
                None,
                None,
                one("MRUList lists value c, which is not there")
            ),
            (
                "OpenSaveMRU",
                Some("*"),
                Some(1),
                "a",
                None,
                Some(r"C:\c.bin"),
                one("is REG_BINARY, not REG_SZ")
            ),
            (
                "OpenSaveMRU",
                Some("*"),
                None,
                "b",
                None,
                Some(r"C:\d.bin"),
                one("MRUList doesn't list it")
            ),
            (
                "LastVisitedMRU",
                None,
                Some(0),
                "a",
                Some("notepad.exe"),
                Some(r"C:\Temp"),
                none()
            ),
        ]
    );
    // the shell items are kept, whole or not; the bytes of what doesn't decode too
    assert_eq!(entries[1].shell_items.as_deref(), Some(&file[..]));
    assert_eq!(entries[0].shell_items.as_deref(), Some(&trailing[..]));
    assert_eq!(entries[0].data_raw.as_deref(), Some(&trailing[..]));
    assert_eq!(entries[1].data_raw, None);
    assert_eq!(entries[4].shell_items.as_deref(), Some(&cut[..]));
    assert_eq!(entries[8].shell_items.as_deref(), Some(&file[..]));
    assert_eq!(
        entries[7].data_raw.as_deref(),
        Some(&utf16z("cut.exe")[..8])
    );
    assert_eq!(entries[7].shell_items, None);
    assert_eq!(entries[10].shell_items.as_deref(), Some(&[0u8, 0][..]));
    assert!(entries[2].data_raw.is_none() && entries[2].shell_items.is_none());
    assert_eq!(entries[0].key_path, all);
    assert!(
        entries
            .iter()
            .all(|e| e.key_last_written > 0 && !e.replayed)
    );
    // no ComDlg32 key
    assert!(dialogs(&Tree::default().hive("ROOT")).is_none());
}

/// An entry's place, value, program and path.
type Lettered<'a> = (Option<u32>, &'a str, Option<&'a str>, Option<&'a str>);

#[test]
fn mru_lists_that_dont_add_up() {
    use ys_registry_parser::comdlg32::{COMDLG32, dialogs};
    let xp = format!(r"{COMDLG32}\LastVisitedMRU");
    let mut t = Tree::default();
    // a letter listed twice, in another case; a list past its NUL; a value that isn't a letter
    let mut list = utf16z("bAa");
    list.extend(utf16z("z"));
    t.set(&xp, "MRUList", 1, &list)
        .set(&xp, "a", 3, &strings(&["one.exe", r"C:\One"]))
        .set(&xp, "b", 3, &strings(&["two.exe"]))
        .sz(&xp, "extra", "x")
        .set(&xp, "MRUListEx", 3, &mru(&[0]));
    let hive = t.hive("ROOT");
    let (entries, problems) = dialogs(&hive).unwrap();
    assert_eq!(
        problems,
        [
            format!("{xp}: MRUList: characters past its NUL"),
            format!("{xp}: MRUList: a is listed twice"),
            format!(r#"{xp}: value "extra" is not a lettered item"#),
            format!(r#"{xp}: value "MRUListEx" is not a lettered item"#),
        ]
    );
    let got: Vec<Lettered> = entries
        .iter()
        .map(|e| {
            (
                e.mru_position,
                e.value_name.as_str(),
                e.program.as_deref(),
                e.path.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (Some(0), "b", Some("two.exe"), None),
            (Some(1), "a", Some("one.exe"), Some(r"C:\One")),
        ]
    );
    assert!(entries.iter().all(|e| e.problems.is_empty()));
    // MRUList of the wrong type, and no MRUList at all
    let mut t = Tree::default();
    t.dword(&xp, "MRUList", 0x61)
        .set(&xp, "a", 3, &strings(&["one.exe", r"C:\One"]));
    let (entries, problems) = dialogs(&t.hive("ROOT")).unwrap();
    assert_eq!(
        problems,
        [format!("{xp}: MRUList: is REG_DWORD, not REG_SZ")]
    );
    assert_eq!(entries[0].mru_position, Some(0));
    let mut t = Tree::default();
    t.set(&xp, "a", 3, &strings(&["one.exe", "C:"]));
    let (entries, problems) = dialogs(&t.hive("ROOT")).unwrap();
    assert_eq!(
        problems,
        [format!(
            "{xp}: it has no MRUList: its items' order is unknown"
        )]
    );
    assert_eq!(entries[0].problems, ["MRUList doesn't list it"]);
}

/// A generated Ed25519 host key in `SshHostKeys` form, and its fingerprint (`ssh-keygen -l`).
const ED25519: &str = "0x1dc1835f6c2412ce0471e8e93f9bc28c107b658a7c09d1b77cf8328a9727bcbf,0x6a13e584ed673b1b8640774399fbb872c00e7ff64f4e24ea5870315b315b7fd3";
const ED25519_FINGERPRINT: &str = "SHA256:FHMF6w9trn7uMSI+bN+z7+Biyw+8SJgBfXa9ie8UtuY";

#[test]
#[allow(clippy::too_many_lines)]
fn remote_connections_of_each_kind() {
    let tsc = r"Software\Microsoft\Terminal Server Client";
    let default = format!(r"{tsc}\Default");
    let server = format!(r"{tsc}\Servers\server01.example.com");
    let bad_server = format!(r"{tsc}\Servers\10.0.0.5");
    let devices = format!(r"{tsc}\LocalDevices");
    let putty = r"Software\SimonTatham\PuTTY";
    let web = format!(r"{putty}\Sessions\web%20server");
    let template = format!(r"{putty}\Sessions\Default%20Settings");
    let putty_keys = format!(r"{putty}\SshHostKeys");
    let winscp = r"Software\Martin Prikryl\WinSCP 2";
    let files = format!(r"{winscp}\Sessions\alice@files.example.com");
    let mru = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU";
    let points = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2";
    let mut t = Tree::default();
    t.sz(&default, "MRU1", "[fe80::1]:3390")
        .sz(&default, "MRU0", "server01.example.com")
        // damaged: binary; its bytes kept
        .set(&default, "MRU2", 3, &[1, 2, 3])
        .sz(&default, "MRU10", "10.0.0.9:3389")
        .sz(&default, "MRU01", "not an MRU value")
        .sz(&server, "UsernameHint", r"EXAMPLE\alice")
        .set(&server, "CertHash", 3, &[0xab; 20])
        .dword(&bad_server, "UsernameHint", 7)
        .dword(&devices, "server01.example.com", 0x4c)
        // PuTTY: the account in HostName, a proxy with its password, logging off
        .sz(&web, "HostName", "admin@203.0.113.10")
        .dword(&web, "PortNumber", 2222)
        .sz(&web, "Protocol", "ssh")
        .sz(&web, "UserName", "")
        .sz(&web, "PublicKeyFile", r"C:\Users\alice\.ssh\id.ppk")
        .sz(&web, "PortForwardings", "L8080=127.0.0.1:80")
        .dword(&web, "ProxyMethod", 3)
        .sz(&web, "ProxyHost", "proxy.example.com")
        .dword(&web, "ProxyPort", 8080)
        .sz(&web, "ProxyPassword", "not decoded")
        .dword(&web, "LogType", 0)
        .sz(&web, "LogFileName", "putty.log")
        .sz(&template, "HostName", "")
        .sz(&template, "ProxyHost", "proxy")
        .multi(
            &format!(r"{putty}\Jumplist"),
            "Recent sessions",
            &["gone", "web server"],
        )
        .sz(&putty_keys, "ssh-ed25519@22:203.0.113.10", ED25519)
        .sz(&putty_keys, "rsa2@22:203.0.113.11", "0x23,0xzz")
        .sz(&putty_keys, "not-a-host-key", "0x1")
        // WinSCP: FTP over explicit TLS through an SSH tunnel, with a stored password
        .sz(&files, "HostName", "files.example.com")
        .dword(&files, "PortNumber", 21)
        .sz(&files, "UserName", "alice")
        .dword(&files, "FSProtocol", 5)
        .dword(&files, "Ftps", 3)
        .sz(&files, "Password", "A35C4E")
        .sz(&files, "LocalDirectory", "C:%5CUsers%5Calice")
        .sz(&files, "TunnelHostName", "jump.example.com")
        .sz(&files, "TunnelPasswordPlain", "")
        .sz(
            &format!(r"{winscp}\SshHostKeys"),
            "ssh-ed25519@22:files.example.com",
            ED25519,
        )
        // drives: one with the user's own account, one with another
        .sz(r"Network\Z", "RemotePath", r"\\fs01\share")
        .dword(r"Network\Z", "UserName", 0)
        .sz(r"Network\Z", "ProviderName", "Microsoft Windows Network")
        .dword(r"Network\Z", "ProviderType", 0x20000)
        .dword(r"Network\Z", "ConnectionType", 1)
        .sz(r"Network\Y", "RemotePath", r"\\fs02\c$")
        .sz(r"Network\Y", "UserName", r"EXAMPLE\admin")
        // a letter listed twice, one not there, a value not listed
        .sz(mru, "MRUList", "bdab")
        .sz(mru, "a", r"\\fs01\share")
        .sz(mru, "b", r"\\fs02\c$")
        .sz(mru, "c", r"\\fs03\old")
        .sz(&format!(r"{points}\##fs01#share"), "_LabelFromReg", "Team")
        .sz(
            &format!(r"{points}\##live.sysinternals.com#DavWWWRoot"),
            "_LabelFromDesktopINI",
            "",
        )
        .at(&format!(
            r"{points}\{{0a1b2c3d-0000-0000-0000-100000000000}}"
        ))
        .at(&format!(r"{points}\C"));
    let hive = t.hive("ROOT");
    let (records, problems) = connections(&hive);
    assert_eq!(
        problems,
        [
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU: MRUList: b is listed twice"
        ]
    );
    let got: Vec<String> = records
        .iter()
        .map(|c| {
            format!(
                "{} {} {} {} {} {} {} {}",
                c.kind.name(),
                c.target.as_deref().unwrap_or("-"),
                c.port.map_or("-".to_owned(), |p| p.to_string()),
                c.username.as_deref().unwrap_or("-"),
                c.protocol.as_deref().unwrap_or("-"),
                c.mru_position.map_or("-".to_owned(), |p| p.to_string()),
                c.session_name.as_deref().unwrap_or("-"),
                c.password_stored
                    .map_or("-", |p| if p { "password" } else { "none" }),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            "rdp_mru server01.example.com - - - 0 - -",
            "rdp_mru fe80::1 3390 - - 1 - -",
            "rdp_mru - - - - 2 - -",
            "rdp_mru 10.0.0.9 3389 - - 10 - -",
            r"rdp_server server01.example.com - EXAMPLE\alice - - - -",
            "rdp_server 10.0.0.5 - - - - - -",
            "rdp_local_devices server01.example.com - - - - - -",
            "putty_session 203.0.113.10 2222 admin ssh 1 web server password",
            "putty_session - - - - - Default Settings none",
            "putty_session - - - - 0 gone -",
            "putty_host_key 203.0.113.10 22 - - - - -",
            "putty_host_key 203.0.113.11 22 - - - - -",
            "putty_host_key - - - - - - -",
            "winscp_session files.example.com 21 alice ftp - alice@files.example.com password",
            "winscp_host_key files.example.com 22 - - - - -",
            r"network_drive \\fs01\share - - Microsoft Windows Network - - -",
            r"network_drive \\fs02\c$ - EXAMPLE\admin - - - -",
            r"map_network_drive_mru \\fs02\c$ - - - 0 - -",
            "map_network_drive_mru - - - - 1 - -",
            r"map_network_drive_mru \\fs01\share - - - 2 - -",
            r"map_network_drive_mru \\fs03\old - - - - - -",
            r"mount_point \\fs01\share - - - - - -",
            r"mount_point \\live.sysinternals.com\DavWWWRoot - - - - - -",
        ]
    );
    let detail = |at: usize| -> Vec<String> {
        records[at]
            .details
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect()
    };
    // the damaged MRU value keeps its bytes
    assert_eq!(records[2].problems, ["is REG_BINARY, not a string"]);
    assert_eq!(records[2].data_raw.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(records[2].value_name.as_deref(), Some("MRU2"));
    assert_eq!(detail(4), ["CertHash=".to_owned() + &"ab".repeat(20)]);
    assert_eq!(
        records[5].problems,
        ["UsernameHint: is REG_DWORD, not a string; its data: 07000000"]
    );
    assert_eq!(detail(6), ["LocalDevices=0x4c"]);
    assert_eq!(
        detail(7),
        [
            r"PublicKeyFile=C:\Users\alice\.ssh\id.ppk",
            "PortForwardings=L8080=127.0.0.1:80",
            "ProxyMethod=3 (http)",
            "ProxyHost=proxy.example.com",
            "ProxyPort=8080",
            "StoredPasswords=ProxyPassword",
        ]
    );
    assert_eq!(
        records[7].key_path,
        format!(r"{putty}\Sessions\web%20server")
    );
    // the template's unused proxy host isn't reported
    assert_eq!(detail(8), Vec::<String>::new());
    assert_eq!(
        (
            records[9].key_path.as_str(),
            records[9].value_name.as_deref()
        ),
        (
            r"Software\SimonTatham\PuTTY\Jumplist",
            Some("Recent sessions")
        )
    );
    // host keys: a fingerprint, numbers that aren't hex, a name that isn't type@port:host
    assert_eq!(
        (
            records[10].host_key_type.as_deref(),
            records[10].host_key_fingerprint.as_deref(),
            records[10].host_key.as_deref()
        ),
        (
            Some("ssh-ed25519"),
            Some(ED25519_FINGERPRINT),
            Some(ED25519)
        )
    );
    assert_eq!(records[11].problems, [r#""0xzz" is not a number in hex"#]);
    assert_eq!(
        (
            records[11].host_key_fingerprint.as_deref(),
            records[11].host_key.as_deref()
        ),
        (None, Some("0x23,0xzz"))
    );
    assert_eq!(
        records[12].problems,
        ["its name isn't <type>@<port>:<host>"]
    );
    assert_eq!(records[12].value_name.as_deref(), Some("not-a-host-key"));
    assert_eq!(
        detail(13),
        [
            "Ftps=3 (explicit TLS)",
            r"LocalDirectory=C:\Users\alice",
            "TunnelHostName=jump.example.com",
            "StoredPasswords=Password",
        ]
    );
    assert_eq!(
        records[14].host_key_fingerprint.as_deref(),
        Some(ED25519_FINGERPRINT)
    );
    assert_eq!(records[15].drive_letter.as_deref(), Some("Z"));
    assert_eq!(
        detail(15),
        ["ConnectionType=1 (disk)", "ProviderType=0x20000"]
    );
    assert_eq!(records[17].value_name.as_deref(), Some("b"));
    assert_eq!(
        records[18].problems,
        ["MRUList lists value d, which is not there"]
    );
    assert_eq!(records[20].problems, ["MRUList doesn't list it"]);
    assert_eq!(detail(21), ["Label=Team"]);
    for (at, record) in records.iter().enumerate() {
        if ![2, 5, 11, 12, 18, 20].contains(&at) {
            assert_eq!(record.problems, Vec::<String>::new(), "{at}");
        }
    }
    assert!(
        records
            .iter()
            .all(|r| r.key_last_written == WHEN && !r.replayed)
    );
    // a hive without any of these keys
    assert_eq!(
        connections(&Tree::default().hive("ROOT")),
        (Vec::new(), Vec::new())
    );
}

#[test]
fn remote_map_mru_matches_registry_value_case() {
    use ys_registry_parser::remote_access::{MAP_NETWORK_DRIVE_MRU, connections};
    let mut t = Tree::default();
    t.sz(MAP_NETWORK_DRIVE_MRU, "MRUList", "A")
        .sz(MAP_NETWORK_DRIVE_MRU, "a", r"\\server\share");
    let (records, problems) = connections(&t.hive("ROOT"));
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target.as_deref(), Some(r"\\server\share"));
    assert_eq!(records[0].mru_position, Some(0));
}

#[test]
fn remote_stored_passwords_never_leak_through_malformed_value_diagnostics() {
    use ys_registry_parser::remote_access::{PUTTY, WINSCP, connections};
    let mut t = Tree::default();
    let canary = b"secret-canary-do-not-export";
    t.set(
        &format!(r"{PUTTY}\Sessions\test"),
        "ProxyPassword",
        3,
        canary,
    )
    .set(&format!(r"{WINSCP}\Sessions\test"), "Password", 3, canary);
    let (records, problems) = connections(&t.hive("ROOT"));
    assert!(problems.is_empty(), "{problems:?}");
    let text = format!("{records:?}");
    let hex = canary.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write;
        write!(out, "{b:02x}").unwrap();
        out
    });
    assert!(
        !text.contains("secret-canary") && !text.contains(&hex),
        "{text}"
    );
    assert!(records.iter().all(|r| r.password_stored == Some(true)));
}

/// A `TIME_FIELDS`: year, month, day, hour, minute, second, milliseconds, weekday.
fn time_fields(fields: [u16; 8]) -> Vec<u8> {
    fields.iter().flat_map(|f| f.to_le_bytes()).collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn system_details_of_a_built_system() {
    let zone = r"ControlSet002\Control\TimeZoneInformation";
    let upgrade = r"Setup\Source OS (Updated on 5/16/2019 00:55:20)";
    let mut t = Tree::default();
    t.dword("Select", "Current", 2)
        .sz(
            r"ControlSet001\Control\ComputerName\ComputerName",
            "ComputerName",
            "OLDNAME",
        )
        .sz(
            r"ControlSet002\Control\ComputerName\ComputerName",
            "ComputerName",
            "HOST1",
        )
        .sz(
            r"ControlSet002\Services\Tcpip\Parameters",
            "HostName",
            "host1",
        )
        // a workgroup's Domain, on some systems: a REG_DWORD 0
        .dword(r"ControlSet002\Services\Tcpip\Parameters", "Domain", 0)
        .sz(zone, "TimeZoneKeyName", "Easter Island Standard Time")
        .sz(zone, "StandardName", "@tzres.dll,-2372")
        .dword(zone, "Bias", 360)
        .dword(zone, "StandardBias", 0)
        .dword(zone, "DaylightBias", (-60i32).cast_unsigned())
        .dword(zone, "ActiveTimeBias", 300)
        // the kernel's TIME_FIELDS: the first Saturday (weekday 6, last) at 22:00
        .set(
            zone,
            "StandardStart",
            3,
            &time_fields([0, 4, 1, 22, 0, 0, 0, 6]),
        )
        .set(
            zone,
            "DaylightStart",
            3,
            &time_fields([0, 9, 1, 22, 0, 0, 0, 6]),
        )
        .dword(zone, "DynamicDaylightTimeDisabled", 1)
        .dword(zone, "RealTimeIsUniversal", 1)
        .set(
            r"ControlSet002\Control\Windows",
            "ShutdownTime",
            3,
            &WHEN.to_le_bytes(),
        )
        .sz(
            r"ControlSet002\Control\Session Manager\Environment",
            "PROCESSOR_ARCHITECTURE",
            "ARM64",
        )
        .sz(r"ControlSet002\Control\Nls\CodePage", "ACP", "932")
        .sz(r"ControlSet002\Control\Nls\CodePage", "OEMCP", "932")
        .dword("Setup", "SetupType", 0)
        .sz(upgrade, "ProductName", "Windows 10 Pro")
        .sz(upgrade, "EditionID", "Professional")
        .sz(upgrade, "CurrentBuild", "17134")
        .dword(upgrade, "UBR", 765)
        .sz(upgrade, "ReleaseId", "1803")
        .dword(upgrade, "InstallDate", 1_548_585_572)
        .set(
            upgrade,
            "InstallTime",
            11,
            &131_930_591_728_980_553u64.to_le_bytes(),
        )
        // a name whose date isn't one
        .sz(
            r"Setup\Source OS (Updated on 13/40/2019 00:55:20)",
            "ProductName",
            "Windows 10 Home",
        )
        .at(r"Setup\Status");
    let found = system(&t.hive("ROOT"));
    assert_eq!(found.problems, Vec::<String>::new());
    assert_eq!((found.control_set, found.is_current), (Some(2), true));
    assert_eq!(found.computer_name.as_deref(), Some("HOST1"));
    assert_eq!(found.computer_name_last_written, Some(WHEN));
    // value names in any case
    assert_eq!(found.hostname.as_deref(), Some("host1"));
    assert_eq!(found.domain, None);
    assert_eq!(found.last_shutdown, Some(WHEN));
    assert_eq!(found.processor_architecture.as_deref(), Some("ARM64"));
    assert_eq!(found.ansi_code_page.as_deref(), Some("932"));
    let zone = found.time_zone.unwrap();
    assert_eq!(zone.name(), Some("Easter Island Standard Time"));
    assert_eq!(
        (
            zone.bias,
            zone.standard_bias,
            zone.daylight_bias,
            zone.active_time_bias
        ),
        (Some(360), Some(0), Some(-60), Some(300))
    );
    assert_eq!(
        zone.standard_start.and_then(|d| d.describe()).as_deref(),
        Some("first Saturday of April, 22:00")
    );
    assert_eq!(
        zone.daylight_start.and_then(|d| d.describe()).as_deref(),
        Some("first Saturday of September, 22:00")
    );
    assert_eq!(
        (
            zone.dynamic_daylight_time_disabled,
            zone.real_time_is_universal
        ),
        (Some(true), Some(true))
    );
    let versions: Vec<_> = found
        .previous_versions
        .iter()
        .map(|p| {
            (
                p.key_name.as_str(),
                p.updated_on.as_deref(),
                p.version.product_name.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        versions,
        [
            (
                "Source OS (Updated on 5/16/2019 00:55:20)",
                Some("2019-05-16T00:55:20"),
                Some("Windows 10 Pro")
            ),
            (
                "Source OS (Updated on 13/40/2019 00:55:20)",
                None,
                Some("Windows 10 Home")
            ),
        ]
    );
    let v = &found.previous_versions[0].version;
    assert_eq!(
        (
            v.edition_id.as_deref(),
            v.current_build.as_deref(),
            v.ubr,
            v.release_id.as_deref(),
            v.install_date,
            v.install_time
        ),
        (
            Some("Professional"),
            Some("17134"),
            Some(765),
            Some("1803"),
            Some(1_548_585_572),
            Some(131_930_591_728_980_553)
        )
    );
    assert_eq!(v.key_path, upgrade);
}

#[test]
#[allow(clippy::too_many_lines)]
fn system_details_that_dont_decode() {
    let zone = r"ControlSet001\Control\TimeZoneInformation";
    let mut t = Tree::default();
    t.sz(zone, "Bias", "300")
        .set(zone, "TimeZoneKeyName", 3, b"Tokyo")
        .set(zone, "StandardStart", 3, &[0; 15])
        .set(
            zone,
            "DaylightStart",
            3,
            &time_fields([0, 0, 0, 0, 0, 0, 0, 0]),
        )
        .set(
            r"ControlSet001\Control\Windows",
            "ShutdownTime",
            3,
            &[1, 2, 3],
        )
        .set(
            r"ControlSet001\Control\ComputerName\ComputerName",
            "ComputerName",
            4,
            &[1, 2],
        );
    // no Select: the first control set
    let found = system(&t.hive("ROOT"));
    assert_eq!((found.control_set, found.is_current), (Some(1), false));
    assert_eq!(
        found.problems,
        [
            r"ControlSet001\Control\ComputerName\ComputerName\ComputerName: is REG_DWORD, not a string",
            r"ControlSet001\Control\TimeZoneInformation\TimeZoneKeyName: is REG_BINARY, not a string",
            r"ControlSet001\Control\TimeZoneInformation\Bias: is REG_SZ, not REG_DWORD",
            r"ControlSet001\Control\TimeZoneInformation\StandardStart: 15 bytes, not the 16 of a TIME_FIELDS (000000000000000000000000000000)",
            r"ControlSet001\Control\Windows\ShutdownTime: 3 bytes (010203), not a FILETIME",
        ]
    );
    let zone = found.time_zone.unwrap();
    assert_eq!(
        (zone.name(), zone.bias, zone.standard_start),
        (None, None, None)
    );
    // a month of 0: no daylight saving time
    assert_eq!(zone.daylight_start.map(|d| d.is_set()), Some(false));
    assert_eq!((found.computer_name, found.last_shutdown), (None, None));
    // a hive without control sets
    let found = system(&Tree::default().hive("ROOT"));
    assert_eq!(
        (found.control_set, found.time_zone, found.problems.len()),
        (None, None, 0)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn software_details_of_a_built_software_hive() {
    let version = r"Microsoft\Windows NT\CurrentVersion";
    let profiles = r"Microsoft\Windows NT\CurrentVersion\ProfileList";
    let alice = format!(r"{profiles}\S-1-5-21-1-2-3-1001");
    let bob = format!(r"{profiles}\S-1-5-21-1-2-3-1002");
    let logon = r"Microsoft\Windows\CurrentVersion\Authentication\LogonUI";
    let mut t = Tree::default();
    t.sz(version, "ProductName", "Windows 10 Pro")
        .sz(version, "EditionID", "Professional")
        .sz(version, "DisplayVersion", "23H2")
        .sz(version, "ReleaseId", "2009")
        .sz(version, "CurrentVersion", "6.3")
        .dword(version, "CurrentMajorVersionNumber", 10)
        .dword(version, "CurrentMinorVersionNumber", 0)
        .sz(version, "CurrentBuildNumber", "22631")
        .dword(version, "UBR", 4317)
        .sz(version, "InstallationType", "Client")
        .dword(version, "InstallDate", 1_700_000_000)
        .set(version, "InstallTime", 11, &WHEN.to_le_bytes())
        .sz(version, "RegisteredOwner", "alice")
        .sz(version, "RegisteredOrganization", "")
        .sz(version, "SystemRoot", r"C:\Windows")
        .sz(
            &format!(r"{profiles}\S-1-5-18"),
            "ProfileImagePath",
            r"%systemroot%\system32\config\systemprofile",
        )
        .dword(&format!(r"{profiles}\S-1-5-18"), "Flags", 12)
        .sz(&alice, "ProfileImagePath", r"C:\Users\alice")
        .dword(&alice, "LocalProfileLoadTimeHigh", (WHEN >> 32) as u32)
        .dword(&alice, "LocalProfileLoadTimeLow", WHEN as u32)
        .dword(
            &alice,
            "LocalProfileUnloadTimeHigh",
            ((WHEN + 1) >> 32) as u32,
        )
        .dword(&alice, "LocalProfileUnloadTimeLow", (WHEN + 1) as u32)
        .dword(&alice, "ProfileLoadTimeHigh", 0)
        .dword(&alice, "ProfileLoadTimeLow", 0)
        .dword(&alice, "State", 0)
        .sz(&bob, "ProfileImagePath", r"C:\Users\bob")
        // half a time, and a State that isn't a number
        .dword(&bob, "LocalProfileLoadTimeHigh", (WHEN >> 32) as u32)
        .sz(&bob, "State", "256")
        .sz(logon, "LastLoggedOnUser", r".\alice")
        .sz(logon, "LastLoggedOnSAMUser", r".\alice")
        .sz(logon, "LastLoggedOnUserSID", "S-1-5-21-1-2-3-1001")
        .sz(logon, "LastLoggedOnDisplayName", "Alice");
    let found = software(&t.hive("ROOT"));
    assert_eq!(found.problems, Vec::<String>::new());
    let v = found.version.unwrap();
    assert_eq!(v.problems, Vec::<String>::new());
    assert_eq!(
        (
            v.product_name.as_deref(),
            v.edition_id.as_deref(),
            v.display_version.as_deref(),
            v.release_id.as_deref(),
            v.current_build.as_deref(),
            v.ubr
        ),
        (
            Some("Windows 10 Pro"),
            Some("Professional"),
            Some("23H2"),
            Some("2009"),
            // CurrentBuildNumber without CurrentBuild
            Some("22631"),
            Some(4317)
        )
    );
    assert_eq!(
        (
            v.current_version.as_deref(),
            v.major_version,
            v.minor_version
        ),
        (Some("6.3"), Some(10), Some(0))
    );
    assert_eq!(
        (v.install_date, v.install_time),
        (Some(1_700_000_000), Some(WHEN))
    );
    assert_eq!(
        (
            v.registered_owner.as_deref(),
            v.registered_organization.as_deref(),
            v.system_root.as_deref(),
            v.installation_type.as_deref(),
            v.csd_version.as_deref()
        ),
        (
            Some("alice"),
            None,
            Some(r"C:\Windows"),
            Some("Client"),
            None
        )
    );
    assert_eq!(v.key_path, version);
    let got: Vec<_> = found
        .profiles
        .iter()
        .map(|p| {
            (
                p.sid.as_str(),
                p.path.as_deref(),
                p.load_time,
                p.local_load_time,
                p.local_unload_time,
                p.state,
                p.flags,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "S-1-5-18",
                Some(r"%systemroot%\system32\config\systemprofile"),
                None,
                None,
                None,
                None,
                Some(12)
            ),
            (
                "S-1-5-21-1-2-3-1001",
                Some(r"C:\Users\alice"),
                None,
                Some(WHEN),
                Some(WHEN + 1),
                Some(0),
                None
            ),
            (
                "S-1-5-21-1-2-3-1002",
                Some(r"C:\Users\bob"),
                None,
                None,
                None,
                None,
                None
            ),
        ]
    );
    assert_eq!(
        found.profiles[2].problems,
        [
            format!(r"{bob}\LocalProfileLoadTime: only one FILETIME half is present"),
            format!(r"{bob}\State: is REG_SZ, not REG_DWORD")
        ]
    );
    let last = found.last_logged_on.unwrap();
    assert_eq!(
        (
            last.user.as_deref(),
            last.sam_user.as_deref(),
            last.user_sid.as_deref(),
            last.display_name.as_deref(),
            last.key_last_written
        ),
        (
            Some(r".\alice"),
            Some(r".\alice"),
            Some("S-1-5-21-1-2-3-1001"),
            Some("Alice"),
            WHEN
        )
    );
    // a hive without these keys
    let none = software(&Tree::default().hive("ROOT"));
    assert!(none.version.is_none() && none.profiles.is_empty() && none.last_logged_on.is_none());
}

/// A `UNICODE_STRING` as LSA keeps it: length, maximum length, the text's offset, the text.
fn lsa_string(text: &str) -> Vec<u8> {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut b = (units.len() as u16).to_le_bytes().to_vec();
    b.extend(((units.len() + 2) as u16).to_le_bytes());
    b.extend(8u32.to_le_bytes());
    b.extend(&units);
    b.extend([0, 0]);
    b
}

/// A SID `S-1-5-<subs>`.
fn sid_bytes(subs: &[u32]) -> Vec<u8> {
    let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, 5];
    b.extend(subs.iter().flat_map(|s| s.to_le_bytes()));
    b
}

#[test]
#[allow(clippy::too_many_lines)]
fn domains_of_a_built_security_hive() {
    let guid = [
        0x3f, 0xe3, 0xa0, 0x1e, 0xa1, 0xfa, 0x62, 0x41, 0xb5, 0x25, 0x3e, 0xd8, 0x0c, 0x00, 0xc1,
        0xad,
    ];
    let mut t = Tree::default();
    t.set(r"Policy\PolAcDmN", "", 0, &lsa_string("HOST1"))
        .set(r"Policy\PolAcDmS", "", 0, &sid_bytes(&[21, 1, 2, 3]))
        .set(r"Policy\PolPrDmN", "", 0, &lsa_string("CORP"))
        .set(r"Policy\PolPrDmS", "", 0, &sid_bytes(&[21, 7, 8, 9]))
        .set(r"Policy\PolDnDDN", "", 0, &lsa_string("corp.example.com"))
        .set(r"Policy\PolDnTrN", "", 0, &lsa_string("example.com"))
        .set(r"Policy\PolDnDmG", "", 0, &guid)
        .set(
            r"Policy\PolMachineAccountS",
            "",
            0,
            &sid_bytes(&[21, 7, 8, 9, 1105]),
        );
    let found = domains(&t.hive("ROOT")).unwrap();
    assert_eq!(found.problems, Vec::<String>::new());
    assert_eq!(
        (
            found.account_domain_name.as_deref(),
            found.account_domain_sid.as_deref(),
            found.primary_domain_name.as_deref(),
            found.primary_domain_sid.as_deref(),
            found.primary_domain_last_written
        ),
        (
            Some("HOST1"),
            Some("S-1-5-21-1-2-3"),
            Some("CORP"),
            Some("S-1-5-21-7-8-9"),
            Some(WHEN)
        )
    );
    assert_eq!(
        (
            found.dns_domain_name.as_deref(),
            found.dns_forest_name.as_deref(),
            found.domain_guid.as_deref(),
            found.machine_account_sid.as_deref()
        ),
        (
            Some("corp.example.com"),
            Some("example.com"),
            Some("{1ea0e33f-faa1-4162-b525-3ed80c00c1ad}"),
            Some("S-1-5-21-7-8-9-1105")
        )
    );

    // a name past its bytes, a SID that isn't one, a GUID cut short, a zero GUID
    let mut long = lsa_string("CORP");
    long[0] = 0x40;
    let mut t = Tree::default();
    t.set(r"Policy\PolPrDmN", "", 0, &long)
        .set(r"Policy\PolAcDmS", "", 0, &[1, 4, 0, 0])
        .set(r"Policy\PolDnDmG", "", 0, &guid[..15])
        .set(r"Policy\PolPrDmS", "", 0, &[]);
    let found = domains(&t.hive("ROOT")).unwrap();
    assert_eq!(
        found.problems,
        [
            r"Policy\PolPrDmN: invalid UNICODE_STRING: length 64, maximum 10, offset 8 (40000a000800000043004f00520050000000)",
            r"Policy\PolAcDmS: not a SID (01040000)",
            r"Policy\PolDnDmG: 15 bytes (3fe3a01ea1fa6241b5253ed80c00c1), not a GUID",
        ]
    );
    assert_eq!(
        (found.primary_domain_name, found.primary_domain_sid),
        (None, None)
    );
    assert_eq!(found.primary_domain_last_written, Some(WHEN));
    let mut t = Tree::default();
    t.set(r"Policy\PolDnDmG", "", 0, &[0; 16]);
    assert_eq!(domains(&t.hive("ROOT")).unwrap().domain_guid, None);
    assert!(domains(&Tree::default().hive("ROOT")).is_none());
}

#[test]
fn system_info_reports_half_a_profile_time() {
    let mut t = Tree::default();
    t.dword(
        r"Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1-2-3-1001",
        "ProfileLoadTimeLow",
        123,
    );
    let details = ys_registry_parser::system_info::software(&t.hive("ROOT"));
    assert_eq!(details.profiles.len(), 1);
    assert_eq!(details.profiles[0].load_time, None);
    assert!(
        details.profiles[0]
            .problems
            .iter()
            .any(|p| p.contains("only one FILETIME half"))
    );
}
