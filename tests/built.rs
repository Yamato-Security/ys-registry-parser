//! Hives built here, for what real ones seldom hold: every kind of subkey list, big data,
//! damage that must not hide what's next to it, loops, a root found by its flag, and deleted keys
//! and values with their parents in use, deleted or lost.
#![allow(clippy::unwrap_used, clippy::cast_possible_wrap)]

use ys_registry_parser::ntuser::recent_docs;
use ys_registry_parser::{Data, Hive, Status, decode};

/// 2022-02-08T21:03:52Z.
const WHEN: u64 = 132_888_278_320_000_000;
const NONE: u32 = u32::MAX;

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
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
        let list = self.lf(subkeys);
        self.put(
            &nk("ROOT", NONE, (subkeys.len() as u32, list), (0, NONE), 0x2c),
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
    let mut vk = vec![0u8; 0x14];
    vk[..2].copy_from_slice(b"vk");
    vk[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
    vk[4..8].copy_from_slice(&len.to_le_bytes());
    vk[8..12].copy_from_slice(&offset.to_le_bytes());
    vk[12..16].copy_from_slice(&kind.to_le_bytes());
    vk[16..18].copy_from_slice(&1u16.to_le_bytes());
    vk.extend(name.as_bytes());
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
