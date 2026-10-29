//! Hives built here, for what real ones seldom hold: every kind of subkey list, big data,
//! damage that must not hide what's next to it, loops, a root found by its flag, and deleted keys
//! and values with their parents in use, deleted or lost.
#![allow(clippy::unwrap_used, clippy::cast_possible_wrap)]

use ys_registry_parser::ntuser::recent_docs;
use ys_registry_parser::sam::accounts;
use ys_registry_parser::software::{TaskAction, task_cache};
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
