//! Hives built here, for what real ones seldom hold: every kind of subkey list, big data,
//! damage that must not hide what's next to it, loops, a root found by its flag, and deleted keys
//! and values with their parents in use, deleted or lost.
#![allow(clippy::unwrap_used, clippy::cast_possible_wrap)]

use std::fmt::Write as _;

use ys_registry_parser::ntuser::{
    classes_sid, recent_docs, rot13, user_assist, user_assist_settings,
};
use ys_registry_parser::persistence::{self, Autostart, MachineClasses, Mechanism};
use ys_registry_parser::sam::accounts;
use ys_registry_parser::software::{TaskAction, profile_list, task_cache};
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
        .dword(&format!(r"{ua}\Settings"), "NoEncrypt", 1)
        .dword(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Start_TrackProgs",
            0,
        );
    let hive = t.hive("ROOT");
    let (entries, problems) = user_assist(&hive).unwrap();
    assert_eq!(
        problems,
        [
            r"UserAssist\Settings NoEncrypt is 1: names written while it was set are not ROT13, and decode wrongly"
        ]
    );
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
