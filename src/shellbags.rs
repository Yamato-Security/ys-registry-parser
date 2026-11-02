//! `ShellBags`: the folders a user opened in Explorer (and in open and save dialogs), as the trees of
//! shell items Explorer keeps to remember each folder's view.
//!
//! A `BagMRU` key holds numbered values, each a shell item list (one item: a drive, a folder, a
//! control panel page, …), and an `MRUListEx` giving their order, the most recently opened first.
//! Each value has a subkey of the same name for the items under it, so a path is the items from
//! `BagMRU` down to a value. A subkey's `NodeSlot` is the number of its `Bags\N` key, where the
//! folder's view settings are.
//!
//! Since Windows Vista the trees are in `UsrClass.dat` (`Local Settings\Software\Microsoft\Windows
//! \Shell\BagMRU`); `NTUSER.DAT` keeps `Software\Microsoft\Windows\Shell\BagMRU` (desktop and
//! network items) and, on Windows XP, `ShellNoRoam\BagMRU` for local folders.
//!
//! Times: a key's last-write time changes when its `MRUListEx` is rewritten, that is when one of
//! its items is opened and moved to the front. So a key's time dates the opening of its most
//! recent item (`MRUListEx` position 0) only. The times inside a shell item (a folder's FAT
//! modification, creation and access times) are those of the folder when the item was written.
//!
//! The items are kept as their bytes: decode them with a shell item parser (they are the same
//! as a link's target ID list).

use crate::bytes::u32_at;
use crate::data::ValueType;
use crate::hive::{Hive, Key, Status};
use crate::ntuser::mru_items;
use std::collections::HashSet;

/// Where Explorer keeps `BagMRU` trees, under a hive's root: `UsrClass.dat`'s (Windows Vista and
/// later, 64-bit and 32-bit Explorer), then `NTUSER.DAT`'s.
pub const LOCATIONS: [&str; 6] = [
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU",
    r"Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Wow6432Node\Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU",
    r"Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
];

/// How deep a tree is read: a real path has far fewer items, and a hive whose subkey lists lead
/// back up must not make the walk endless.
const MAX_DEPTH: usize = 512;

/// One item of a `BagMRU` tree: a numbered value, and its subkey when it has one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellBag {
    /// The `BagMRU` key of its tree, under the hive's root (one of [`LOCATIONS`]).
    pub location: &'static str,
    /// The numbers from `BagMRU` down to it: `[0, 3]` is value `3` of key `BagMRU\0`, and its
    /// subkey `BagMRU\0\3`.
    pub numbers: Vec<u32>,
    /// The item it is under, as an index into the items returned; `None` at the top of a tree.
    pub parent: Option<usize>,
    /// Its place in its parent key's `MRUListEx` (0: the most recently opened); `None` when the
    /// list doesn't have it.
    pub mru_position: Option<u32>,
    /// Its subkey's `NodeSlot`: the number of its `Bags` key.
    pub node_slot: Option<u32>,
    /// The value's data, a shell item list; `None` when there is no value: `MRUListEx` lists a
    /// number no value has, or a subkey has no value of its name.
    pub data: Option<Vec<u8>>,
    /// The last-write time (FILETIME) of the key the value is in: when it is at position 0,
    /// when it was last opened.
    pub parent_last_written: u64,
    /// The last-write time of its own subkey, when it has one: when its most recent item was
    /// opened.
    pub last_written: Option<u64>,
    /// Whether the value or its parent's `MRUListEx` came from the transaction logs.
    pub replayed: bool,
    /// What is wrong with it.
    pub problems: Vec<String>,
}

impl ShellBag {
    /// Its subkey's path under the hive's root (`…\BagMRU\0\3`).
    #[must_use]
    pub fn key_path(&self) -> String {
        let mut path = self.location.to_owned();
        for n in &self.numbers {
            path.push('\\');
            path.push_str(&n.to_string());
        }
        path
    }

    /// The path of the key its value is in (`…\BagMRU\0`).
    #[must_use]
    pub fn parent_key_path(&self) -> String {
        let mut path = self.location.to_owned();
        for n in &self.numbers[..self.numbers.len().saturating_sub(1)] {
            path.push('\\');
            path.push_str(&n.to_string());
        }
        path
    }
}

/// The items of every `BagMRU` tree in `hive`, each tree from the top down in `MRUListEx` order
/// (an item, then the items under it), with what keeps keys from being read (each starting with
/// the key's path). `None` when the hive has none of [`LOCATIONS`].
#[must_use]
pub fn shell_bags(hive: &Hive) -> Option<(Vec<ShellBag>, Vec<String>)> {
    let mut found = false;
    let mut walk = Walker {
        items: Vec::new(),
        problems: Vec::new(),
        visited: HashSet::new(),
    };
    for location in LOCATIONS {
        let Some(key) = hive.key(location) else {
            continue;
        };
        found = true;
        walk.visited.insert(key.offset());
        walk.key(&key, location, &[], None, 0);
    }
    found.then_some((walk.items, walk.problems))
}

struct Walker {
    items: Vec<ShellBag>,
    problems: Vec<String>,
    /// The keys read, by cell offset: a key reached twice is a loop.
    visited: HashSet<u32>,
}

impl Walker {
    /// The items of `key` (at `numbers` under `location`) and, under each, its subkey's.
    fn key(
        &mut self,
        key: &Key,
        location: &'static str,
        numbers: &[u32],
        parent: Option<usize>,
        depth: usize,
    ) {
        let path = path_of(location, numbers);
        let (ordered, list_replayed, problems) = mru_items(key, &["NodeSlot", "NodeSlots"]);
        self.problems
            .extend(problems.into_iter().map(|p| format!("{path}: {p}")));
        let (subkeys, problems) = key.subkeys();
        self.problems
            .extend(problems.into_iter().map(|p| format!("{path}: {p}")));
        let mut used = vec![false; subkeys.len()];
        // This key's items in order, each with its subkey; then each item and the items under
        // it, so that a tree reads from the top down.
        let mut level: Vec<(ShellBag, Option<Key>)> = Vec::new();
        for m in ordered {
            let mut bag = ShellBag {
                location,
                numbers: [numbers, &[m.n]].concat(),
                parent,
                mru_position: m.position,
                parent_last_written: key.last_written(),
                replayed: list_replayed,
                ..ShellBag::default()
            };
            bag.problems.extend(m.problem);
            if let Some(value) = m.value {
                let (bytes, problem) = value.read_data();
                if value.value_type() != ValueType::Binary {
                    bag.problems
                        .push(format!("is {}, not REG_BINARY", value.value_type().name()));
                }
                bag.problems.extend(problem);
                bag.replayed |= value.status() == Status::Replayed;
                bag.data = Some(bytes);
            }
            let name = m.n.to_string();
            let sub = subkeys
                .iter()
                .enumerate()
                .find(|(at, k)| !used[*at] && k.name() == name)
                .map(|(at, k)| {
                    used[at] = true;
                    *k
                });
            if let Some(sub) = &sub {
                subkey(&mut bag, sub);
            }
            level.push((bag, sub));
        }
        // A subkey whose value is gone still holds the items under it.
        for (at, sub) in subkeys.iter().enumerate() {
            if used[at] {
                continue;
            }
            let name = sub.name();
            let Some(n) = name.parse::<u32>().ok().filter(|n| n.to_string() == name) else {
                self.problems
                    .push(format!("{path}: subkey {name:?} is not a numbered item"));
                continue;
            };
            let mut bag = ShellBag {
                location,
                numbers: [numbers, &[n]].concat(),
                parent,
                parent_last_written: key.last_written(),
                problems: vec![format!(
                    "no value {n} in its parent key: its shell item is unknown"
                )],
                ..ShellBag::default()
            };
            subkey(&mut bag, sub);
            level.push((bag, Some(*sub)));
        }
        for (mut bag, sub) in level {
            let index = self.items.len();
            let numbers = bag.numbers.clone();
            let Some(sub) = sub else {
                self.items.push(bag);
                continue;
            };
            if depth + 1 >= MAX_DEPTH {
                bag.problems.push(format!(
                    "deeper than {MAX_DEPTH} items: the items under it are not read"
                ));
                self.items.push(bag);
            } else if self.visited.insert(sub.offset()) {
                self.items.push(bag);
                self.key(&sub, location, &numbers, Some(index), depth + 1);
            } else {
                bag.problems.push(
                    "its subkey is a key already read (the hive's subkey lists loop): the items under it are not read again"
                        .to_owned(),
                );
                self.items.push(bag);
            }
        }
    }
}

/// What an item's own subkey adds: its last-write time and `NodeSlot`.
fn subkey(bag: &mut ShellBag, sub: &Key) {
    bag.last_written = Some(sub.last_written());
    bag.replayed |= sub.status() == Status::Replayed;
    if let Some(slot) = sub.value("NodeSlot") {
        let (bytes, problem) = slot.read_data();
        bag.problems
            .extend(problem.map(|p| format!("NodeSlot: {p}")));
        match (slot.value_type(), u32_at(&bytes, 0)) {
            (ValueType::Dword, Some(n)) if bytes.len() == 4 => bag.node_slot = Some(n),
            (kind, n) => {
                bag.node_slot = n.filter(|_| bytes.len() == 4);
                bag.problems.push(format!(
                    "NodeSlot: is {} of {} bytes, not a REG_DWORD",
                    kind.name(),
                    bytes.len()
                ));
            }
        }
    }
}

/// `location` and the numbers of the keys under it, as a key path.
fn path_of(location: &str, numbers: &[u32]) -> String {
    let mut path = location.to_owned();
    for n in numbers {
        path.push('\\');
        path.push_str(&n.to_string());
    }
    path
}
