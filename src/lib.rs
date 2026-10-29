//! Windows registry hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat`,
//! `Amcache.hve`, ...) for forensics: every key with its last-write time and every value with its
//! type and data, a dirty hive's transaction logs replayed, and what each key and value came
//! from: in use, from the logs, or deleted (left in a free cell).
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (hive, recovery) = ys_registry_parser::open(std::path::Path::new("SYSTEM"))?;
//! if recovery.dirty && !recovery.recovered {
//!     eprintln!("dirty, without usable logs: keys or values may be missing");
//! }
//! for entry in hive.walk() {
//!     let (values, _problems) = entry.key.values();
//!     for value in values {
//!         let data = ys_registry_parser::decode(value.data_type(), &value.data()?);
//!         println!("{}\\{} = {data:?}", entry.path, value.name());
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The format is Maxim Suhanov's *Windows registry file format specification*
//! (<https://github.com/msuhanov/regf>, CC BY 4.0). Damage is reported, never a panic: see
//! [`Key::subkeys`], [`Key::values`] and [`Value::read_data`].

mod bytes;
mod data;
mod deleted;
mod hive;
mod log;
pub mod system;

use std::path::Path;

pub use data::{Data, ValueType, decode, filetime};
pub use deleted::{Deleted, DeletedKey, DeletedValue};
pub use hive::{Error, Header, Hive, Key, KeyEntry, Status, Value, Walk};
pub use log::{LogFile, Recovery, find_logs};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Larger files are not hives: Windows limits a hive to 2 GiB.
const MAX_HIVE_SIZE: u64 = 2 * 1024 * 1024 * 1024 + 4096;

/// Open the hive file at `path`, with the transaction logs next to it ([`find_logs`]) replayed
/// when it is dirty.
///
/// # Errors
/// When the file can't be read, is too large to be a hive, or isn't one.
pub fn open(path: &Path) -> Result<(Hive, Recovery), Error> {
    open_with(path, &find_logs(path))
}

/// [`open`], with `logs` as the transaction logs (none: the hive as it is).
///
/// # Errors
/// When the file can't be read, is too large to be a hive, or isn't one.
pub fn open_with(path: &Path, logs: &[LogFile]) -> Result<(Hive, Recovery), Error> {
    let size = path.metadata().map_err(|e| Error(e.to_string()))?.len();
    if size > MAX_HIVE_SIZE {
        return Err(Error(format!(
            "too large for a registry hive ({size} bytes)"
        )));
    }
    let bytes = std::fs::read(path).map_err(|e| Error(e.to_string()))?;
    Hive::open(bytes, logs)
}
