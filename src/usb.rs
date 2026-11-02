//! Removable devices and the volumes they held, from `SYSTEM`, `SOFTWARE` and `NTUSER.DAT`:
//!
//! - USB storage (`Enum\USBSTOR`), USB devices (`Enum\USB`) and portable devices
//!   (`Enum\SWD\WPDBUSENUM`) of a control set, with their install, arrival and removal times
//!   ([`devices`]);
//! - the drive letters and volume GUIDs `MountedDevices` gives volumes ([`mounted_devices`]);
//! - the names Explorer gave portable devices and volumes (`SOFTWARE`'s `Windows Portable
//!   Devices`, [`portable_devices`]) and volume serial numbers (`ReadyBoost`'s `EMDMgmt`,
//!   [`ready_boost`]);
//! - the volumes a user had mounted (`NTUSER.DAT`'s `MountPoints2`, [`mount_points`]).
//!
//! [`history`] joins them: one record per device, and per volume no device key names.
//!
//! A device's times are device properties under `Properties\{83da6326-97a6-4088-9453-a1923f573b29}`,
//! as `devpkey.h` numbers them: 0x64 `DEVPKEY_Device_InstallDate`, 0x65
//! `DEVPKEY_Device_FirstInstallDate`, 0x66 `DEVPKEY_Device_LastArrivalDate` and 0x67
//! `DEVPKEY_Device_LastRemovalDate`. Windows 8 and later keep each as the default value of a key
//! named `0064` … `0067` (of type `0xffff0010`: `DEVPROP_TYPE_FILETIME`); Windows 7 as the `Data`
//! value of a `00000064\00000000` key.

use crate::bytes::{u32_at, u64_at};
use crate::data::filetime;
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{control_set_name, string};

/// The device properties with the install, arrival and removal times.
pub const DEVICE_TIMES: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";
/// `DEVPROP_TYPE_FILETIME`, as the registry types a device property's value.
const DEVPROP_FILETIME: u32 = 0xffff_0010;
/// The null container ID Windows gives a device that is part of the computer.
const NULL_CONTAINER: &str = "{00000000-0000-0000-ffff-ffffffffffff}";
/// Where `SOFTWARE` keeps portable devices.
const PORTABLE_DEVICES: &str = r"Microsoft\Windows Portable Devices\Devices";
/// Where `SOFTWARE` keeps the devices `ReadyBoost` tested.
const EMD_MGMT: &str = r"Microsoft\Windows NT\CurrentVersion\EMDMgmt";
/// Where `NTUSER.DAT` keeps the volumes and shares a user had mounted.
const MOUNT_POINTS2: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2";

/// Where in a control set's `Enum` a device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceClass {
    /// `Enum\USBSTOR`: USB mass storage (a disk, a CD-ROM, …), one key per logical unit.
    UsbStorage,
    /// `Enum\USB`: a USB device (a storage device's USB side, a hub, a phone, a mouse, …).
    Usb,
    /// `Enum\SWD\WPDBUSENUM`: a portable device (a volume or a phone Explorer shows as one).
    PortableDevice,
}

impl DeviceClass {
    /// `usbstor`, `usb`, `wpdbusenum`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            DeviceClass::UsbStorage => "usbstor",
            DeviceClass::Usb => "usb",
            DeviceClass::PortableDevice => "wpdbusenum",
        }
    }

    /// The key under `Enum`.
    fn path(self) -> &'static str {
        match self {
            DeviceClass::UsbStorage => "USBSTOR",
            DeviceClass::Usb => "USB",
            DeviceClass::PortableDevice => r"SWD\WPDBUSENUM",
        }
    }
}

/// A device a device path or a key name names (`\??\USBSTOR#Disk&Ven_…#<serial>&0#{…}`): its
/// enumerator, device and instance, as written.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceRef {
    /// `USBSTOR`, `USB`, `SCSI`, `STORAGE`, ….
    pub enumerator: String,
    /// The device: `Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26`, `VID_0781&PID_5567`.
    pub device: String,
    /// The instance: a serial number (with `&<n>`, the logical unit, for USB storage), or one
    /// Windows made up for a device that reports none.
    pub instance: String,
}

impl DeviceRef {
    /// Whether `other` names the same device, in any case.
    #[must_use]
    pub fn same(&self, other: &DeviceRef) -> bool {
        self.enumerator.eq_ignore_ascii_case(&other.enumerator)
            && self.device.eq_ignore_ascii_case(&other.device)
            && self.instance.eq_ignore_ascii_case(&other.instance)
    }
}

/// The device a device path names. One that wraps another (`STORAGE#Volume#_??_USBSTOR#…`,
/// `WPDBUSENUMROOT#UMB#…#STORAGE#VOLUME#_??_USBSTOR#…`, `SWD#WPDBUSENUM#_??_USB#…`) names the
/// USB storage device in it, else the USB device, else the SCSI device, else its first.
#[must_use]
pub fn device_ref(path: &str) -> Option<DeviceRef> {
    let parts: Vec<&str> = path.split('#').map(strip_prefix).collect();
    let find = |enumerator: &str| {
        parts
            .iter()
            .rposition(|p| p.eq_ignore_ascii_case(enumerator))
    };
    let at = find("USBSTOR")
        .or_else(|| find("USB"))
        .or_else(|| find("SCSI"))
        .or_else(|| parts.iter().position(|p| !p.is_empty()))?;
    let device = parts.get(at + 1).filter(|p| !p.is_empty())?;
    let instance = parts.get(at + 2).filter(|p| !p.is_empty())?;
    Some(DeviceRef {
        enumerator: parts[at].to_owned(),
        device: (*device).to_owned(),
        instance: (*instance).to_owned(),
    })
}

/// A path part without the `\??\`, `_??_` or `\\?\` it starts with.
fn strip_prefix(part: &str) -> &str {
    for prefix in [r"\??\", "_??_", r"\\?\"] {
        if let Some(rest) = part.strip_prefix(prefix) {
            return rest;
        }
    }
    part
}

/// The parts of a USB storage device's name, `Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26`: its type
/// (`Disk`, `CdRom`, `Other`), vendor, product and revision; empty ones are `None`.
#[must_use]
pub fn storage_name(device: &str) -> [Option<String>; 4] {
    let mut parts = device.split('&');
    let kind = parts.next().filter(|k| !k.is_empty()).map(str::to_owned);
    let (mut vendor, mut product, mut revision) = (None, None, None);
    for part in parts {
        let field = |prefix: &str| {
            part.get(..prefix.len())
                .filter(|p| p.eq_ignore_ascii_case(prefix))
                .map(|_| part[prefix.len()..].to_owned())
                .filter(|v| !v.is_empty())
        };
        if let Some(v) = field("Ven_") {
            vendor = Some(v);
        } else if let Some(p) = field("Prod_") {
            product = Some(p);
        } else if let Some(r) = field("Rev_") {
            revision = Some(r);
        }
    }
    [kind, vendor, product, revision]
}

/// A USB device's vendor and product IDs from its name, `VID_0781&PID_5567&MI_00`: `0781`,
/// `5567`.
#[must_use]
pub fn vid_pid(device: &str) -> (Option<String>, Option<String>) {
    let mut vid = None;
    let mut pid = None;
    for part in device.split('&') {
        let field = |prefix: &str| {
            part.get(..prefix.len())
                .filter(|p| p.eq_ignore_ascii_case(prefix))
                .map(|_| part[prefix.len()..].to_owned())
                .filter(|v| !v.is_empty())
        };
        vid = vid.or_else(|| field("VID_"));
        pid = pid.or_else(|| field("PID_"));
    }
    (vid, pid)
}

/// The serial number in an instance: the instance without a USB storage device's `&<n>` (its
/// logical unit); `None` when Windows made the instance up (its second character is `&`), for
/// a device that reports no serial number.
#[must_use]
pub fn serial(enumerator: &str, instance: &str) -> Option<String> {
    if instance.is_empty() || instance.as_bytes().get(1) == Some(&b'&') {
        return None;
    }
    let serial = if enumerator.eq_ignore_ascii_case("USBSTOR") {
        match instance.rsplit_once('&') {
            Some((serial, lun))
                if !serial.is_empty()
                    && !lun.is_empty()
                    && lun.bytes().all(|b| b.is_ascii_digit()) =>
            {
                serial
            }
            _ => instance,
        }
    } else {
        instance
    };
    Some(serial.to_owned())
}

/// A device: an instance key under a control set's `Enum\USBSTOR\<device>`, `Enum\USB\<device>`
/// or `Enum\SWD\WPDBUSENUM`. A value it hasn't is `None`; one that can't be read, or isn't of
/// its type, is `None` and a problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Where in `Enum` it is.
    pub class: DeviceClass,
    /// Its control set's number.
    pub control_set: u32,
    /// Its instance key's path: `ControlSet001\Enum\USBSTOR\Disk&Ven_…\<instance>`.
    pub path: String,
    /// The device it is, or, for a portable device, the device its instance names (the USB
    /// storage device or USB device it was enumerated from).
    pub reference: Option<DeviceRef>,
    /// USB storage: its type (`Disk`, `CdRom`, `Other`).
    pub kind: Option<String>,
    /// USB storage: the vendor in its name.
    pub vendor: Option<String>,
    /// USB storage: the product in its name.
    pub product: Option<String>,
    /// USB storage: the revision in its name.
    pub revision: Option<String>,
    /// USB: its vendor ID (`0781`).
    pub vid: Option<String>,
    /// USB: its product ID (`5567`).
    pub pid: Option<String>,
    /// Its serial number ([`serial`]).
    pub serial: Option<String>,
    /// `FriendlyName` (a portable device's: the name Explorer shows, often its volume's).
    pub friendly_name: Option<String>,
    /// `DeviceDesc`, as written (often `@<inf>,%…%;<text>`).
    pub device_desc: Option<String>,
    /// `Mfg`, as written.
    pub manufacturer: Option<String>,
    /// `ContainerID`: the physical device it is part of.
    pub container_id: Option<String>,
    /// `Driver`: its driver key under `Control\Class`.
    pub driver: Option<String>,
    /// `Service`.
    pub service: Option<String>,
    /// `LocationInformation`.
    pub location: Option<String>,
    /// When its driver was last installed (property 0x64, FILETIME).
    pub install: Option<u64>,
    /// When it was first installed (property 0x65, FILETIME).
    pub first_install: Option<u64>,
    /// When it last arrived (property 0x66, FILETIME; Windows 8 and later).
    pub last_arrival: Option<u64>,
    /// When it was last removed (property 0x67, FILETIME; Windows 8 and later).
    pub last_removal: Option<u64>,
    /// When its instance key was last written (FILETIME).
    pub last_written: u64,
    /// Whether the transaction logs' replay wrote its key or a value read.
    pub replayed: bool,
    /// What couldn't be read, and data that isn't what it should be (with its bytes in hex).
    pub problems: Vec<String>,
}

/// The devices of control set `set` (`ControlSet001` for 1): USB storage, USB, then portable
/// devices, each in key order; with them what keeps keys from being read. `None` when the
/// control set has no `Enum` key.
#[must_use]
pub fn devices(hive: &Hive, set: u32) -> Option<(Vec<Device>, Vec<String>)> {
    let control_set = control_set_name(set);
    let enumerated = hive.key(&format!(r"{control_set}\Enum"))?;
    let mut devices = Vec::new();
    let mut problems = Vec::new();
    for class in [
        DeviceClass::UsbStorage,
        DeviceClass::Usb,
        DeviceClass::PortableDevice,
    ] {
        let Some(key) = class
            .path()
            .split('\\')
            .try_fold(enumerated, |key, part| key.subkey(part))
        else {
            continue;
        };
        let base = format!(r"{control_set}\Enum\{}", class.path());
        let (subkeys, why) = key.subkeys();
        problems.extend(why.into_iter().map(|w| format!("{base}: {w}")));
        if class == DeviceClass::PortableDevice {
            // a portable device's instance is the key itself
            for instance in &subkeys {
                devices.push(device(class, set, &base, None, instance));
            }
            continue;
        }
        for device_key in &subkeys {
            let name = device_key.name();
            let (instances, why) = device_key.subkeys();
            problems.extend(why.into_iter().map(|w| format!(r"{base}\{name}: {w}")));
            for instance in &instances {
                devices.push(device(class, set, &base, Some(&name), instance));
            }
        }
    }
    Some((devices, problems))
}

/// The device whose instance key is `key`, under `base` (and `device`, but for portable
/// devices).
fn device(class: DeviceClass, set: u32, base: &str, device: Option<&str>, key: &Key) -> Device {
    let instance = key.name();
    let path = match device {
        Some(device) => format!(r"{base}\{device}\{instance}"),
        None => format!(r"{base}\{instance}"),
    };
    let reference = match device {
        Some(device) => Some(DeviceRef {
            enumerator: class.path().to_owned(),
            device: device.to_owned(),
            instance: instance.clone(),
        }),
        None => device_ref(&instance),
    };
    let mut d = Device {
        class,
        control_set: set,
        path,
        reference: None,
        kind: None,
        vendor: None,
        product: None,
        revision: None,
        vid: None,
        pid: None,
        serial: None,
        friendly_name: None,
        device_desc: None,
        manufacturer: None,
        container_id: None,
        driver: None,
        service: None,
        location: None,
        install: None,
        first_install: None,
        last_arrival: None,
        last_removal: None,
        last_written: key.last_written(),
        replayed: key.status() == Status::Replayed,
        problems: Vec::new(),
    };
    if let Some(r) = &reference {
        if r.enumerator.eq_ignore_ascii_case("USBSTOR") {
            let [kind, vendor, product, revision] = storage_name(&r.device);
            (d.kind, d.vendor, d.product, d.revision) = (kind, vendor, product, revision);
        } else {
            (d.vid, d.pid) = vid_pid(&r.device);
        }
        d.serial = serial(&r.enumerator, &r.instance);
    }
    d.reference = reference;
    let (values, why) = key.values();
    d.problems.extend(why);
    for value in &values {
        let slot = match value.name().to_ascii_lowercase().as_str() {
            "friendlyname" => &mut d.friendly_name,
            "devicedesc" => &mut d.device_desc,
            "mfg" => &mut d.manufacturer,
            "containerid" => &mut d.container_id,
            "driver" => &mut d.driver,
            "service" => &mut d.service,
            "locationinformation" => &mut d.location,
            _ => continue,
        };
        let (text, why) = string(value);
        *slot = text;
        d.replayed |= value.status() == Status::Replayed;
        if let Some(why) = why {
            d.problems.push(format!("{}: {why}", value.name()));
        }
    }
    device_times(key, &mut d);
    d
}

/// The install, arrival and removal times under `key`'s `Properties`.
fn device_times(key: &Key, d: &mut Device) {
    let Some(properties) = key
        .subkey("Properties")
        .and_then(|p| p.subkey(DEVICE_TIMES))
    else {
        return;
    };
    d.replayed |= properties.status() == Status::Replayed;
    let (subkeys, why) = properties.subkeys();
    d.problems.extend(
        why.into_iter()
            .map(|w| format!(r"Properties\{DEVICE_TIMES}: {w}")),
    );
    for property in &subkeys {
        let name = property.name();
        let id = u32::from_str_radix(&name, 16).ok().filter(|_| {
            (name.len() == 4 || name.len() == 8) && name.bytes().all(|b| b.is_ascii_hexdigit())
        });
        let slot = match id {
            Some(0x64) => &mut d.install,
            Some(0x65) => &mut d.first_install,
            Some(0x66) => &mut d.last_arrival,
            Some(0x67) => &mut d.last_removal,
            _ => continue,
        };
        let at = format!(r"Properties\{DEVICE_TIMES}\{name}");
        match property_filetime(property) {
            Ok((time, replayed)) => {
                d.replayed |= replayed;
                match time {
                    Some(t) if t != 0 && filetime(t).is_none() => {
                        d.problems
                            .push(format!("{at}: FILETIME 0x{t:016x} is past 9999"));
                    }
                    Some(t) if t != 0 => *slot = Some(t),
                    _ => {}
                }
            }
            Err(why) => d.problems.push(format!("{at}: {why}")),
        }
    }
}

/// A device property's FILETIME: the key's default value (Windows 8 and later), else the `Data`
/// value of its `00000000` subkey (Windows 7); `None` when it has neither. With it whether the
/// replay wrote what was read.
fn property_filetime(key: &Key) -> Result<(Option<u64>, bool), String> {
    let mut replayed = key.status() == Status::Replayed;
    let value = if let Some(value) = key.value("") {
        value
    } else {
        let Some(item) = key.subkey("00000000") else {
            return Ok((None, replayed));
        };
        replayed |= item.status() == Status::Replayed;
        let Some(value) = item.value("Data") else {
            return Ok((None, replayed));
        };
        value
    };
    replayed |= value.status() == Status::Replayed;
    let (bytes, why) = value.read_data();
    if let Some(why) = why {
        return Err(format!("{why} ({})", hex(&bytes)));
    }
    let typed = matches!(
        value.data_type(),
        DEVPROP_FILETIME | 0x10 | 3 | 11 // DEVPROP_TYPE_FILETIME, Data's REG_BINARY, REG_QWORD
    );
    match u64_at(&bytes, 0) {
        Some(time) if typed && bytes.len() == 8 => Ok((Some(time), replayed)),
        _ => Err(format!(
            "type 0x{:x} of {} bytes, not a FILETIME ({})",
            value.data_type(),
            bytes.len(),
            hex(&bytes)
        )),
    }
}

/// Bytes in hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// What a `MountedDevices` value's data says a volume is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountTarget {
    /// A partition of an MBR disk: the disk's signature and the partition's offset in bytes
    /// (12 bytes).
    Mbr {
        /// The disk signature.
        signature: u32,
        /// The partition's offset on the disk, in bytes.
        offset: u64,
    },
    /// A GPT partition, by its GUID (`DMIO:ID:` and 16 bytes).
    Gpt(String),
    /// A device path (UTF-16): `\??\USBSTOR#Disk&Ven_…#<serial>&0#{53f56307-…}`, `_??_USBSTOR#…`.
    Path(String),
    /// None of these: the bytes are in [`MountedDevice::data`].
    Other,
}

/// A `MountedDevices` value: a drive letter's or a volume GUID's volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedDevice {
    /// The value's name: `\DosDevices\E:`, `\??\Volume{…}`, `#{…}`.
    pub name: String,
    /// The drive letter of a `\DosDevices\X:` value.
    pub drive_letter: Option<char>,
    /// The `{GUID}` of a `\??\Volume{GUID}` value.
    pub volume_guid: Option<String>,
    /// What the data says the volume is on.
    pub target: MountTarget,
    /// The device a [`MountTarget::Path`] names ([`device_ref`]).
    pub reference: Option<DeviceRef>,
    /// The data: values with the same data name the same volume.
    pub data: Vec<u8>,
    /// Whether the transaction logs' replay wrote the value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The values of `MountedDevices`, in order, and what keeps others from being read; `None`
/// when the hive has no `MountedDevices` key.
#[must_use]
pub fn mounted_devices(hive: &Hive) -> Option<(Vec<MountedDevice>, Vec<String>)> {
    let key = hive.key("MountedDevices")?;
    let (values, problems) = key.values();
    Some((values.iter().map(mounted_device).collect(), problems))
}

/// The `MountedDevices` value `value`.
fn mounted_device(value: &Value) -> MountedDevice {
    let name = value.name();
    let (data, why) = value.read_data();
    let target = mount_target(&data);
    let reference = match &target {
        MountTarget::Path(path) => device_ref(path),
        _ => None,
    };
    MountedDevice {
        drive_letter: drive_letter(&name),
        volume_guid: volume_guid(&name),
        name,
        target,
        reference,
        data,
        replayed: value.status() == Status::Replayed,
        problems: why.into_iter().collect(),
    }
}

/// The letter of `\DosDevices\X:`.
fn drive_letter(name: &str) -> Option<char> {
    let rest = name
        .get(..12)
        .filter(|p| p.eq_ignore_ascii_case(r"\DosDevices\"))
        .map(|_| &name[12..])?;
    let mut chars = rest.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(letter), Some(':'), None) if letter.is_ascii_alphabetic() => {
            Some(letter.to_ascii_uppercase())
        }
        _ => None,
    }
}

/// The `{GUID}` of `\??\Volume{GUID}`.
fn volume_guid(name: &str) -> Option<String> {
    let rest = name
        .get(..10)
        .filter(|p| p.eq_ignore_ascii_case(r"\??\Volume"))
        .map(|_| &name[10..])?;
    is_guid(rest).then(|| rest.to_owned())
}

/// Whether `text` is a `{GUID}`.
fn is_guid(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, &c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// What `MountedDevices` data says a volume is on.
#[must_use]
pub fn mount_target(data: &[u8]) -> MountTarget {
    if data.len() == 12
        && let (Some(signature), Some(offset)) = (u32_at(data, 0), u64_at(data, 4))
    {
        return MountTarget::Mbr { signature, offset };
    }
    if data.len() == 24
        && data.starts_with(b"DMIO:ID:")
        && let Some(guid) = guid_of(&data[8..])
    {
        return MountTarget::Gpt(guid);
    }
    if data.len() >= 8 && data.len().is_multiple_of(2) {
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|u| u16::from_le_bytes(*u))
            .collect();
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        if let Ok(path) = String::from_utf16(&units[..end])
            && units[end..].iter().all(|&u| u == 0)
            && path.starts_with(['\\', '_', '#'])
            && !path.chars().any(char::is_control)
        {
            return MountTarget::Path(path);
        }
    }
    MountTarget::Other
}

/// A GUID's 16 bytes as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
fn guid_of(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.try_into().ok()?;
    let data1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let data2 = u16::from_le_bytes([b[4], b[5]]);
    let data3 = u16::from_le_bytes([b[6], b[7]]);
    Some(format!(
        "{{{data1:08x}-{data2:04x}-{data3:04x}-{}-{}}}",
        hex(&b[8..10]),
        hex(&b[10..])
    ))
}

/// A portable device `SOFTWARE` keeps (`Microsoft\Windows Portable Devices\Devices\<key>`): the
/// name Explorer gave it, often its volume's (`E:\`, a label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableDevice {
    /// The key's name: a device path with `#` for `\`
    /// (`WPDBUSENUMROOT#UMB#…#_??_USBSTOR#DISK&VEN_…#<serial>&0#`, `USB#VID_…#<serial>`).
    pub key: String,
    /// The device it names ([`device_ref`]).
    pub reference: Option<DeviceRef>,
    /// `FriendlyName`.
    pub friendly_name: Option<String>,
    /// When the key was last written (FILETIME).
    pub last_written: u64,
    /// Whether the transaction logs' replay wrote the key or its `FriendlyName`.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The portable devices of a `SOFTWARE` hive, in key order, and what keeps others from being
/// read; `None` when it has no such key.
#[must_use]
pub fn portable_devices(hive: &Hive) -> Option<(Vec<PortableDevice>, Vec<String>)> {
    let key = hive.key(PORTABLE_DEVICES)?;
    let (subkeys, problems) = key.subkeys();
    let devices = subkeys
        .iter()
        .map(|k| {
            let name = k.name();
            let mut d = PortableDevice {
                reference: device_ref(&name),
                key: name,
                friendly_name: None,
                last_written: k.last_written(),
                replayed: k.status() == Status::Replayed,
                problems: Vec::new(),
            };
            let (values, why) = k.values();
            d.problems.extend(why);
            if let Some(value) = values
                .iter()
                .find(|v| v.name().eq_ignore_ascii_case("FriendlyName"))
            {
                let (text, why) = string(value);
                d.friendly_name = text.filter(|t| !t.is_empty());
                d.replayed |= value.status() == Status::Replayed;
                d.problems.extend(why.map(|w| format!("FriendlyName: {w}")));
            }
            d
        })
        .collect();
    Some((devices, problems))
}

/// A device `ReadyBoost` tested (`SOFTWARE`'s `EMDMgmt\<key>`). The key's name is the device's
/// path, then the volume's label and its serial number in decimal:
/// `_??_USBSTOR#Disk&Ven_…#<serial>&0#{53f56307-…}<label>_<volume serial>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyBoostDevice {
    /// The key's name.
    pub key: String,
    /// The device it names ([`device_ref`]).
    pub reference: Option<DeviceRef>,
    /// The volume's label.
    pub volume_name: Option<String>,
    /// The volume's serial number.
    pub volume_serial: Option<u32>,
    /// When the key was last written (FILETIME).
    pub last_written: u64,
    /// Whether the transaction logs' replay wrote the key.
    pub replayed: bool,
    /// What doesn't decode.
    pub problems: Vec<String>,
}

/// The devices of a `SOFTWARE` hive's `EMDMgmt`, in key order, and what keeps others from being
/// read; `None` when it has no such key.
#[must_use]
pub fn ready_boost(hive: &Hive) -> Option<(Vec<ReadyBoostDevice>, Vec<String>)> {
    let key = hive.key(EMD_MGMT)?;
    let (subkeys, problems) = key.subkeys();
    let devices = subkeys
        .iter()
        .map(|k| {
            let name = k.name();
            let (volume_name, volume_serial, problem) = ready_boost_volume(&name);
            ReadyBoostDevice {
                reference: name.contains('#').then(|| device_ref(&name)).flatten(),
                key: name,
                volume_name,
                volume_serial,
                last_written: k.last_written(),
                replayed: k.status() == Status::Replayed,
                problems: problem.into_iter().collect(),
            }
        })
        .collect();
    Some((devices, problems))
}

/// The volume label and serial number at the end of an `EMDMgmt` key's name, and why the serial
/// doesn't decode.
fn ready_boost_volume(name: &str) -> (Option<String>, Option<u32>, Option<String>) {
    let tail = name.rsplit_once('}').map_or(name, |(_, tail)| tail);
    let Some((label, number)) = tail.rsplit_once('_') else {
        return (
            None,
            None,
            Some(format!("no volume serial number in {tail:?}")),
        );
    };
    let label = (!label.is_empty()).then(|| label.to_owned());
    match number.parse::<u32>() {
        Ok(n) if number.bytes().all(|b| b.is_ascii_digit()) => (label, Some(n), None),
        _ => (
            label,
            None,
            Some(format!(
                "volume serial number {number:?} is not a 32-bit number"
            )),
        ),
    }
}

/// A key of a user's `MountPoints2`: a volume, a share or a drive the user had mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPoint {
    /// The key's name: `{GUID}`, `##server#share`, a drive letter.
    pub name: String,
    /// The volume GUID of a `{GUID}` key.
    pub volume_guid: Option<String>,
    /// The server of a `##server#share` key.
    pub server: Option<String>,
    /// The share of a `##server#share` key (`\share\folder`).
    pub share: Option<String>,
    /// `_LabelFromReg`: a label the user gave it.
    pub label: Option<String>,
    /// When the key was last written (FILETIME): when the user last had it mounted, as a rule.
    pub last_written: u64,
    /// Whether the transaction logs' replay wrote the key.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The keys of a user's `MountPoints2`, in order, and what keeps others from being read; `None`
/// when the hive has no `MountPoints2` key.
#[must_use]
pub fn mount_points(hive: &Hive) -> Option<(Vec<MountPoint>, Vec<String>)> {
    let key = hive.key(MOUNT_POINTS2)?;
    let (subkeys, problems) = key.subkeys();
    let points = subkeys
        .iter()
        .map(|k| {
            let name = k.name();
            let (server, share) = match name.strip_prefix("##") {
                Some(rest) => {
                    let (server, share) = rest.split_once('#').unwrap_or((rest, ""));
                    (
                        Some(server.to_owned()),
                        (!share.is_empty()).then(|| format!(r"\{}", share.replace('#', r"\"))),
                    )
                }
                None => (None, None),
            };
            let mut point = MountPoint {
                volume_guid: is_guid(&name).then(|| name.clone()),
                name,
                server,
                share,
                label: None,
                last_written: k.last_written(),
                replayed: k.status() == Status::Replayed,
                problems: Vec::new(),
            };
            if let Some(value) = k.value("_LabelFromReg") {
                let (text, why) = string(&value);
                point.label = text.filter(|t| !t.is_empty());
                point
                    .problems
                    .extend(why.map(|w| format!("_LabelFromReg: {w}")));
            }
            point
        })
        .collect();
    Some((points, problems))
}

/// What [`history`] joins: decoded by [`devices`] and [`mounted_devices`] (`SYSTEM`),
/// [`portable_devices`] and [`ready_boost`] (`SOFTWARE`), and [`mount_points`] (each user's
/// `NTUSER.DAT`, with the user's name).
#[derive(Debug, Clone, Copy, Default)]
pub struct Sources<'a> {
    /// The devices, of one or more control sets.
    pub devices: &'a [Device],
    /// `MountedDevices`.
    pub mounted: &'a [MountedDevice],
    /// `Windows Portable Devices`.
    pub portable: &'a [PortableDevice],
    /// `EMDMgmt`.
    pub ready_boost: &'a [ReadyBoostDevice],
    /// Each user's name and `MountPoints2`.
    pub users: &'a [(String, Vec<MountPoint>)],
}

/// A user who had a volume mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMount {
    /// The user's name, as [`Sources::users`] gives it.
    pub user: String,
    /// When the user's `MountPoints2\{GUID}` key was last written (FILETIME).
    pub last_written: u64,
}

/// One device with one of its volumes, or a volume no device key names, as [`history`] joins
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    /// The device: `None` for a volume that only `MountedDevices`, `MountPoints2` or `SOFTWARE`
    /// knows (an internal disk's, or one whose device key is gone).
    pub device: Option<Device>,
    /// For a volume without a device: the device its `MountedDevices` data or its `SOFTWARE`
    /// key names.
    pub named: Option<DeviceRef>,
    /// USB storage: the vendor and product IDs of the USB device with its container ID or its
    /// serial number.
    pub vid_pid: Option<(Option<String>, Option<String>)>,
    /// The volume's GUID (`\??\Volume{GUID}`).
    pub volume_guid: Option<String>,
    /// The drive letters whose `MountedDevices` data is the volume's: the letters last given
    /// to it.
    pub drive_letters: Vec<char>,
    /// The `MountedDevices` data of the volume.
    pub mount_target: Option<MountTarget>,
    /// The names Explorer gave the device or its volume (`Windows Portable Devices` and portable
    /// devices' `FriendlyName`), and `ReadyBoost`'s volume labels.
    pub volume_names: Vec<String>,
    /// The volume serial numbers in `ReadyBoost`'s keys.
    pub volume_serials: Vec<u32>,
    /// The users with the volume in their `MountPoints2`.
    pub users: Vec<UserMount>,
    /// Where it was found: `Enum`, `MountedDevices`, `Windows Portable Devices`, `EMDMgmt`,
    /// `MountPoints2`.
    pub found_in: Vec<&'static str>,
    /// The keys and values it was joined from, each with its hive:
    /// `SYSTEM ControlSet001\Enum\USBSTOR\…`, `SYSTEM MountedDevices: \??\Volume{…}`,
    /// `SOFTWARE Microsoft\Windows Portable Devices\Devices\…`, `NTUSER.DAT (<user>) …\MountPoints2\{…}`.
    pub keys: Vec<String>,
    /// Whether the transaction logs' replay wrote what it was joined from, by hive:
    /// `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`.
    pub replayed_in: Vec<&'static str>,
    /// What couldn't be read in what it was joined from.
    pub problems: Vec<String>,
}

impl History {
    fn new(device: Option<Device>, named: Option<DeviceRef>) -> Self {
        let mut found_in = Vec::new();
        let mut keys = Vec::new();
        let mut replayed_in = Vec::new();
        let mut problems = Vec::new();
        if let Some(d) = &device {
            found_in.push("Enum");
            keys.push(format!("SYSTEM {}", d.path));
            if d.replayed {
                replayed_in.push("SYSTEM");
            }
            problems.clone_from(&d.problems);
        }
        History {
            device,
            named,
            vid_pid: None,
            volume_guid: None,
            drive_letters: Vec::new(),
            mount_target: None,
            volume_names: Vec::new(),
            volume_serials: Vec::new(),
            users: Vec::new(),
            found_in,
            keys,
            replayed_in,
            problems,
        }
    }

    fn found(&mut self, place: &'static str, hive: &'static str, key: String, replayed: bool) {
        if !self.found_in.contains(&place) {
            self.found_in.push(place);
        }
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
        if replayed && !self.replayed_in.contains(&hive) {
            self.replayed_in.push(hive);
        }
    }
}

/// The USB storage device a device is or names: what its volumes are found by.
fn storage_of(reference: Option<&DeviceRef>) -> Option<&DeviceRef> {
    reference.filter(|r| r.enumerator.eq_ignore_ascii_case("USBSTOR"))
}

/// Whether `a` and `b` name the same device.
fn names(a: Option<&DeviceRef>, b: Option<&DeviceRef>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a.same(b))
}

/// Join the devices with their volumes: one record per device and volume GUID of its (a device
/// without one: one record), then one per volume of `MountedDevices` no device has, per volume
/// only users' `MountPoints2` have, and per device only `SOFTWARE` names.
///
/// A USB storage device's volumes are the `\??\Volume{GUID}` values whose data is a path that
/// names it, and their drive letters the `\DosDevices\X:` values with the same data. Volume
/// names come from `Windows Portable Devices` and portable devices that name the same device,
/// serial numbers and labels from `EMDMgmt` keys that do, and users from the `MountPoints2`
/// keys of the volume's GUID. A USB storage device takes its vendor and product IDs from the
/// USB device with its container ID (but the null one) or, without one, its serial number.
#[must_use]
pub fn history(sources: &Sources) -> Vec<History> {
    let mut join = Join {
        sources,
        used_volumes: vec![false; sources.mounted.len()],
        used_portable: vec![false; sources.portable.len()],
        used_boost: vec![false; sources.ready_boost.len()],
    };
    let mut out = Vec::new();
    for device in sources.devices {
        join.device(device, &mut out);
    }
    join.unlinked_volumes(&mut out);
    out.extend(users_only(sources));
    join.software_only(&mut out);
    out
}

/// What [`history`] has joined so far.
struct Join<'s, 'a> {
    sources: &'s Sources<'a>,
    used_volumes: Vec<bool>,
    used_portable: Vec<bool>,
    used_boost: Vec<bool>,
}

impl Join<'_, '_> {
    /// The records of `device`: one per volume of its.
    fn device(&mut self, device: &Device, out: &mut Vec<History>) {
        let storage = storage_of(device.reference.as_ref());
        let mut base = History::new(Some(device.clone()), None);
        if device.class == DeviceClass::UsbStorage {
            base.vid_pid = usb_ids(device, self.sources.devices);
            for other in self.sources.devices.iter().filter(|o| {
                o.class == DeviceClass::PortableDevice && names(o.reference.as_ref(), storage)
            }) {
                add_name(&mut base.volume_names, other.friendly_name.as_deref());
            }
        }
        self.software(&mut base, device.reference.as_ref(), storage);
        let volumes: Vec<usize> = self
            .sources
            .mounted
            .iter()
            .enumerate()
            .filter(|(_, m)| m.volume_guid.is_some() && names(m.reference.as_ref(), storage))
            .map(|(i, _)| i)
            .collect();
        if volumes.is_empty() {
            out.push(base);
            return;
        }
        for i in volumes {
            self.used_volumes[i] = true;
            let mut record = base.clone();
            add_volume(&mut record, self.sources, i);
            out.push(record);
        }
    }

    /// Add what `SOFTWARE` says of the device `own`, or of USB storage device `storage`: the
    /// portable devices that name either, and the `ReadyBoost` keys that name `storage`.
    fn software(
        &mut self,
        record: &mut History,
        own: Option<&DeviceRef>,
        storage: Option<&DeviceRef>,
    ) {
        for (i, p) in self.sources.portable.iter().enumerate() {
            if names(p.reference.as_ref(), own) || names(p.reference.as_ref(), storage) {
                self.used_portable[i] = true;
                add_portable(record, p);
            }
        }
        for (i, b) in self.sources.ready_boost.iter().enumerate() {
            if names(b.reference.as_ref(), storage) {
                self.used_boost[i] = true;
                add_boost(record, b);
            }
        }
    }

    /// The records of the `MountedDevices` volumes no device has.
    fn unlinked_volumes(&mut self, out: &mut Vec<History>) {
        for (i, m) in self.sources.mounted.iter().enumerate() {
            if self.used_volumes[i] || m.volume_guid.is_none() {
                continue;
            }
            let mut record = History::new(None, m.reference.clone());
            self.software(&mut record, None, storage_of(m.reference.as_ref()));
            add_volume(&mut record, self.sources, i);
            out.push(record);
        }
    }

    /// The records of what only `SOFTWARE` names.
    fn software_only(&mut self, out: &mut Vec<History>) {
        for (i, p) in self.sources.portable.iter().enumerate() {
            if self.used_portable[i] {
                continue;
            }
            let mut record = History::new(None, p.reference.clone());
            add_portable(&mut record, p);
            let storage = storage_of(p.reference.as_ref());
            for (j, b) in self.sources.ready_boost.iter().enumerate() {
                if !self.used_boost[j] && names(b.reference.as_ref(), storage) {
                    self.used_boost[j] = true;
                    add_boost(&mut record, b);
                }
            }
            out.push(record);
        }
        for (i, b) in self.sources.ready_boost.iter().enumerate() {
            if !self.used_boost[i] {
                let mut record = History::new(None, b.reference.clone());
                add_boost(&mut record, b);
                out.push(record);
            }
        }
    }
}

/// The records of the volumes only users' `MountPoints2` have: one per volume GUID.
fn users_only(sources: &Sources) -> Vec<History> {
    let mut records: Vec<History> = Vec::new();
    for (user, points) in sources.users {
        for point in points {
            let Some(guid) = point.volume_guid.as_deref() else {
                continue;
            };
            let mounted = sources.mounted.iter().any(|m| {
                m.volume_guid
                    .as_deref()
                    .is_some_and(|g| g.eq_ignore_ascii_case(guid))
            });
            if mounted {
                continue;
            }
            let at = records
                .iter()
                .position(|h| {
                    h.volume_guid
                        .as_deref()
                        .is_some_and(|g| g.eq_ignore_ascii_case(guid))
                })
                .unwrap_or_else(|| {
                    let mut record = History::new(None, None);
                    record.volume_guid = Some(guid.to_owned());
                    records.push(record);
                    records.len() - 1
                });
            add_user(&mut records[at], user, point);
        }
    }
    records
}

/// Add a portable device's name.
fn add_portable(record: &mut History, portable: &PortableDevice) {
    add_name(&mut record.volume_names, portable.friendly_name.as_deref());
    record.found(
        "Windows Portable Devices",
        "SOFTWARE",
        format!(r"SOFTWARE {PORTABLE_DEVICES}\{}", portable.key),
        portable.replayed,
    );
    record.problems.extend(portable.problems.iter().cloned());
}

/// The vendor and product IDs of the USB device of USB storage device `storage`.
fn usb_ids(storage: &Device, devices: &[Device]) -> Option<(Option<String>, Option<String>)> {
    let usb = devices.iter().filter(|d| {
        d.class == DeviceClass::Usb && d.control_set == storage.control_set && d.vid.is_some()
    });
    let container = storage
        .container_id
        .as_deref()
        .filter(|c| !c.eq_ignore_ascii_case(NULL_CONTAINER));
    let found = if let Some(container) = container {
        usb.clone().find(|d| {
            d.container_id
                .as_deref()
                .is_some_and(|c| c.eq_ignore_ascii_case(container))
        })
    } else {
        None
    }
    .or_else(|| {
        let serial = storage.serial.as_deref()?;
        usb.clone().find(|d| {
            d.serial
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(serial))
        })
    })?;
    Some((found.vid.clone(), found.pid.clone()))
}

/// Add `name` to `names`, once.
fn add_name(names: &mut Vec<String>, name: Option<&str>) {
    if let Some(name) = name.filter(|n| !n.is_empty())
        && !names.iter().any(|n| n == name)
    {
        names.push(name.to_owned());
    }
}

/// Add a `ReadyBoost` key's label and serial number.
fn add_boost(record: &mut History, boost: &ReadyBoostDevice) {
    add_name(&mut record.volume_names, boost.volume_name.as_deref());
    if let Some(serial) = boost.volume_serial
        && !record.volume_serials.contains(&serial)
    {
        record.volume_serials.push(serial);
    }
    record.found(
        "EMDMgmt",
        "SOFTWARE",
        format!(r"SOFTWARE {EMD_MGMT}\{}", boost.key),
        boost.replayed,
    );
    record.problems.extend(boost.problems.iter().cloned());
}

/// Add `MountedDevices` volume `i`: its GUID, data, drive letters and users.
fn add_volume(record: &mut History, sources: &Sources, i: usize) {
    let volume = &sources.mounted[i];
    record.volume_guid.clone_from(&volume.volume_guid);
    record.mount_target = Some(volume.target.clone());
    record.found(
        "MountedDevices",
        "SYSTEM",
        format!("SYSTEM MountedDevices: {}", volume.name),
        volume.replayed,
    );
    record.problems.extend(volume.problems.iter().cloned());
    for letter in sources
        .mounted
        .iter()
        .filter(|m| m.data == volume.data && !volume.data.is_empty())
    {
        if let Some(l) = letter.drive_letter
            && !record.drive_letters.contains(&l)
        {
            record.drive_letters.push(l);
            record.found(
                "MountedDevices",
                "SYSTEM",
                format!("SYSTEM MountedDevices: {}", letter.name),
                letter.replayed,
            );
        }
    }
    let Some(guid) = volume.volume_guid.as_deref() else {
        return;
    };
    for (user, points) in sources.users {
        for point in points.iter().filter(|p| {
            p.volume_guid
                .as_deref()
                .is_some_and(|g| g.eq_ignore_ascii_case(guid))
        }) {
            add_user(record, user, point);
        }
    }
}

/// Add a user whose `MountPoints2` has the volume.
fn add_user(record: &mut History, user: &str, point: &MountPoint) {
    record.users.push(UserMount {
        user: user.to_owned(),
        last_written: point.last_written,
    });
    record.found(
        "MountPoints2",
        "NTUSER.DAT",
        format!(r"NTUSER.DAT ({user}) {MOUNT_POINTS2}\{}", point.name),
        point.replayed,
    );
    record
        .problems
        .extend(point.problems.iter().map(|p| format!("{user}: {p}")));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn device_paths_name_the_usb_storage_device_in_them() {
        let usbstor = |device: &str, instance: &str| {
            Some(DeviceRef {
                enumerator: "USBSTOR".to_owned(),
                device: device.to_owned(),
                instance: instance.to_owned(),
            })
        };
        assert_eq!(
            device_ref(
                r"\??\USBSTOR#Disk&Ven_Kanguru&Prod_FlashBlu&Rev_PMAP#58B104027B7A0072&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
            ),
            usbstor(
                "Disk&Ven_Kanguru&Prod_FlashBlu&Rev_PMAP",
                "58B104027B7A0072&0"
            )
        );
        assert_eq!(
            device_ref(
                "WPDBUSENUMROOT#UMB#2&37C186B&1&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_CRUZER&REV_1.26#2005&0#"
            ),
            usbstor("DISK&VEN_SANDISK&PROD_CRUZER&REV_1.26", "2005&0")
        );
        assert_eq!(
            device_ref(
                "_??_USBSTOR#Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07#A1B2C3D4&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}USBDRIVE_1234567890"
            ),
            usbstor("Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07", "A1B2C3D4&0")
        );
        let usb = device_ref("USB#VID_0781&PID_7400#0781005B300304C7").unwrap_or_else(|| panic!());
        assert_eq!(
            (usb.enumerator.as_str(), usb.device.as_str()),
            ("USB", "VID_0781&PID_7400")
        );
        assert_eq!(
            device_ref(r"\??\SCSI#CdRom&Ven_NECVMWar&Prod_VMware_SATA_CD01#5&260e6d66&0&010000#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}")
                .map(|r| r.enumerator),
            Some("SCSI".to_owned())
        );
        assert_eq!(device_ref("USBSTOR#Disk"), None);
        assert_eq!(device_ref(""), None);
    }

    #[test]
    fn names_ids_and_serial_numbers() {
        assert_eq!(
            storage_name("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26"),
            [
                Some("Disk".to_owned()),
                Some("SanDisk".to_owned()),
                Some("Cruzer".to_owned()),
                Some("1.26".to_owned())
            ]
        );
        assert_eq!(
            storage_name("Disk&Ven_&Prod_Flash_Disk&Rev_8.07")[1..],
            [None, Some("Flash_Disk".to_owned()), Some("8.07".to_owned())]
        );
        assert_eq!(
            vid_pid("VID_04E8&PID_6860&MS_COMP_MTP&SAMSUNG_Android"),
            (Some("04E8".to_owned()), Some("6860".to_owned()))
        );
        assert_eq!(vid_pid("ROOT_HUB30"), (None, None));
        assert_eq!(
            serial("USBSTOR", "58B104027B7A0072&0"),
            Some("58B104027B7A0072".to_owned())
        );
        assert_eq!(
            serial("USBSTOR", "0000e3947403&1"),
            Some("0000e3947403".to_owned())
        );
        assert_eq!(serial("USBSTOR", "7&2a3fb3c&0"), None);
        assert_eq!(serial("USB", "5&1e0e1ee8&0&2"), None);
        assert_eq!(
            serial("USB", "AA011004141209081070"),
            Some("AA011004141209081070".to_owned())
        );
        assert_eq!(serial("USB", ""), None);
    }

    #[test]
    fn mounted_devices_data() {
        let mut mbr = 0xa5ff_c3bd_u32.to_le_bytes().to_vec();
        mbr.extend(368_050_176_u64.to_le_bytes());
        assert_eq!(
            mount_target(&mbr),
            MountTarget::Mbr {
                signature: 0xa5ff_c3bd,
                offset: 368_050_176
            }
        );
        let mut gpt = b"DMIO:ID:".to_vec();
        gpt.extend([
            0xcf, 0x26, 0x1d, 0x24, 0x58, 0x64, 0xa4, 0x4c, 0x90, 0x4b, 0xa3, 0x38, 0x22, 0x7e,
            0x6f, 0xb6,
        ]);
        assert_eq!(
            mount_target(&gpt),
            MountTarget::Gpt("{241d26cf-6458-4ca4-904b-a338227e6fb6}".to_owned())
        );
        let path = r"_??_USBSTOR#Disk&Ven_Garmin&Prod_nuvi_Flash&Rev_1.00#0000e3947403&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        assert_eq!(
            mount_target(&utf16(path)),
            MountTarget::Path(path.to_owned())
        );
        // control characters, an odd length, too short: other
        assert_eq!(mount_target(&utf16("\\a\u{1}bcdefgh")), MountTarget::Other);
        assert_eq!(mount_target(&[0x5c, 0, 0x5c]), MountTarget::Other);
        assert_eq!(mount_target(&[]), MountTarget::Other);
        assert_eq!(drive_letter(r"\DosDevices\e:"), Some('E'));
        assert_eq!(drive_letter(r"\DosDevices\E:\x"), None);
        assert_eq!(
            volume_guid(r"\??\Volume{14fc504e-e0e5-11e3-8258-ac220b2a5a56}"),
            Some("{14fc504e-e0e5-11e3-8258-ac220b2a5a56}".to_owned())
        );
        assert_eq!(volume_guid(r"\??\Volume{14fc504e}"), None);
    }

    #[test]
    fn ready_boost_key_names() {
        assert_eq!(
            ready_boost_volume(
                "_??_USBSTOR#Disk&Ven_Generic&Prod_Flash_Disk&Rev_8.07#A1B2C3D4&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}USB_DRIVE_1234567890"
            ),
            (Some("USB_DRIVE".to_owned()), Some(1_234_567_890), None)
        );
        assert_eq!(
            ready_boost_volume("BW_Q___1893742278"),
            (Some("BW_Q__".to_owned()), Some(1_893_742_278), None)
        );
        assert_eq!(
            ready_boost_volume("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}_42"),
            (None, Some(42), None)
        );
        assert!(ready_boost_volume("NoSerial").2.is_some());
        assert!(ready_boost_volume("Label_99999999999").2.is_some());
        assert!(ready_boost_volume("Label_+12").2.is_some());
    }
}
