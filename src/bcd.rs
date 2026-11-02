//! Boot Configuration Data (`BCD`) hives: the boot manager, its boot entries and the settings
//! objects they inherit, each object's elements decoded by its element type, and the settings
//! that matter after a compromise: recovery turned off (`recoveryenabled`, `bootstatuspolicy`),
//! test signing on, integrity checks off, safe mode.
//!
//! The store keeps an object per key under `Objects` (named after the object's GUID): its type
//! in `Description\Type`, and each element in `Elements\<type>\Element`, its type 8 hexadecimal
//! digits. An element type's top 4 bits are its class (1: library, any application; 2: one kind
//! of application; 3: device), the next 4 its format (1: device, 2: string, 3: object, 4: object
//! list, 5: integer, 6: boolean, 7: integer list). Integers, booleans and integer lists are
//! `REG_BINARY` (an integer in 1 to 8 bytes, little-endian); a device's data is a binary
//! structure. An object's type's top 4 bits are its kind (1: application, 2: inherited settings,
//! 3: device); an application's next 4 bits after 4 reserved ones are its image type and its low
//! 20 its application type (1: firmware boot manager, 2: Windows boot manager, 3: Windows boot
//! loader, …). Class 2 elements are named by the application type: an OS loader's
//! `0x250000E0` is its boot status policy. The names are those of Microsoft's BCD WMI provider
//! documentation (`BcdLibraryElementTypes`, `BcdBootMgrElementTypes`, `BcdOSLoaderElementTypes`,
//! `BcdResumeElementTypes`, `BcdMemDiagElementTypes`, `BcdDeviceObjectElementTypes`).

use crate::bytes::u32_at;
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status};
use crate::software::guid;
use std::collections::{HashMap, HashSet};

/// The element with an object's description.
const DESCRIPTION: u32 = 0x1200_0004;
/// The elements with an application's device and path.
const APPLICATION_DEVICE: u32 = 0x1100_0001;
const APPLICATION_PATH: u32 = 0x1200_0002;
/// The objects an object inherits elements from.
const INHERITED_OBJECTS: u32 = 0x1400_0006;
/// `recoveryenabled`, `nointegritychecks`, `testsigning`.
const AUTO_RECOVERY_ENABLED: u32 = 0x1600_0009;
const DISABLE_INTEGRITY_CHECKS: u32 = 0x1600_0048;
const ALLOW_PRERELEASE_SIGNATURES: u32 = 0x1600_0049;
/// An OS loader's own `AllowPrereleaseSignatures`, `SafeBoot` and `BootStatusPolicy`.
const OS_LOADER_PRERELEASE_SIGNATURES: u32 = 0x2600_0027;
const SAFE_BOOT: u32 = 0x2500_0080;
const BOOT_STATUS_POLICY: u32 = 0x2500_00e0;
/// The Windows boot manager's default object and display order.
const DEFAULT_OBJECT: u32 = 0x2300_0003;
const DISPLAY_ORDER: u32 = 0x2400_0001;
/// Application types.
const WINDOWS_BOOT_MANAGER: u32 = 2;
const OS_LOADER: u32 = 3;
/// How deep inherited objects are followed.
const MAX_INHERITANCE: usize = 8;

/// Elements of every object (class 1), by type.
const LIBRARY: &[(u32, &str)] = &[
    (0x1100_0001, "BcdLibraryDevice_ApplicationDevice"),
    (0x1200_0002, "BcdLibraryString_ApplicationPath"),
    (0x1200_0004, "BcdLibraryString_Description"),
    (0x1200_0005, "BcdLibraryString_PreferredLocale"),
    (0x1400_0006, "BcdLibraryObjectList_InheritedObjects"),
    (0x1500_0007, "BcdLibraryInteger_TruncatePhysicalMemory"),
    (0x1400_0008, "BcdLibraryObjectList_RecoverySequence"),
    (0x1600_0009, "BcdLibraryBoolean_AutoRecoveryEnabled"),
    (0x1700_000a, "BcdLibraryIntegerList_BadMemoryList"),
    (0x1600_000b, "BcdLibraryBoolean_AllowBadMemoryAccess"),
    (0x1500_000c, "BcdLibraryInteger_FirstMegabytePolicy"),
    (0x1500_000d, "BcdLibraryInteger_RelocatePhysicalMemory"),
    (0x1500_000e, "BcdLibraryInteger_AvoidLowPhysicalMemory"),
    (0x1600_0010, "BcdLibraryBoolean_DebuggerEnabled"),
    (0x1500_0011, "BcdLibraryInteger_DebuggerType"),
    (0x1500_0012, "BcdLibraryInteger_SerialDebuggerPortAddress"),
    (0x1500_0013, "BcdLibraryInteger_SerialDebuggerPort"),
    (0x1500_0014, "BcdLibraryInteger_SerialDebuggerBaudRate"),
    (0x1500_0015, "BcdLibraryInteger_1394DebuggerChannel"),
    (0x1200_0016, "BcdLibraryString_UsbDebuggerTargetName"),
    (
        0x1600_0017,
        "BcdLibraryBoolean_DebuggerIgnoreUsermodeExceptions",
    ),
    (0x1500_0018, "BcdLibraryInteger_DebuggerStartPolicy"),
    (0x1200_0019, "BcdLibraryString_DebuggerBusParameters"),
    (0x1500_001a, "BcdLibraryInteger_DebuggerNetHostIP"),
    (0x1500_001b, "BcdLibraryInteger_DebuggerNetPort"),
    (0x1600_001c, "BcdLibraryBoolean_DebuggerNetDhcp"),
    (0x1200_001d, "BcdLibraryString_DebuggerNetKey"),
    (0x1600_0020, "BcdLibraryBoolean_EmsEnabled"),
    (0x1500_0022, "BcdLibraryInteger_EmsPort"),
    (0x1500_0023, "BcdLibraryInteger_EmsBaudRate"),
    (0x1200_0030, "BcdLibraryString_LoadOptionsString"),
    (0x1600_0040, "BcdLibraryBoolean_DisplayAdvancedOptions"),
    (0x1600_0041, "BcdLibraryBoolean_DisplayOptionsEdit"),
    (0x1100_0043, "BcdLibraryDevice_BsdLogDevice"),
    (0x1200_0044, "BcdLibraryString_BsdLogPath"),
    (0x1600_0046, "BcdLibraryBoolean_GraphicsModeDisabled"),
    (0x1500_0047, "BcdLibraryInteger_ConfigAccessPolicy"),
    (0x1600_0048, "BcdLibraryBoolean_DisableIntegrityChecks"),
    (0x1600_0049, "BcdLibraryBoolean_AllowPrereleaseSignatures"),
    (0x1200_004a, "BcdLibraryString_FontPath"),
    (0x1500_004b, "BcdLibraryInteger_SiPolicy"),
    (0x1500_004c, "BcdLibraryInteger_FveBandId"),
    (0x1600_0050, "BcdLibraryBoolean_ConsoleExtendedInput"),
    (0x1500_0052, "BcdLibraryInteger_GraphicsResolution"),
    (0x1600_0053, "BcdLibraryBoolean_RestartOnFailure"),
    (0x1600_0054, "BcdLibraryBoolean_GraphicsForceHighestMode"),
    (0x1600_0060, "BcdLibraryBoolean_IsolatedExecutionContext"),
    (0x1600_006c, "BcdLibraryBoolean_BootUxDisable"),
    (0x1600_0074, "BcdLibraryBoolean_BootShutdownDisabled"),
    (0x1700_0077, "BcdLibraryIntegerList_AllowedInMemorySettings"),
    (0x1600_0079, "BcdLibraryBoolean_ForceFipsCrypto"),
];

/// Elements of boot managers (class 2, application types 1 and 2).
const BOOT_MANAGER: &[(u32, &str)] = &[
    (0x2400_0001, "BcdBootMgrObjectList_DisplayOrder"),
    (0x2400_0002, "BcdBootMgrObjectList_BootSequence"),
    (0x2300_0003, "BcdBootMgrObject_DefaultObject"),
    (0x2500_0004, "BcdBootMgrInteger_Timeout"),
    (0x2600_0005, "BcdBootMgrBoolean_AttemptResume"),
    (0x2300_0006, "BcdBootMgrObject_ResumeObject"),
    (0x2400_0010, "BcdBootMgrObjectList_ToolsDisplayOrder"),
    (0x2600_0020, "BcdBootMgrBoolean_DisplayBootMenu"),
    (0x2600_0021, "BcdBootMgrBoolean_NoErrorDisplay"),
    (0x2100_0022, "BcdBootMgrDevice_BcdDevice"),
    (0x2200_0023, "BcdBootMgrString_BcdFilePath"),
    (0x2600_0028, "BcdBootMgrBoolean_ProcessCustomActionsFirst"),
    (0x2700_0030, "BcdBootMgrIntegerList_CustomActionsList"),
    (0x2600_0031, "BcdBootMgrBoolean_PersistBootSequence"),
];

/// Elements of Windows boot loaders (class 2, application type 3).
const OS_LOADER_ELEMENTS: &[(u32, &str)] = &[
    (0x2100_0001, "BcdOSLoaderDevice_OSDevice"),
    (0x2200_0002, "BcdOSLoaderString_SystemRoot"),
    (0x2300_0003, "BcdOSLoaderObject_AssociatedResumeObject"),
    (0x2600_0010, "BcdOSLoaderBoolean_DetectKernelAndHal"),
    (0x2200_0011, "BcdOSLoaderString_KernelPath"),
    (0x2200_0012, "BcdOSLoaderString_HalPath"),
    (0x2200_0013, "BcdOSLoaderString_DbgTransportPath"),
    (0x2500_0020, "BcdOSLoaderInteger_NxPolicy"),
    (0x2500_0021, "BcdOSLoaderInteger_PAEPolicy"),
    (0x2600_0022, "BcdOSLoaderBoolean_WinPEMode"),
    (0x2600_0024, "BcdOSLoaderBoolean_DisableCrashAutoReboot"),
    (0x2600_0025, "BcdOSLoaderBoolean_UseLastGoodSettings"),
    (0x2600_0027, "BcdOSLoaderBoolean_AllowPrereleaseSignatures"),
    (0x2600_0030, "BcdOSLoaderBoolean_NoLowMemory"),
    (0x2500_0031, "BcdOSLoaderInteger_RemoveMemory"),
    (0x2500_0032, "BcdOSLoaderInteger_IncreaseUserVa"),
    (0x2600_0040, "BcdOSLoaderBoolean_UseVgaDriver"),
    (0x2600_0041, "BcdOSLoaderBoolean_DisableBootDisplay"),
    (0x2600_0042, "BcdOSLoaderBoolean_DisableVesaBios"),
    (0x2600_0043, "BcdOSLoaderBoolean_DisableVgaMode"),
    (0x2500_0050, "BcdOSLoaderInteger_ClusterModeAddressing"),
    (0x2600_0051, "BcdOSLoaderBoolean_UsePhysicalDestination"),
    (0x2500_0052, "BcdOSLoaderInteger_RestrictApicCluster"),
    (0x2600_0054, "BcdOSLoaderBoolean_UseLegacyApicMode"),
    (0x2500_0055, "BcdOSLoaderInteger_X2ApicPolicy"),
    (0x2600_0060, "BcdOSLoaderBoolean_UseBootProcessorOnly"),
    (0x2500_0061, "BcdOSLoaderInteger_NumberOfProcessors"),
    (0x2600_0062, "BcdOSLoaderBoolean_ForceMaximumProcessors"),
    (
        0x2500_0063,
        "BcdOSLoaderBoolean_ProcessorConfigurationFlags",
    ),
    (0x2600_0064, "BcdOSLoaderBoolean_MaximizeGroupsCreated"),
    (0x2600_0065, "BcdOSLoaderBoolean_ForceGroupAwareness"),
    (0x2500_0066, "BcdOSLoaderInteger_GroupSize"),
    (0x2600_0070, "BcdOSLoaderInteger_UseFirmwarePciSettings"),
    (0x2500_0071, "BcdOSLoaderInteger_MsiPolicy"),
    (0x2500_0080, "BcdOSLoaderInteger_SafeBoot"),
    (0x2600_0081, "BcdOSLoaderBoolean_SafeBootAlternateShell"),
    (0x2600_0090, "BcdOSLoaderBoolean_BootLogInitialization"),
    (0x2600_0091, "BcdOSLoaderBoolean_VerboseObjectLoadMode"),
    (0x2600_00a0, "BcdOSLoaderBoolean_KernelDebuggerEnabled"),
    (0x2600_00a1, "BcdOSLoaderBoolean_DebuggerHalBreakpoint"),
    (0x2600_00a2, "BcdOSLoaderBoolean_UsePlatformClock"),
    (0x2600_00a3, "BcdOSLoaderBoolean_ForceLegacyPlatform"),
    (0x2500_00a6, "BcdOSLoaderInteger_TscSyncPolicy"),
    (0x2600_00b0, "BcdOSLoaderBoolean_EmsEnabled"),
    (0x2500_00c1, "BcdOSLoaderInteger_DriverLoadFailurePolicy"),
    (0x2500_00c2, "BcdOSLoaderInteger_BootMenuPolicy"),
    (0x2600_00c3, "BcdOSLoaderBoolean_AdvancedOptionsOneTime"),
    (0x2500_00e0, "BcdOSLoaderInteger_BootStatusPolicy"),
    (0x2600_00e1, "BcdOSLoaderBoolean_DisableElamDrivers"),
    (0x2500_00f0, "BcdOSLoaderInteger_HypervisorLaunchType"),
    (0x2600_00f2, "BcdOSLoaderBoolean_HypervisorDebuggerEnabled"),
    (0x2500_00f3, "BcdOSLoaderInteger_HypervisorDebuggerType"),
    (
        0x2500_00f4,
        "BcdOSLoaderInteger_HypervisorDebuggerPortNumber",
    ),
    (0x2500_00f5, "BcdOSLoaderInteger_HypervisorDebuggerBaudrate"),
    (
        0x2500_00f6,
        "BcdOSLoaderInteger_HypervisorDebugger1394Channel",
    ),
    (0x2500_00f7, "BcdOSLoaderInteger_BootUxPolicy"),
    (0x2200_00f9, "BcdOSLoaderString_HypervisorDebuggerBusParams"),
    (0x2500_00fa, "BcdOSLoaderInteger_HypervisorNumProc"),
    (0x2500_00fb, "BcdOSLoaderInteger_HypervisorRootProcPerNode"),
    (0x2600_00fc, "BcdOSLoaderBoolean_HypervisorUseLargeVTlb"),
    (
        0x2500_00fd,
        "BcdOSLoaderInteger_HypervisorDebuggerNetHostIp",
    ),
    (
        0x2500_00fe,
        "BcdOSLoaderInteger_HypervisorDebuggerNetHostPort",
    ),
    (0x2500_0100, "BcdOSLoaderInteger_TpmBootEntropyPolicy"),
    (0x2200_0110, "BcdOSLoaderString_HypervisorDebuggerNetKey"),
    (0x2600_0114, "BcdOSLoaderBoolean_HypervisorDebuggerNetDhcp"),
    (0x2500_0115, "BcdOSLoaderInteger_HypervisorIommuPolicy"),
    (0x2500_012b, "BcdOSLoaderInteger_XSaveDisable"),
];

/// Elements of resume applications (class 2, application type 4).
const RESUME: &[(u32, &str)] = &[
    (0x2600_0003, "BcdResumeBoolean_UseCustomSettings"),
    (0x2100_0005, "BcdResumeDevice_AssociatedOsDevice"),
    (0x2600_0006, "BcdResumeBoolean_DebugOptionEnabled"),
    (0x2500_0008, "BcdResumeInteger_BootMenuPolicy"),
];

/// Elements of memory testers (class 2, application type 5).
const MEMORY_TESTER: &[(u32, &str)] = &[
    (0x2500_0001, "BcdMemDiagInteger_PassCount"),
    (0x2500_0003, "BcdMemDiagInteger_FailureCount"),
];

/// Elements of device objects (class 3).
const DEVICE: &[(u32, &str)] = &[
    (0x3500_0001, "BcdDeviceInteger_RamdiskImageOffset"),
    (0x3500_0002, "BcdDeviceInteger_TftpClientPort"),
    (0x3100_0003, "BcdDeviceInteger_SdiDevice"),
    (0x3200_0004, "BcdDeviceInteger_SdiPath"),
    (0x3500_0005, "BcdDeviceInteger_RamdiskImageLength"),
    (0x3600_0006, "BcdDeviceBoolean_RamdiskExportAsCd"),
    (0x3600_0007, "BcdDeviceInteger_RamdiskTftpBlockSize"),
    (0x3600_0008, "BcdDeviceInteger_RamdiskTftpWindowSize"),
    (0x3600_0009, "BcdDeviceBoolean_RamdiskMulticastEnabled"),
    (0x3600_000a, "BcdDeviceBoolean_RamdiskMulticastTftpFallback"),
    (0x3600_000b, "BcdDeviceBoolean_RamdiskTftpVarWindow"),
];

/// Application types, by number.
const APPLICATION_TYPES: [(u32, &str); 10] = [
    (1, "firmware boot manager"),
    (2, "Windows boot manager"),
    (3, "Windows boot loader"),
    (4, "Windows resume application"),
    (5, "memory tester"),
    (6, "legacy NtLdr"),
    (7, "legacy SetupLdr"),
    (8, "boot sector"),
    (9, "startup module"),
    (10, "generic application"),
];

/// `BcdOSLoaderInteger_BootStatusPolicy` values.
const BOOT_STATUS_POLICIES: [&str; 8] = [
    "DisplayAllFailures",
    "IgnoreAllFailures",
    "IgnoreShutdownFailures",
    "IgnoreBootFailures",
    "IgnoreCheckpointFailures",
    "DisplayShutdownFailures",
    "DisplayBootFailures",
    "DisplayCheckpointFailures",
];

/// `BcdOSLoaderInteger_SafeBoot` values.
const SAFE_BOOT_MODES: [&str; 3] = ["Minimal", "Network", "DsRepair"];

/// An element's value, decoded by its format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BcdValue {
    /// Format 1: a device; its bytes are in [`BcdElement::data_raw`], and what is understood of
    /// them here ([`device_summary`]).
    Device(Option<String>),
    /// Format 2.
    String(String),
    /// Format 3: an object's GUID.
    Object(String),
    /// Format 4: objects' GUIDs.
    ObjectList(Vec<String>),
    /// Format 5.
    Integer(u64),
    /// Format 6.
    Boolean(bool),
    /// Format 7.
    IntegerList(Vec<u64>),
    /// Data that doesn't decode by the element type's format (or a format without decoding):
    /// its bytes are in [`BcdElement::data_raw`].
    Undecoded,
}

/// One element of an object: `Elements\<type>\Element`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BcdElement {
    /// The `Elements` subkey's name, as written.
    pub key_name: String,
    /// The element type the name gives; `None` when it isn't 8 hexadecimal digits.
    pub element_type: Option<u32>,
    /// The element type's name in Microsoft's documentation, for the object's kind.
    pub name: Option<&'static str>,
    /// The value.
    pub value: BcdValue,
    /// The data's bytes: always for a device and an element type without a documented name,
    /// and when the value doesn't decode.
    pub data_raw: Option<Vec<u8>>,
    /// When the element's key was last written (FILETIME): when the setting was last changed.
    pub key_last_written: u64,
    /// Whether the transaction logs' replay wrote the element's key or value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// One object of the store, with the settings that matter after a compromise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BcdObject {
    /// Its key's name: its GUID.
    pub guid: String,
    /// `Description\Type`.
    pub object_type: Option<u32>,
    /// What the type says it is ([`object_type_name`]).
    pub type_name: String,
    /// When its key was last written (FILETIME).
    pub key_last_written: u64,
    /// Its description (`BcdLibraryString_Description`).
    pub description: Option<String>,
    /// Whether it is the Windows boot manager's default object.
    pub is_default: bool,
    /// Its place in the Windows boot manager's display order, from 0.
    pub display_order: Option<usize>,
    /// Its application device (`BcdLibraryDevice_ApplicationDevice`), as far as understood.
    pub device: Option<String>,
    /// Its application path (`BcdLibraryString_ApplicationPath`).
    pub path: Option<String>,
    /// `recoveryenabled` (`BcdLibraryBoolean_AutoRecoveryEnabled`), its own or inherited.
    pub recovery_enabled: Option<bool>,
    /// `testsigning` (`BcdLibraryBoolean_AllowPrereleaseSignatures`, or a Windows boot loader's
    /// `BcdOSLoaderBoolean_AllowPrereleaseSignatures`), its own or inherited.
    pub test_signing: Option<bool>,
    /// `nointegritychecks` (`BcdLibraryBoolean_DisableIntegrityChecks`), its own or inherited.
    pub no_integrity_checks: Option<bool>,
    /// `safeboot` (`BcdOSLoaderInteger_SafeBoot`, a Windows boot loader's), its own or
    /// inherited.
    pub safe_boot: Option<u64>,
    /// `bootstatuspolicy` (`BcdOSLoaderInteger_BootStatusPolicy`, a Windows boot loader's), its
    /// own or inherited.
    pub boot_status_policy: Option<u64>,
    /// Which of these settings come from objects it inherits (`test_signing from {GUID}`).
    pub inherited: Vec<String>,
    /// Its elements, in the hive's order.
    pub elements: Vec<BcdElement>,
    /// Whether the transaction logs' replay wrote its key, its type or one of its elements.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// What an object's type says it is: `Windows boot loader` (an application), `inherited
/// settings for Windows boot loader`, `inherited settings`, `device`, or `type 0x…`.
#[must_use]
pub fn object_type_name(object_type: u32) -> String {
    let application = |t: u32| {
        APPLICATION_TYPES
            .iter()
            .find(|(n, _)| *n == t & 0xf_ffff)
            .map(|(_, name)| (*name).to_owned())
    };
    match object_type >> 28 {
        1 => application(object_type).unwrap_or_else(|| format!("application 0x{object_type:08x}")),
        2 => match (object_type >> 20) & 0xf {
            2 => application(object_type).map_or_else(
                || "inherited settings".to_owned(),
                |name| format!("inherited settings for {name}"),
            ),
            _ => "inherited settings".to_owned(),
        },
        3 => "device".to_owned(),
        _ => format!("type 0x{object_type:08x}"),
    }
}

/// The application type whose class 2 elements an object of `object_type` has: an
/// application's, or that of inherited settings for one kind of application.
fn application_type(object_type: Option<u32>) -> Option<u32> {
    let t = object_type?;
    match t >> 28 {
        1 => Some(t & 0xf_ffff),
        2 if (t >> 20) & 0xf == 2 => Some(t & 0xf_ffff),
        _ => None,
    }
}

/// The documented name of element type `element` in an object of `object_type`.
#[must_use]
pub fn element_name(object_type: Option<u32>, element: u32) -> Option<&'static str> {
    let table: &[(u32, &str)] = match element >> 28 {
        1 => LIBRARY,
        2 => match application_type(object_type)? {
            1 | WINDOWS_BOOT_MANAGER => BOOT_MANAGER,
            OS_LOADER => OS_LOADER_ELEMENTS,
            4 => RESUME,
            5 => MEMORY_TESTER,
            _ => return None,
        },
        3 => DEVICE,
        _ => return None,
    };
    table
        .iter()
        .find(|(t, _)| *t == element)
        .map(|(_, name)| *name)
}

/// The name of a `bootstatuspolicy` value (`IgnoreAllFailures`).
#[must_use]
pub fn boot_status_policy_name(policy: u64) -> Option<&'static str> {
    BOOT_STATUS_POLICIES
        .get(usize::try_from(policy).ok()?)
        .copied()
}

/// The name of a `safeboot` value (`Minimal`, `Network`, `DsRepair`).
#[must_use]
pub fn safe_boot_name(mode: u64) -> Option<&'static str> {
    SAFE_BOOT_MODES.get(usize::try_from(mode).ok()?).copied()
}

/// What is understood of a device element's bytes: the GUID of a device options object in the
/// first 16 bytes (zero: none), and, for a partition (device type 6 at offset 16, with zeros at
/// 48 to 55, as Windows writes it for a GPT disk), its partition's GUID at 32 and its disk's at
/// 56. `None` when neither is there.
#[must_use]
pub fn device_summary(bytes: &[u8]) -> Option<String> {
    let lower = |b: &[u8]| guid(b).to_ascii_lowercase();
    let options = bytes
        .get(..16)
        .filter(|b| b.iter().any(|&x| x != 0))
        .map(lower);
    let partition = (u32_at(bytes, 16) == Some(6)
        && bytes.get(48..56).is_some_and(|b| b.iter().all(|&x| x == 0)))
    .then(|| Some((lower(bytes.get(32..48)?), lower(bytes.get(56..72)?))))
    .flatten()
    .map(|(partition, disk)| format!("partition {partition} on disk {disk}"));
    match (partition, options) {
        (Some(p), Some(o)) => Some(format!("{p} (options {o})")),
        (Some(p), None) => Some(p),
        (None, Some(o)) => Some(format!("device with options {o}")),
        (None, None) => None,
    }
}

/// The objects of a `BCD` hive, in the hive's order, with what keeps keys from being read.
/// `None` when it has no `Objects` key.
#[must_use]
pub fn bcd(hive: &Hive) -> Option<(Vec<BcdObject>, Vec<String>)> {
    let key = hive.key("Objects")?;
    let (keys, problems) = key.subkeys();
    let mut objects: Vec<BcdObject> = keys.iter().map(object).collect();
    let by_guid: HashMap<String, usize> = objects
        .iter()
        .enumerate()
        .map(|(i, o)| (o.guid.to_ascii_lowercase(), i))
        .collect();
    // the Windows boot manager's default and display order
    if let Some(manager) = objects.iter().find(|o| {
        application_type(o.object_type) == Some(WINDOWS_BOOT_MANAGER)
            && o.object_type.is_some_and(|t| t >> 28 == 1)
    }) {
        let default = match own(manager, DEFAULT_OBJECT) {
            Some(BcdValue::Object(g)) => Some(g.to_ascii_lowercase()),
            _ => None,
        };
        let order: Vec<String> = match own(manager, DISPLAY_ORDER) {
            Some(BcdValue::ObjectList(list)) => {
                list.iter().map(|g| g.to_ascii_lowercase()).collect()
            }
            _ => Vec::new(),
        };
        for o in &mut objects {
            let id = o.guid.to_ascii_lowercase();
            o.is_default = default.as_deref() == Some(id.as_str());
            o.display_order = order.iter().position(|g| *g == id);
        }
    }
    // the settings, own or inherited
    let settings: Vec<_> = (0..objects.len())
        .map(|i| {
            let find = |element: u32, os_loader_only: bool| {
                inherited(&objects, &by_guid, i, element, os_loader_only)
            };
            (
                find(AUTO_RECOVERY_ENABLED, false),
                find(ALLOW_PRERELEASE_SIGNATURES, false)
                    .or_else(|| find(OS_LOADER_PRERELEASE_SIGNATURES, true)),
                find(DISABLE_INTEGRITY_CHECKS, false),
                find(SAFE_BOOT, true),
                find(BOOT_STATUS_POLICY, true),
            )
        })
        .collect();
    for (o, (recovery, signing, integrity, safe, policy)) in objects.iter_mut().zip(settings) {
        let mut from = |what: &str, found: &Option<(BcdValue, Option<String>)>| {
            if let Some((_, Some(source))) = found {
                o.inherited.push(format!("{what} from {source}"));
            }
        };
        from("recovery_enabled", &recovery);
        from("test_signing", &signing);
        from("no_integrity_checks", &integrity);
        from("safe_boot", &safe);
        from("boot_status_policy", &policy);
        let boolean = |found: Option<(BcdValue, Option<String>)>| match found {
            Some((BcdValue::Boolean(b), _)) => Some(b),
            _ => None,
        };
        let integer = |found: Option<(BcdValue, Option<String>)>| match found {
            Some((BcdValue::Integer(n), _)) => Some(n),
            _ => None,
        };
        o.recovery_enabled = boolean(recovery);
        o.test_signing = boolean(signing);
        o.no_integrity_checks = boolean(integrity);
        o.safe_boot = integer(safe);
        o.boot_status_policy = integer(policy);
    }
    Some((objects, problems))
}

/// The value of `object`'s own element `element`.
fn own(object: &BcdObject, element: u32) -> Option<&BcdValue> {
    object
        .elements
        .iter()
        .find(|e| e.element_type == Some(element))
        .map(|e| &e.value)
}

/// Element `element` of object `at`, its own, else from the objects it inherits (in their
/// order, depth first), with the GUID of the object it came from when not its own. With
/// `os_loader_only`, only from objects whose class 2 elements are a Windows boot loader's.
fn inherited(
    objects: &[BcdObject],
    by_guid: &HashMap<String, usize>,
    at: usize,
    element: u32,
    os_loader_only: bool,
) -> Option<(BcdValue, Option<String>)> {
    let mut seen = HashSet::new();
    let mut stack = vec![(at, 0)];
    while let Some((i, depth)) = stack.pop() {
        if !seen.insert(i) || depth > MAX_INHERITANCE {
            continue;
        }
        let o = &objects[i];
        let applies = !os_loader_only || application_type(o.object_type) == Some(OS_LOADER);
        if applies && let Some(value) = own(o, element) {
            return Some((value.clone(), (i != at).then(|| o.guid.clone())));
        }
        if let Some(BcdValue::ObjectList(list)) = own(o, INHERITED_OBJECTS) {
            // depth first in list order: push in reverse
            for g in list.iter().rev() {
                if let Some(&j) = by_guid.get(&g.to_ascii_lowercase()) {
                    stack.push((j, depth + 1));
                }
            }
        }
    }
    None
}

/// The object of key `key` (`Objects\{GUID}`), without its default, display order and settings.
fn object(key: &Key) -> BcdObject {
    let mut o = BcdObject {
        guid: key.name(),
        object_type: None,
        type_name: String::new(),
        key_last_written: key.last_written(),
        description: None,
        is_default: false,
        display_order: None,
        device: None,
        path: None,
        recovery_enabled: None,
        test_signing: None,
        no_integrity_checks: None,
        safe_boot: None,
        boot_status_policy: None,
        inherited: Vec::new(),
        elements: Vec::new(),
        replayed: key.status() == Status::Replayed,
        problems: Vec::new(),
    };
    match key.subkey("Description").and_then(|d| d.value("Type")) {
        Some(value) => {
            o.replayed |= value.status() == Status::Replayed;
            match crate::system::number(&value) {
                Ok(t) => o.object_type = Some(t),
                Err(why) => o.problems.push(format!(r"Description\Type: {why}")),
            }
        }
        None => o.problems.push(r"it has no Description\Type".to_owned()),
    }
    o.type_name = o
        .object_type
        .map_or_else(|| "unknown".to_owned(), object_type_name);
    let Some(elements) = key.subkey("Elements") else {
        return o;
    };
    let (keys, why) = elements.subkeys();
    o.problems
        .extend(why.into_iter().map(|w| format!("Elements: {w}")));
    for element_key in &keys {
        let e = element(element_key, o.object_type);
        o.replayed |= e.replayed;
        o.elements.push(e);
    }
    for e in &o.elements {
        match (e.element_type, &e.value) {
            (Some(DESCRIPTION), BcdValue::String(s)) => o.description = Some(s.clone()),
            (Some(APPLICATION_PATH), BcdValue::String(s)) => o.path = Some(s.clone()),
            (Some(APPLICATION_DEVICE), BcdValue::Device(d)) => o.device.clone_from(d),
            _ => {}
        }
    }
    o
}

/// The element of key `key` (`Elements\<type>`) in an object of `object_type`.
fn element(key: &Key, object_type: Option<u32>) -> BcdElement {
    let key_name = key.name();
    let element_type = (key_name.len() == 8)
        .then(|| u32::from_str_radix(&key_name, 16).ok())
        .flatten();
    let mut e = BcdElement {
        name: element_type.and_then(|t| element_name(object_type, t)),
        element_type,
        key_name,
        value: BcdValue::Undecoded,
        data_raw: None,
        key_last_written: key.last_written(),
        replayed: key.status() == Status::Replayed,
        problems: Vec::new(),
    };
    if element_type.is_none() {
        e.problems
            .push("its key's name is not an element type (8 hexadecimal digits)".to_owned());
    }
    let Some(value) = key.value("Element") else {
        e.problems.push("it has no Element value".to_owned());
        return e;
    };
    e.replayed |= value.status() == Status::Replayed;
    let (bytes, read) = value.read_data();
    if let Some(why) = read {
        e.problems.push(why);
        e.data_raw = Some(bytes);
        return e;
    }
    let format = element_type.map_or(0, |t| (t >> 24) & 0xf);
    match element_value(format, value.value_type(), value.data_type(), &bytes) {
        Ok(v) => {
            // a device's bytes, and an undocumented element's, are kept
            if matches!(v, BcdValue::Device(_)) || e.name.is_none() {
                e.data_raw = Some(bytes);
            }
            e.value = v;
        }
        Err(why) => {
            e.problems.extend(why);
            e.data_raw = Some(bytes);
        }
    }
    e
}

/// The value of an element of `format` stored as `kind` (`code`) with `bytes`, or what is wrong
/// with it.
fn element_value(
    format: u32,
    kind: ValueType,
    code: u32,
    bytes: &[u8],
) -> Result<BcdValue, Option<String>> {
    let wrong = |want: &str| Some(format!("is {}, not {want}", kind.name()));
    let text = || match decode(code, bytes) {
        Data::Text {
            value,
            lossy: false,
        } => Ok(value),
        Data::Text { lossy: true, .. } => Err(Some("is not valid UTF-16".to_owned())),
        _ => Err(wrong("REG_SZ")),
    };
    let binary = || {
        if kind == ValueType::Binary {
            Ok(bytes)
        } else {
            Err(wrong("REG_BINARY"))
        }
    };
    // an integer of 1 to 8 bytes, little-endian
    let integer = |b: &[u8]| -> Result<u64, Option<String>> {
        if b.is_empty() || b.len() > 8 {
            return Err(Some(format!(
                "{} bytes are not an integer of 1 to 8",
                b.len()
            )));
        }
        Ok(b.iter().rev().fold(0, |n, &x| (n << 8) | u64::from(x)))
    };
    match format {
        1 => Ok(BcdValue::Device(device_summary(binary()?))),
        2 => Ok(BcdValue::String(text()?)),
        3 => Ok(BcdValue::Object(text()?)),
        4 => match decode(code, bytes) {
            Data::MultiText {
                values,
                lossy: false,
            } => Ok(BcdValue::ObjectList(values)),
            Data::MultiText { lossy: true, .. } => Err(Some("is not valid UTF-16".to_owned())),
            _ => Err(wrong("REG_MULTI_SZ")),
        },
        5 => Ok(BcdValue::Integer(integer(binary()?)?)),
        6 => match integer(binary()?)? {
            0 => Ok(BcdValue::Boolean(false)),
            1 => Ok(BcdValue::Boolean(true)),
            n => Err(Some(format!("boolean {n} is neither 0 nor 1"))),
        },
        7 => {
            let b = binary()?;
            if b.len().is_multiple_of(8) {
                Ok(BcdValue::IntegerList(
                    b.as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| u64::from_le_bytes(*c))
                        .collect(),
                ))
            } else {
                Err(Some(format!(
                    "{} bytes are not a list of 8-byte integers",
                    b.len()
                )))
            }
        }
        _ => Err(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(object_type_name(0x1010_0002), "Windows boot manager");
        assert_eq!(object_type_name(0x1020_0003), "Windows boot loader");
        assert_eq!(object_type_name(0x101f_ffff), "application 0x101fffff");
        assert_eq!(object_type_name(0x2010_0000), "inherited settings");
        assert_eq!(
            object_type_name(0x2020_0003),
            "inherited settings for Windows boot loader"
        );
        assert_eq!(object_type_name(0x3000_0000), "device");
        assert_eq!(object_type_name(0x5000_0000), "type 0x50000000");
        assert_eq!(
            element_name(Some(0x1020_0003), 0x2500_00e0),
            Some("BcdOSLoaderInteger_BootStatusPolicy")
        );
        assert_eq!(
            element_name(Some(0x2020_0003), 0x2500_00f4),
            Some("BcdOSLoaderInteger_HypervisorDebuggerPortNumber")
        );
        // the same type in a boot manager: its default object
        assert_eq!(
            element_name(Some(0x1010_0002), 0x2300_0003),
            Some("BcdBootMgrObject_DefaultObject")
        );
        assert_eq!(
            element_name(Some(0x1020_0003), 0x2300_0003),
            Some("BcdOSLoaderObject_AssociatedResumeObject")
        );
        assert_eq!(element_name(Some(0x1030_0006), 0x2200_0002), None);
        assert_eq!(
            element_name(None, 0x1600_0049),
            Some("BcdLibraryBoolean_AllowPrereleaseSignatures")
        );
        assert_eq!(element_name(None, 0x4600_0010), None);
        assert_eq!(boot_status_policy_name(1), Some("IgnoreAllFailures"));
        assert_eq!(boot_status_policy_name(8), None);
        assert_eq!(safe_boot_name(1), Some("Network"));
        assert_eq!(safe_boot_name(u64::MAX), None);
    }

    #[test]
    fn values() {
        let v = |format, kind, bytes: &[u8]| element_value(format, kind, 3, bytes);
        assert_eq!(v(5, ValueType::Binary, &[0x1e]), Ok(BcdValue::Integer(30)));
        assert_eq!(
            v(5, ValueType::Binary, &[0, 0xc2, 1]),
            Ok(BcdValue::Integer(115_200))
        );
        assert!(v(5, ValueType::Binary, &[0; 9]).is_err());
        assert!(v(5, ValueType::Binary, &[]).is_err());
        assert_eq!(v(6, ValueType::Binary, &[1]), Ok(BcdValue::Boolean(true)));
        assert_eq!(v(6, ValueType::Binary, &[0]), Ok(BcdValue::Boolean(false)));
        assert_eq!(
            v(6, ValueType::Binary, &[2]),
            Err(Some("boolean 2 is neither 0 nor 1".to_owned()))
        );
        assert_eq!(
            v(6, ValueType::Dword, &[1, 0, 0, 0]),
            Err(Some("is REG_DWORD, not REG_BINARY".to_owned()))
        );
        assert_eq!(
            v(
                7,
                ValueType::Binary,
                &[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
            ),
            Ok(BcdValue::IntegerList(vec![1, 2]))
        );
        assert!(v(7, ValueType::Binary, &[1, 2, 3]).is_err());
        assert_eq!(v(9, ValueType::Binary, &[1]), Err(None));
    }

    proptest::proptest! {
        /// Element data of any bytes, of any format and value type: decoded or refused, never a
        /// panic.
        #[test]
        fn arbitrary_elements(
            format in 0u32..16,
            code in 0u32..12,
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)
        ) {
            let _ = element_value(format, ValueType::from_code(code), code, &bytes);
            let _ = device_summary(&bytes);
        }
    }

    #[test]
    fn devices() {
        let mut gpt = vec![0u8; 88];
        gpt[16] = 6;
        gpt[24] = 0x48;
        gpt[32..48].copy_from_slice(&[0x11; 16]);
        gpt[56..72].copy_from_slice(&[0x22; 16]);
        assert_eq!(
            device_summary(&gpt).as_deref(),
            Some(
                "partition {11111111-1111-1111-1111-111111111111} on disk {22222222-2222-2222-2222-222222222222}"
            )
        );
        gpt[..16].copy_from_slice(&[0x33; 16]);
        assert!(
            device_summary(&gpt)
                .unwrap_or_default()
                .ends_with("(options {33333333-3333-3333-3333-333333333333})")
        );
        // another device type, or something at 48: not read
        let mut other = gpt.clone();
        other[..16].copy_from_slice(&[0; 16]);
        other[16] = 5;
        assert_eq!(device_summary(&other), None);
        other[16] = 6;
        other[50] = 1;
        assert_eq!(device_summary(&other), None);
        assert_eq!(
            device_summary(&gpt[..60]).as_deref(),
            Some("device with options {33333333-3333-3333-3333-333333333333}")
        );
        assert_eq!(device_summary(&[]), None);
    }
}
