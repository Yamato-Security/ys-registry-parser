//! The security settings attackers change to weaken a system, in `SOFTWARE`, `SYSTEM` and
//! `NTUSER.DAT`: Microsoft Defender (and its exclusions), User Account Control, credential
//! protection (`WDigest`, LSA protection, Credential Guard, Restricted Admin, NTLM), Remote
//! Desktop, the firewall and `SMBv1`, PowerShell (logging, execution policy, AMSI) and what keeps
//! evidence (last access times, System Restore, event logs).
//!
//! Each setting found is a [`Setting`] with its value, what the value means, whether it weakens
//! the default, and whether it comes from a `Policies` key (Group Policy, or a tool writing
//! there). A setting that isn't there is not reported; this does not establish its effective
//! state, which can depend on other configuration sources and the platform version.
//!
//! *Weakens the default* compares a value with what current Windows (10 and 11) does without it:
//! a protection or an evidence source that the stored setting can lower when honored. It does
//! not measure the effective protection state, and doesn't say the system was
//! compromised: administrators, other security products and older Windows versions set some of
//! these values too, and the meaning says so where it is common. `None` is for values that are
//! neither (a port, a size, an AMSI provider) or that this can't tell.

use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use crate::system::control_set_name;

/// The part of the system a setting protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Area {
    /// Microsoft Defender Antivirus.
    Defender,
    /// User Account Control.
    Uac,
    /// Credential protection: `WDigest`, LSA, NTLM.
    Credentials,
    /// Remote Desktop.
    RemoteAccess,
    /// The firewall and SMB.
    Network,
    /// PowerShell and AMSI.
    Powershell,
    /// What keeps evidence: last access times, System Restore, event logs.
    Evidence,
}

impl Area {
    /// `defender`, `uac`, `credentials`, `remote_access`, `network`, `powershell` or `evidence`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Area::Defender => "defender",
            Area::Uac => "uac",
            Area::Credentials => "credentials",
            Area::RemoteAccess => "remote_access",
            Area::Network => "network",
            Area::Powershell => "powershell",
            Area::Evidence => "evidence",
        }
    }
}

/// One security setting as a hive holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// What it is: `defender_disable_antispyware`, `uac_enable_lua`, `defender_exclusion_path`, …
    pub setting: &'static str,
    /// The part of the system it protects.
    pub area: Area,
    /// The key, from the hive's root (`ControlSet001\…` in a `SYSTEM` hive).
    pub key_path: String,
    /// The value; empty for a setting that is a key (an AMSI provider).
    pub value_name: String,
    /// The value as text: a number in decimal, a string, an exclusion's path; `None` when it
    /// can't be read.
    pub value: Option<String>,
    /// What the value means.
    pub meaning: String,
    /// Whether the value weakens what current Windows does by default; `None` when that doesn't
    /// apply or can't be told.
    pub weakens_default: Option<bool>,
    /// Whether it comes from a `Policies` key.
    pub policy: bool,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
    /// The value's bytes, when they aren't of the type the setting has.
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the key or the value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// How a value is read and what it means.
#[derive(Clone, Copy)]
enum Rule {
    /// A `REG_DWORD` whose 1 turns `what` off (`Disable…`).
    Off(&'static str),
    /// A `REG_DWORD` whose 0 turns `what` off (`Enable…`).
    On(&'static str),
    /// A `REG_DWORD`, read by its own function.
    Number(fn(u32) -> (String, Option<bool>)),
    /// A string, read by its own function.
    Text(fn(&str) -> (String, Option<bool>)),
}

/// A setting: its name, area, key (under the hive's root, or a control set's), value and rule.
type Entry = (&'static str, Area, &'static str, &'static str, Rule);

const DEFENDER: &str = r"Microsoft\Windows Defender";
const DEFENDER_POLICY: &str = r"Policies\Microsoft\Windows Defender";
const UAC: &str = r"Microsoft\Windows\CurrentVersion\Policies\System";
const PS_POLICY: &str = r"Policies\Microsoft\Windows\PowerShell";

/// The settings of `SOFTWARE` hives.
const SOFTWARE: &[Entry] = &[
    (
        "defender_disable_antispyware",
        Area::Defender,
        DEFENDER,
        "DisableAntiSpyware",
        Rule::Number(disable_antispyware),
    ),
    (
        "defender_disable_antivirus",
        Area::Defender,
        DEFENDER,
        "DisableAntiVirus",
        Rule::Number(disable_antispyware),
    ),
    (
        "defender_disable_realtime_monitoring",
        Area::Defender,
        r"Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
        Rule::Off("real-time protection"),
    ),
    (
        "defender_disable_behavior_monitoring",
        Area::Defender,
        r"Microsoft\Windows Defender\Real-Time Protection",
        "DisableBehaviorMonitoring",
        Rule::Off("behavior monitoring"),
    ),
    (
        "defender_disable_on_access_protection",
        Area::Defender,
        r"Microsoft\Windows Defender\Real-Time Protection",
        "DisableOnAccessProtection",
        Rule::Off("on-access protection"),
    ),
    (
        "defender_disable_ioav_protection",
        Area::Defender,
        r"Microsoft\Windows Defender\Real-Time Protection",
        "DisableIOAVProtection",
        Rule::Off("scanning of downloaded files and attachments"),
    ),
    (
        "defender_disable_script_scanning",
        Area::Defender,
        r"Microsoft\Windows Defender\Real-Time Protection",
        "DisableScriptScanning",
        Rule::Off("script scanning"),
    ),
    (
        "defender_tamper_protection",
        Area::Defender,
        r"Microsoft\Windows Defender\Features",
        "TamperProtection",
        Rule::Number(tamper_protection),
    ),
    (
        "defender_spynet_reporting",
        Area::Defender,
        r"Microsoft\Windows Defender\Spynet",
        "SpyNetReporting",
        Rule::Number(spynet_reporting),
    ),
    (
        "defender_submit_samples_consent",
        Area::Defender,
        r"Microsoft\Windows Defender\Spynet",
        "SubmitSamplesConsent",
        Rule::Number(submit_samples_consent),
    ),
    (
        "defender_disable_antispyware",
        Area::Defender,
        DEFENDER_POLICY,
        "DisableAntiSpyware",
        Rule::Number(disable_antispyware),
    ),
    (
        "defender_disable_antivirus",
        Area::Defender,
        DEFENDER_POLICY,
        "DisableAntiVirus",
        Rule::Number(disable_antispyware),
    ),
    (
        "defender_disable_realtime_monitoring",
        Area::Defender,
        r"Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
        Rule::Off("real-time protection"),
    ),
    (
        "defender_disable_behavior_monitoring",
        Area::Defender,
        r"Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableBehaviorMonitoring",
        Rule::Off("behavior monitoring"),
    ),
    (
        "defender_disable_on_access_protection",
        Area::Defender,
        r"Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableOnAccessProtection",
        Rule::Off("on-access protection"),
    ),
    (
        "defender_disable_ioav_protection",
        Area::Defender,
        r"Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableIOAVProtection",
        Rule::Off("scanning of downloaded files and attachments"),
    ),
    (
        "defender_disable_script_scanning",
        Area::Defender,
        r"Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableScriptScanning",
        Rule::Off("script scanning"),
    ),
    (
        "defender_spynet_reporting",
        Area::Defender,
        r"Policies\Microsoft\Windows Defender\Spynet",
        "SpynetReporting",
        Rule::Number(spynet_reporting),
    ),
    (
        "defender_submit_samples_consent",
        Area::Defender,
        r"Policies\Microsoft\Windows Defender\Spynet",
        "SubmitSamplesConsent",
        Rule::Number(submit_samples_consent),
    ),
    (
        "uac_enable_lua",
        Area::Uac,
        UAC,
        "EnableLUA",
        Rule::Number(enable_lua),
    ),
    (
        "uac_consent_prompt_behavior_admin",
        Area::Uac,
        UAC,
        "ConsentPromptBehaviorAdmin",
        Rule::Number(consent_prompt_behavior_admin),
    ),
    (
        "uac_local_account_token_filter_policy",
        Area::Uac,
        UAC,
        "LocalAccountTokenFilterPolicy",
        Rule::Number(local_account_token_filter_policy),
    ),
    (
        "uac_filter_administrator_token",
        Area::Uac,
        UAC,
        "FilterAdministratorToken",
        Rule::Number(filter_administrator_token),
    ),
    (
        "rdp_deny_connections",
        Area::RemoteAccess,
        r"Policies\Microsoft\Windows NT\Terminal Services",
        "fDenyTSConnections",
        Rule::Number(deny_ts_connections),
    ),
    (
        "rdp_network_level_authentication",
        Area::RemoteAccess,
        r"Policies\Microsoft\Windows NT\Terminal Services",
        "UserAuthentication",
        Rule::Number(user_authentication),
    ),
    (
        "firewall_domain_profile",
        Area::Network,
        r"Policies\Microsoft\WindowsFirewall\DomainProfile",
        "EnableFirewall",
        Rule::On("Windows Firewall for the domain profile"),
    ),
    (
        "firewall_private_profile",
        Area::Network,
        r"Policies\Microsoft\WindowsFirewall\StandardProfile",
        "EnableFirewall",
        Rule::On("Windows Firewall for the private profile"),
    ),
    (
        "firewall_public_profile",
        Area::Network,
        r"Policies\Microsoft\WindowsFirewall\PublicProfile",
        "EnableFirewall",
        Rule::On("Windows Firewall for the public profile"),
    ),
    (
        "powershell_execution_policy",
        Area::Powershell,
        r"Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
        "ExecutionPolicy",
        Rule::Text(execution_policy),
    ),
    (
        "powershell_enable_scripts",
        Area::Powershell,
        PS_POLICY,
        "EnableScripts",
        Rule::Number(enable_scripts),
    ),
    (
        "powershell_execution_policy",
        Area::Powershell,
        PS_POLICY,
        "ExecutionPolicy",
        Rule::Text(execution_policy),
    ),
    (
        "powershell_script_block_logging",
        Area::Powershell,
        r"Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        Rule::Number(script_block_logging),
    ),
    (
        "powershell_script_block_invocation_logging",
        Area::Powershell,
        r"Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockInvocationLogging",
        Rule::Number(script_block_invocation_logging),
    ),
    (
        "powershell_module_logging",
        Area::Powershell,
        r"Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "EnableModuleLogging",
        Rule::Number(module_logging),
    ),
    (
        "powershell_transcription",
        Area::Powershell,
        r"Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableTranscripting",
        Rule::Number(transcription),
    ),
    (
        "powershell_transcription_directory",
        Area::Powershell,
        r"Policies\Microsoft\Windows\PowerShell\Transcription",
        "OutputDirectory",
        Rule::Text(transcription_directory),
    ),
    (
        "system_restore_disabled",
        Area::Evidence,
        r"Microsoft\Windows NT\CurrentVersion\SystemRestore",
        "DisableSR",
        Rule::Off("System Restore"),
    ),
    (
        "system_restore_disabled",
        Area::Evidence,
        r"Policies\Microsoft\Windows NT\SystemRestore",
        "DisableSR",
        Rule::Off("System Restore"),
    ),
    (
        "system_restore_config_disabled",
        Area::Evidence,
        r"Policies\Microsoft\Windows NT\SystemRestore",
        "DisableConfig",
        Rule::Off("System Restore's configuration (and its restore points)"),
    ),
];

/// The settings of a `SYSTEM` hive's control sets (keys under `ControlSet00N`).
const SYSTEM: &[Entry] = &[
    (
        "wdigest_use_logon_credential",
        Area::Credentials,
        r"Control\SecurityProviders\WDigest",
        "UseLogonCredential",
        Rule::Number(use_logon_credential),
    ),
    (
        "lsa_run_as_ppl",
        Area::Credentials,
        r"Control\Lsa",
        "RunAsPPL",
        Rule::Number(run_as_ppl),
    ),
    (
        "lsa_credential_guard",
        Area::Credentials,
        r"Control\Lsa",
        "LsaCfgFlags",
        Rule::Number(lsa_cfg_flags),
    ),
    (
        "lsa_disable_restricted_admin",
        Area::Credentials,
        r"Control\Lsa",
        "DisableRestrictedAdmin",
        Rule::Number(disable_restricted_admin),
    ),
    (
        "lsa_lm_compatibility_level",
        Area::Credentials,
        r"Control\Lsa",
        "LmCompatibilityLevel",
        Rule::Number(lm_compatibility_level),
    ),
    (
        "rdp_deny_connections",
        Area::RemoteAccess,
        r"Control\Terminal Server",
        "fDenyTSConnections",
        Rule::Number(deny_ts_connections),
    ),
    (
        "rdp_port",
        Area::RemoteAccess,
        r"Control\Terminal Server\WinStations\RDP-Tcp",
        "PortNumber",
        Rule::Number(rdp_port),
    ),
    (
        "rdp_network_level_authentication",
        Area::RemoteAccess,
        r"Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication",
        Rule::Number(user_authentication),
    ),
    (
        "firewall_domain_profile",
        Area::Network,
        r"Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "EnableFirewall",
        Rule::On("Windows Firewall for the domain profile"),
    ),
    (
        "firewall_private_profile",
        Area::Network,
        r"Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "EnableFirewall",
        Rule::On("Windows Firewall for the private profile"),
    ),
    (
        "firewall_public_profile",
        Area::Network,
        r"Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        "EnableFirewall",
        Rule::On("Windows Firewall for the public profile"),
    ),
    (
        "smb1_server",
        Area::Network,
        r"Services\LanmanServer\Parameters",
        "SMB1",
        Rule::Number(smb1),
    ),
    (
        "ntfs_disable_last_access_update",
        Area::Evidence,
        r"Control\FileSystem",
        "NtfsDisableLastAccessUpdate",
        Rule::Number(last_access),
    ),
];

/// The settings of `NTUSER.DAT` hives: the user's own.
const NTUSER: &[Entry] = &[
    (
        "powershell_execution_policy",
        Area::Powershell,
        r"Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
        "ExecutionPolicy",
        Rule::Text(execution_policy),
    ),
    (
        "powershell_enable_scripts",
        Area::Powershell,
        r"Software\Policies\Microsoft\Windows\PowerShell",
        "EnableScripts",
        Rule::Number(enable_scripts),
    ),
    (
        "powershell_execution_policy",
        Area::Powershell,
        r"Software\Policies\Microsoft\Windows\PowerShell",
        "ExecutionPolicy",
        Rule::Text(execution_policy),
    ),
    (
        "powershell_script_block_logging",
        Area::Powershell,
        r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
        Rule::Number(script_block_logging),
    ),
    (
        "powershell_module_logging",
        Area::Powershell,
        r"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "EnableModuleLogging",
        Rule::Number(module_logging),
    ),
    (
        "powershell_transcription",
        Area::Powershell,
        r"Software\Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableTranscripting",
        Rule::Number(transcription),
    ),
    (
        "wsh_amsi_enable",
        Area::Powershell,
        r"Software\Microsoft\Windows Script\Settings",
        "AmsiEnable",
        Rule::On("AMSI for Windows Script Host (VBScript and JScript)"),
    ),
];

/// The kinds of Defender exclusions: the subkey of `Exclusions` and the setting.
const EXCLUSIONS: [(&str, &str, &str); 5] = [
    ("Paths", "defender_exclusion_path", "files under this path"),
    (
        "Extensions",
        "defender_exclusion_extension",
        "files with this extension",
    ),
    (
        "Processes",
        "defender_exclusion_process",
        "files this process opens",
    ),
    (
        "IpAddresses",
        "defender_exclusion_ip_address",
        "network traffic with this address",
    ),
    (
        "TemporaryPaths",
        "defender_exclusion_temporary_path",
        "files under this path, for now",
    ),
];

/// Event log channels (`WINEVT\Channels`) that record attacks, and whether Windows turns each on
/// by default.
const CHANNELS: [(&str, bool); 25] = [
    ("Microsoft-Windows-PowerShell/Operational", true),
    ("PowerShellCore/Operational", true),
    ("Microsoft-Windows-Sysmon/Operational", true),
    ("Microsoft-Windows-Windows Defender/Operational", true),
    (
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        true,
    ),
    (
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        true,
    ),
    (
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        true,
    ),
    ("Microsoft-Windows-WMI-Activity/Operational", true),
    ("Microsoft-Windows-Bits-Client/Operational", true),
    (
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        true,
    ),
    ("Microsoft-Windows-CodeIntegrity/Operational", true),
    ("Microsoft-Windows-SMBServer/Security", true),
    ("Microsoft-Windows-SmbClient/Security", true),
    ("Microsoft-Windows-WinRM/Operational", true),
    ("Microsoft-Windows-NTLM/Operational", true),
    ("Microsoft-Windows-AppLocker/EXE and DLL", true),
    ("Microsoft-Windows-AppLocker/MSI and Script", true),
    ("Microsoft-Windows-Security-Mitigations/KernelMode", true),
    ("Microsoft-Windows-Kernel-PnP/Configuration", true),
    ("Microsoft-Windows-Shell-Core/Operational", true),
    ("Microsoft-Windows-TaskScheduler/Operational", false),
    ("Microsoft-Windows-DNS-Client/Operational", false),
    (
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        false,
    ),
    ("Microsoft-Windows-LSA/Operational", false),
    ("Microsoft-Windows-PrintService/Operational", false),
];

/// Where `SOFTWARE` keeps the event log channels.
const WINEVT_CHANNELS: &str = r"Microsoft\Windows\CurrentVersion\WINEVT\Channels";

/// Where `SOFTWARE` keeps the AMSI providers.
const AMSI_PROVIDERS: &str = r"Microsoft\AMSI\Providers";

/// The classic event logs' default size on Windows 10 and 11.
const LOG_DEFAULT_SIZE: u64 = 20 * 1024 * 1024;

// --- meanings ----------------------------------------------------------------------------------

/// Text and weakness for a number no rule names.
fn unknown(n: u32) -> (String, Option<bool>) {
    (format!("{n}: not a value Windows documents"), None)
}

fn disable_antispyware(n: u32) -> (String, Option<bool>) {
    match n {
        0 => ("legacy Defender disable flag is clear; check effective protection separately".to_owned(), Some(false)),
        1 => (
            "legacy Defender disable flag is set; modern platforms or tamper protection can ignore it (also used when another antivirus is registered)"
                .to_owned(),
            Some(true),
        ),
        n => unknown(n),
    }
}

fn tamper_protection(n: u32) -> (String, Option<bool>) {
    if n & 1 == 1 {
        ("tamper protection on".to_owned(), Some(false))
    } else {
        ("tamper protection off".to_owned(), Some(true))
    }
}

fn spynet_reporting(n: u32) -> (String, Option<bool>) {
    match n {
        0 => (
            "cloud-delivered protection (MAPS) off".to_owned(),
            Some(true),
        ),
        1 => ("basic MAPS membership".to_owned(), Some(false)),
        2 => ("advanced MAPS membership".to_owned(), Some(false)),
        n => unknown(n),
    }
}

fn submit_samples_consent(n: u32) -> (String, Option<bool>) {
    match n {
        0 => (
            "always prompt before sending samples".to_owned(),
            Some(false),
        ),
        1 => ("send safe samples automatically".to_owned(), Some(false)),
        2 => ("never send samples".to_owned(), Some(true)),
        3 => ("send all samples automatically".to_owned(), Some(false)),
        n => unknown(n),
    }
}

fn enable_lua(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "User Account Control off: administrators run with a full token".to_owned(),
            Some(true),
        )
    } else {
        (
            "User Account Control (Admin Approval Mode) on".to_owned(),
            Some(false),
        )
    }
}

fn consent_prompt_behavior_admin(n: u32) -> (String, Option<bool>) {
    let what = match n {
        0 => {
            return (
                "administrators are elevated without a prompt".to_owned(),
                Some(true),
            );
        }
        1 => "prompt administrators for credentials on the secure desktop",
        2 => "prompt administrators for consent on the secure desktop",
        3 => "prompt administrators for credentials",
        4 => "prompt administrators for consent",
        5 => "prompt administrators for consent for programs that aren't Windows' (the default)",
        n => return unknown(n),
    };
    (what.to_owned(), Some(false))
}

fn local_account_token_filter_policy(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "remote UAC on: local administrators get a filtered token over the network (the default)"
                .to_owned(),
            Some(false),
        )
    } else {
        (
            "remote UAC off: local administrators get a full token over the network (pass-the-hash with local accounts works)"
                .to_owned(),
            Some(true),
        )
    }
}

fn filter_administrator_token(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "the built-in Administrator runs with a full token (the default)".to_owned(),
            Some(false),
        )
    } else {
        (
            "Admin Approval Mode for the built-in Administrator".to_owned(),
            Some(false),
        )
    }
}

fn use_logon_credential(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "WDigest doesn't keep cleartext passwords in memory (the default since Windows 8.1)"
                .to_owned(),
            Some(false),
        )
    } else {
        (
            "WDigest keeps cleartext passwords in LSASS memory".to_owned(),
            Some(true),
        )
    }
}

fn run_as_ppl(n: u32) -> (String, Option<bool>) {
    match n {
        0 => ("LSA protection (RunAsPPL) off".to_owned(), Some(true)),
        1 => (
            "LSA protection on, with a UEFI variable".to_owned(),
            Some(false),
        ),
        2 => (
            "LSA protection on, without a UEFI variable".to_owned(),
            Some(false),
        ),
        n => unknown(n),
    }
}

fn lsa_cfg_flags(n: u32) -> (String, Option<bool>) {
    match n {
        0 => ("Credential Guard off".to_owned(), Some(true)),
        1 => (
            "Credential Guard on, with UEFI lock".to_owned(),
            Some(false),
        ),
        2 => (
            "Credential Guard on, without UEFI lock".to_owned(),
            Some(false),
        ),
        n => unknown(n),
    }
}

fn disable_restricted_admin(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "Restricted Admin mode on: Remote Desktop accepts sign-ins with an NTLM hash (pass-the-hash)"
                .to_owned(),
            Some(true),
        )
    } else {
        (
            "Restricted Admin mode off (the default)".to_owned(),
            Some(false),
        )
    }
}

fn lm_compatibility_level(n: u32) -> (String, Option<bool>) {
    let (what, weak) = match n {
        0 => ("send LM and NTLM responses", true),
        1 => (
            "send LM and NTLM, NTLMv2 session security if negotiated",
            true,
        ),
        2 => ("send NTLM responses only", true),
        3 => ("send NTLMv2 responses only (the default)", false),
        4 => ("send NTLMv2 responses only; refuse LM", false),
        5 => ("send NTLMv2 responses only; refuse LM and NTLM", false),
        n => return unknown(n),
    };
    (what.to_owned(), Some(weak))
}

fn deny_ts_connections(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        ("Remote Desktop connections allowed".to_owned(), Some(true))
    } else {
        (
            "Remote Desktop connections denied (the default)".to_owned(),
            Some(false),
        )
    }
}

fn rdp_port(n: u32) -> (String, Option<bool>) {
    if !(1..=u32::from(u16::MAX)).contains(&n) {
        return (format!("{n}: not a valid TCP port"), None);
    }
    if n == 3389 {
        (
            "Remote Desktop listens on TCP 3389 (the default)".to_owned(),
            Some(false),
        )
    } else {
        (
            format!("Remote Desktop listens on TCP {n}, not the default 3389"),
            Some(false),
        )
    }
}

fn user_authentication(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "Network Level Authentication not required: the sign-in screen is shown before authentication"
                .to_owned(),
            Some(true),
        )
    } else {
        (
            "Network Level Authentication required (the default)".to_owned(),
            Some(false),
        )
    }
}

fn smb1(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        ("SMBv1 server off".to_owned(), Some(false))
    } else {
        ("SMBv1 server on".to_owned(), Some(true))
    }
}

fn last_access(n: u32) -> (String, Option<bool>) {
    match n {
        0 => ("last access times updated".to_owned(), Some(false)),
        1 => (
            "last access times not updated (the default before Windows 10 1803)".to_owned(),
            None,
        ),
        0x8000_0000 => (
            "last access times updated (user managed)".to_owned(),
            Some(false),
        ),
        0x8000_0001 => (
            "last access times not updated (user managed: set by hand)".to_owned(),
            Some(true),
        ),
        0x8000_0002 => (
            "last access times updated (system managed, the default since Windows 10 1803)"
                .to_owned(),
            Some(false),
        ),
        0x8000_0003 => (
            "last access times not updated (system managed: Windows chose it for a large volume)"
                .to_owned(),
            Some(false),
        ),
        n => (format!("0x{n:08x}: not a value Windows documents"), None),
    }
}

fn execution_policy(text: &str) -> (String, Option<bool>) {
    let (what, weak) = match text.to_ascii_lowercase().as_str() {
        "unrestricted" => ("scripts run without a signature check", Some(true)),
        "bypass" => (
            "nothing is blocked and there are no warnings or prompts",
            Some(true),
        ),
        "remotesigned" => ("scripts from the internet must be signed", Some(false)),
        "allsigned" => ("every script must be signed", Some(false)),
        "restricted" => ("scripts don't run", Some(false)),
        "default" | "undefined" => ("the default policy applies", Some(false)),
        _ => ("not a policy PowerShell knows", None),
    };
    (format!("{text}: {what}"), weak)
}

fn enable_scripts(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "script execution turned off by policy".to_owned(),
            Some(false),
        )
    } else {
        (
            "script execution allowed by policy, as its ExecutionPolicy says".to_owned(),
            Some(false),
        )
    }
}

fn script_block_logging(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "script block logging off, also for suspicious script blocks PowerShell logs by default"
                .to_owned(),
            Some(true),
        )
    } else {
        (
            "script block logging on (event 4104)".to_owned(),
            Some(false),
        )
    }
}

fn script_block_invocation_logging(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        (
            "script block start and stop not logged (the default)".to_owned(),
            Some(false),
        )
    } else {
        (
            "script block start and stop logged (events 4105, 4106)".to_owned(),
            Some(false),
        )
    }
}

fn module_logging(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        ("module logging off (the default)".to_owned(), Some(false))
    } else {
        ("module logging on (event 4103)".to_owned(), Some(false))
    }
}

fn transcription(n: u32) -> (String, Option<bool>) {
    if n == 0 {
        ("transcription off (the default)".to_owned(), Some(false))
    } else {
        ("transcription on".to_owned(), Some(false))
    }
}

fn transcription_directory(text: &str) -> (String, Option<bool>) {
    (format!("transcripts are written under {text}"), None)
}

/// The meaning of a `Rule::Off` or `Rule::On` value.
fn switch(what: &str, n: u32, one_turns_off: bool) -> (String, Option<bool>) {
    let off = if one_turns_off { n == 1 } else { n == 0 };
    let known = n <= 1 || !one_turns_off;
    if !known {
        return unknown(n);
    }
    if off {
        (format!("{what} turned off"), Some(true))
    } else {
        (format!("{what} on"), Some(false))
    }
}

/// A size in bytes, in MiB or KiB where it is a whole number of them.
fn size(n: u64) -> String {
    if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n.is_multiple_of(1 << 10) {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} bytes")
    }
}

// --- reading ---------------------------------------------------------------------------------

/// Whether `path` is under a `Policies` key.
fn is_policy(path: &str) -> bool {
    path.split('\\').any(|p| p.eq_ignore_ascii_case("Policies"))
}

/// A setting of `key` at `key_path`, with nothing read yet.
fn setting(setting: &'static str, area: Area, key: &Key, key_path: String) -> Setting {
    Setting {
        setting,
        area,
        policy: is_policy(&key_path),
        key_path,
        value_name: String::new(),
        value: None,
        meaning: String::new(),
        weakens_default: None,
        key_last_written: key.last_written(),
        data_raw: None,
        replayed: key.status() == Status::Replayed,
        problems: Vec::new(),
    }
}

/// The number of a `REG_DWORD` (or `REG_QWORD`) value, or with a problem its bytes.
fn number_of(value: &Value, record: &mut Setting) -> Option<u64> {
    let (bytes, why) = value.read_data();
    if why.is_some() {
        record.data_raw = Some(bytes.clone());
    }
    record.problems.extend(why);
    match (value.value_type(), decode(value.data_type(), &bytes)) {
        (ValueType::Dword | ValueType::Qword, Data::Number(n)) => Some(n),
        (_, Data::Malformed(why)) => {
            record.problems.push(why);
            record.data_raw = Some(bytes);
            None
        }
        (kind, _) => {
            record
                .problems
                .push(format!("is {}, not REG_DWORD", kind.name()));
            record.data_raw = Some(bytes);
            None
        }
    }
}

/// The text of a string value, or with a problem its bytes.
fn text_of(value: &Value, record: &mut Setting) -> Option<String> {
    let (text, why) = crate::system::string(value);
    let why = why.or_else(|| {
        (!matches!(
            value.value_type(),
            ValueType::Sz | ValueType::ExpandSz | ValueType::Link
        ))
        .then(|| format!("is {}, not a string", value.value_type().name()))
    });
    if let Some(why) = why {
        record.problems.push(why);
        record.data_raw = Some(value.read_data().0);
    }
    text
}

/// Read `rule`'s value into `record`.
fn apply(rule: Rule, value: &Value, record: &mut Setting) {
    record.value_name = value.name();
    record.replayed |= value.status() == Status::Replayed;
    match rule {
        Rule::Text(meaning) => {
            if let Some(text) = text_of(value, record) {
                (record.meaning, record.weakens_default) = meaning(&text);
                record.value = Some(text);
            }
        }
        Rule::Off(_) | Rule::On(_) | Rule::Number(_) => {
            let Some(n) = number_of(value, record) else {
                return;
            };
            record.value = Some(n.to_string());
            let Ok(n) = u32::try_from(n) else {
                record.meaning = format!("{n}: not a value Windows documents");
                return;
            };
            (record.meaning, record.weakens_default) = match rule {
                Rule::Off(what) => switch(what, n, true),
                Rule::On(what) => switch(what, n, false),
                Rule::Number(meaning) => meaning(n),
                Rule::Text(_) => unreachable!("read above"),
            };
        }
    }
}

/// The settings of `entries` in `hive`, their keys under `prefix` (a control set's name, or
/// empty for the hive's root).
fn read_entries(hive: &Hive, prefix: &str, entries: &[Entry], out: &mut Vec<Setting>) {
    for &(name, area, path, value_name, rule) in entries {
        let key_path = if prefix.is_empty() {
            path.to_owned()
        } else {
            format!(r"{prefix}\{path}")
        };
        let Some(key) = hive.key(&key_path) else {
            continue;
        };
        let (values, problems) = key.values();
        let value = values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case(value_name));
        if value.is_none() && problems.is_empty() {
            continue;
        }
        let mut record = setting(name, area, &key, key_path);
        value_name.clone_into(&mut record.value_name);
        record.problems.extend(problems);
        if let Some(value) = value {
            apply(rule, value, &mut record);
        } else {
            "value unavailable in damaged value list".clone_into(&mut record.meaning);
        }
        out.push(record);
    }
}

/// The settings of a `SOFTWARE` hive: Defender's (with each exclusion), UAC's, Remote Desktop's
/// and the firewall's policies, PowerShell's (with each AMSI provider), System Restore's and the
/// event log channels that record attacks; with what keeps keys from being read.
#[must_use]
pub fn software(hive: &Hive) -> (Vec<Setting>, Vec<String>) {
    let mut settings = Vec::new();
    let mut problems = Vec::new();
    read_entries(hive, "", SOFTWARE, &mut settings);
    for base in [DEFENDER, DEFENDER_POLICY] {
        exclusions(
            hive,
            &format!(r"{base}\Exclusions"),
            &mut settings,
            &mut problems,
        );
    }
    amsi_providers(hive, &mut settings, &mut problems);
    channels(hive, &mut settings, &mut problems);
    (settings, problems)
}

/// Each Defender exclusion under `path`: a value per excluded path, extension, process or
/// address, named after it.
fn exclusions(hive: &Hive, path: &str, out: &mut Vec<Setting>, problems: &mut Vec<String>) {
    for (sub, name, what) in EXCLUSIONS {
        let key_path = format!(r"{path}\{sub}");
        let Some(key) = hive.key(&key_path) else {
            continue;
        };
        let (values, why) = key.values();
        problems.extend(why.into_iter().map(|w| format!("{key_path}: {w}")));
        for value in values {
            let excluded = value.name();
            if excluded.is_empty() {
                continue;
            }
            let mut record = setting(name, Area::Defender, &key, key_path.clone());
            record.replayed |= value.status() == Status::Replayed;
            record.meaning = format!("Microsoft Defender doesn't scan {what}");
            record.weakens_default = (sub != "TemporaryPaths").then_some(true);
            record.value = Some(excluded.clone());
            record.value_name = excluded;
            out.push(record);
        }
    }
}

/// Each AMSI provider, with its COM server's DLL from `Classes\CLSID`.
fn amsi_providers(hive: &Hive, out: &mut Vec<Setting>, problems: &mut Vec<String>) {
    let Some(key) = hive.key(AMSI_PROVIDERS) else {
        return;
    };
    let (providers, why) = key.subkeys();
    problems.extend(why.into_iter().map(|w| format!("{AMSI_PROVIDERS}: {w}")));
    for provider in providers {
        let clsid = provider.name();
        let mut record = setting(
            "amsi_provider",
            Area::Powershell,
            &provider,
            format!(r"{AMSI_PROVIDERS}\{clsid}"),
        );
        let server = hive
            .key(&format!(r"Classes\CLSID\{clsid}\InprocServer32"))
            .and_then(|key| {
                record.replayed |= key.status() == Status::Replayed;
                let value = key.value("")?;
                record.replayed |= value.status() == Status::Replayed;
                text_of(&value, &mut record)
            })
            .filter(|s| !s.is_empty());
        record.meaning = match server {
            Some(dll) => format!("an AMSI provider: {dll}"),
            None => "an AMSI provider without a COM server in Classes\\CLSID".to_owned(),
        };
        record.value = Some(clsid);
        out.push(record);
    }
}

/// The event log channels of [`CHANNELS`] there are: whether each is on, and its size.
fn channels(hive: &Hive, out: &mut Vec<Setting>, problems: &mut Vec<String>) {
    for (channel, on_by_default) in CHANNELS {
        let key_path = format!(r"{WINEVT_CHANNELS}\{channel}");
        let Some(key) = hive.key(&key_path) else {
            continue;
        };
        let (values, why) = key.values();
        problems.extend(why.into_iter().map(|w| format!("{key_path}: {w}")));
        if let Some(value) = values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case("Enabled"))
        {
            let mut record = setting(
                "event_channel_enabled",
                Area::Evidence,
                &key,
                key_path.clone(),
            );
            record.value_name = value.name();
            record.replayed |= value.status() == Status::Replayed;
            if let Some(n) = number_of(value, &mut record) {
                record.value = Some(n.to_string());
                (record.meaning, record.weakens_default) = match (n, on_by_default) {
                    (0, true) => (
                        format!("{channel} turned off; Windows turns it on"),
                        Some(true),
                    ),
                    (0, false) => (format!("{channel} off (the default)"), Some(false)),
                    (_, true) => (format!("{channel} on (the default)"), Some(false)),
                    (_, false) => (
                        format!("{channel} turned on; Windows leaves it off"),
                        Some(false),
                    ),
                };
            }
            out.push(record);
        }
        if let Some(value) = values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case("MaxSize"))
        {
            let mut record = setting("event_channel_max_size", Area::Evidence, &key, key_path);
            record.value_name = value.name();
            record.replayed |= value.status() == Status::Replayed;
            if let Some(n) = number_of(value, &mut record) {
                record.value = Some(n.to_string());
                record.meaning = format!("{channel} keeps up to {}", size(n));
            }
            out.push(record);
        }
    }
}

/// The settings of control set `set` of a `SYSTEM` hive (`ControlSet001` for 1): `WDigest`, LSA,
/// Remote Desktop, the firewall, `SMBv1`, last access times and each event log's size; with what
/// keeps keys from being read. `None` when the control set isn't there.
#[must_use]
pub fn system(hive: &Hive, set: u32) -> Option<(Vec<Setting>, Vec<String>)> {
    let prefix = control_set_name(set);
    hive.key(&prefix)?;
    let mut settings = Vec::new();
    let mut problems = Vec::new();
    read_entries(hive, &prefix, SYSTEM, &mut settings);
    let logs_path = format!(r"{prefix}\Services\EventLog");
    if let Some(logs) = hive.key(&logs_path) {
        let (logs, why) = logs.subkeys();
        problems.extend(why.into_iter().map(|w| format!("{logs_path}: {w}")));
        for log in logs {
            let name = log.name();
            let (values, why) = log.values();
            problems.extend(why.into_iter().map(|w| format!("{logs_path}\\{name}: {w}")));
            let Some(value) = values
                .iter()
                .find(|v| v.name().eq_ignore_ascii_case("MaxSize"))
            else {
                continue;
            };
            let mut record = setting(
                "event_log_max_size",
                Area::Evidence,
                &log,
                format!(r"{logs_path}\{name}"),
            );
            record.value_name = value.name();
            record.replayed |= value.status() == Status::Replayed;
            if let Some(n) = number_of(value, &mut record) {
                record.value = Some(n.to_string());
                let main = ["Application", "Security", "System"]
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(&name));
                (record.meaning, record.weakens_default) = if !main {
                    (format!("the {name} log keeps up to {}", size(n)), None)
                } else if n < LOG_DEFAULT_SIZE {
                    (
                        format!(
                            "the {name} log keeps up to {}, less than the default {}",
                            size(n),
                            size(LOG_DEFAULT_SIZE)
                        ),
                        Some(true),
                    )
                } else {
                    (
                        format!("the {name} log keeps up to {}", size(n)),
                        Some(false),
                    )
                };
            }
            settings.push(record);
        }
    }
    Some((settings, problems))
}

/// The settings of an `NTUSER.DAT` hive: the user's PowerShell execution policy and logging
/// policies, and AMSI for Windows Script Host.
#[must_use]
pub fn ntuser(hive: &Hive) -> Vec<Setting> {
    let mut settings = Vec::new();
    read_entries(hive, "", NTUSER, &mut settings);
    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_rdp_ports_have_no_verdict() {
        for port in [0, 65536, u32::MAX] {
            assert_eq!(rdp_port(port).1, None);
            assert!(rdp_port(port).0.contains("not a valid TCP port"));
        }
    }

    #[test]
    fn meanings() {
        assert_eq!(switch("real-time protection", 1, true).1, Some(true));
        assert_eq!(switch("real-time protection", 0, true).1, Some(false));
        assert_eq!(switch("real-time protection", 2, true).1, None);
        assert_eq!(switch("the firewall", 0, false).1, Some(true));
        assert_eq!(switch("the firewall", 2, false).1, Some(false));
        assert_eq!(tamper_protection(5).1, Some(false));
        assert_eq!(tamper_protection(4).1, Some(true));
        assert_eq!(consent_prompt_behavior_admin(0).1, Some(true));
        assert_eq!(consent_prompt_behavior_admin(9).1, None);
        assert_eq!(lm_compatibility_level(2).1, Some(true));
        assert_eq!(lm_compatibility_level(3).1, Some(false));
        assert_eq!(last_access(1).1, None);
        assert_eq!(last_access(0x8000_0001).1, Some(true));
        assert_eq!(
            last_access(7).0,
            "0x00000007: not a value Windows documents"
        );
        assert_eq!(execution_policy("Bypass").1, Some(true));
        assert_eq!(
            execution_policy("unrestricted").0,
            "unrestricted: scripts run without a signature check"
        );
        assert_eq!(execution_policy("RemoteSigned").1, Some(false));
        assert_eq!(execution_policy("Odd").1, None);
        assert_eq!(
            rdp_port(3390).0,
            "Remote Desktop listens on TCP 3390, not the default 3389"
        );
        assert_eq!(size(20 * 1024 * 1024), "20 MiB");
        assert_eq!(size(1536), "1536 bytes");
        assert_eq!(size(68 * 1024), "68 KiB");
        assert_eq!(size(100), "100 bytes");
        assert!(is_policy(r"Policies\Microsoft\Windows Defender"));
        assert!(is_policy(
            r"Microsoft\Windows\CurrentVersion\Policies\System"
        ));
        assert!(!is_policy(r"Microsoft\Windows Defender"));
        assert_eq!(Area::RemoteAccess.name(), "remote_access");
    }
}
