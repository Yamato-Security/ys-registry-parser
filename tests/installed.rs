//! regipy's `NTUSER-WSL.DAT` (MIT; `tests/fixtures/regipy/`): a Windows 10 user's installed
//! software, WSL distributions among it. Every entry is what regipy's `installed_programs_ntuser`,
//! `wsl` and `ntuser_classes_installer` plugins give for the same hive.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::installed::{ProgramSource, Scope, ntuser, software};

fn hive(name: &str) -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

#[test]
fn a_users_programs_and_wsl_distributions() {
    let (programs, problems) = ntuser(&hive("NTUSER-WSL.DAT"));
    assert_eq!(problems, Vec::<String>::new());
    let lines: Vec<String> = programs
        .iter()
        .map(|p| {
            format!(
                "{} {} {} | {} | {}",
                p.source.name(),
                p.name.as_deref().unwrap_or("-"),
                p.version.as_deref().unwrap_or("-"),
                p.program.as_deref().unwrap_or("-"),
                p.install_location.as_deref().unwrap_or("-"),
            )
        })
        .collect();
    let apps = r"C:\Program Files\WindowsApps";
    let packages = r"C:\Users\admin\AppData\Local\Packages";
    assert_eq!(
        lines,
        [
            "uninstall Microsoft OneDrive 21.220.1024.0005 | - | -".to_owned(),
            format!(
                r"app_path debian.exe - | {apps}\TheDebianProject.DebianGNULinux_1.1.3.0_x64__76v4gfsz19hv4\debian.exe | {apps}\TheDebianProject.DebianGNULinux_1.1.3.0_x64__76v4gfsz19hv4"
            ),
            "app_path OneDriveFileLauncher.exe - | - | -".to_owned(),
            format!(
                r"app_path ubuntu.exe - | {apps}\CanonicalGroupLimited.UbuntuonWindows_2004.2020.424.0_x64__79rhkp1fndgsc\ubuntu.exe | {apps}\CanonicalGroupLimited.UbuntuonWindows_2004.2020.424.0_x64__79rhkp1fndgsc"
            ),
            format!(
                r"app_path ubuntu2004.exe - | {apps}\CanonicalGroupLimited.Ubuntu20.04onWindows_2004.2020.424.0_x64__79rhkp1fndgsc\ubuntu2004.exe | {apps}\CanonicalGroupLimited.Ubuntu20.04onWindows_2004.2020.424.0_x64__79rhkp1fndgsc"
            ),
            format!(
                r"wsl Debian 1 | - | {packages}\TheDebianProject.DebianGNULinux_76v4gfsz19hv4\LocalState"
            ),
            format!(
                r"wsl Ubuntu 1 | - | {packages}\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState"
            ),
            format!(
                r"wsl Ubuntu-20.04 1 | - | {packages}\CanonicalGroupLimited.Ubuntu20.04onWindows_79rhkp1fndgsc\LocalState"
            ),
        ]
    );
    assert!(programs.iter().all(|p| p.scope == Scope::User
        && p.problems.is_empty()
        && p.data_raw.is_empty()
        && !p.replayed
        && !p.wow64));
    let onedrive = &programs[0];
    assert_eq!(
        onedrive.key_path,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
    );
    assert_eq!(onedrive.key_last_written, 133_771_328_926_766_746);
    assert_eq!(
        (onedrive.publisher.as_deref(), onedrive.size_kb),
        (Some("Microsoft Corporation"), Some(174_061))
    );
    assert_eq!(
        onedrive.uninstall_command.as_deref(),
        Some(
            r"C:\Users\admin\AppData\Local\Microsoft\OneDrive\21.220.1024.0005\OneDriveSetup.exe  /uninstall "
        )
    );
    // the Lxss key's AppxInstallerCache is not a distribution; Ubuntu-20.04 is the default one,
    // and none runs in WSL 2's virtual machine (Flags 0x7), though Version is 2 (the file
    // system's)
    let ubuntu = programs.last().unwrap();
    assert_eq!(ubuntu.source, ProgramSource::Wsl);
    assert_eq!(
        ubuntu.key_path,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\{e3986a51-3357-4c37-8a3e-1a83d995a3da}"
    );
    let details: Vec<(&str, &str)> = ubuntu
        .details
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        details,
        [
            ("Flags", "0x7"),
            ("State", "1"),
            ("DefaultUid", "0"),
            ("Version", "2"),
            (
                "PackageFamilyName",
                "CanonicalGroupLimited.Ubuntu20.04onWindows_79rhkp1fndgsc"
            ),
            ("Default", "true"),
        ]
    );
    assert!(
        programs[5..7]
            .iter()
            .all(|p| !p.details.iter().any(|(k, _)| k == "Default"))
    );
}

#[test]
fn hives_without_these_keys() {
    let ntuser_hive = hive("NTUSER.DAT");
    assert_eq!(ntuser(&ntuser_hive), (Vec::new(), Vec::new()));
    // a user hive read as SOFTWARE: its root has none of SOFTWARE's keys
    assert_eq!(software(&ntuser_hive), (Vec::new(), Vec::new()));
}
