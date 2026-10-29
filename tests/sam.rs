//! The `SAM` of regipy's test data (MIT; `tests/fixtures/regipy/`): its local accounts. Every
//! field is what dissect's `F` and `V` structures give for the same hive (and for 6 other
//! public `SAM` hives).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::sam::{NEVER, account_flag_names, accounts};

fn sam() -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/SAM.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

#[test]
fn local_accounts() {
    let (found, problems) = accounts(&sam()).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let names: Vec<(Option<u32>, &str)> = found
        .iter()
        .map(|a| (a.rid, a.username.as_deref().unwrap()))
        .collect();
    assert_eq!(
        names,
        [
            (Some(500), "Administrator"),
            (Some(501), "Guest"),
            (Some(1000), "Preston")
        ]
    );
    assert!(found.iter().all(|a| a.problems.is_empty() && !a.replayed));

    let admin = &found[0];
    let f = admin.f.unwrap();
    assert_eq!(f.last_logon, 129_347_632_925_692_440);
    assert_eq!(f.password_last_set, 129_347_637_947_436_870);
    assert_eq!((f.account_expires, f.last_failed_logon), (0, 0));
    assert_eq!((f.logon_count, f.failed_logon_count), (6, 0));
    assert_eq!(
        account_flag_names(f.flags),
        ["disabled", "normal_account", "dont_expire_password"]
    );
    assert_eq!(
        admin.v.comment.as_deref(),
        Some("Built-in account for administering the computer/domain")
    );
    assert_eq!(admin.key_name.as_deref(), Some("000001F4"));
    assert_eq!(admin.last_written, Some(130_560_139_703_780_424));
    assert_eq!(admin.names_last_written, Some(130_560_033_663_588_374));

    // never expires
    let guest = &found[1];
    assert_eq!(guest.f.unwrap().account_expires, NEVER);
    assert_eq!(
        account_flag_names(guest.f.unwrap().flags),
        [
            "disabled",
            "password_not_required",
            "normal_account",
            "dont_expire_password"
        ]
    );
    let user = &found[2];
    let f = user.f.unwrap();
    assert_eq!(account_flag_names(f.flags), ["normal_account"]);
    assert_eq!((f.logon_count, f.country_code, f.code_page), (4, 1, 1252));
    assert_eq!(user.hidden_from_logon_ui, None);
}
