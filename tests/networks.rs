// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Networks on regipy's Windows 7 `SYSTEM` (MIT; `tests/fixtures/regipy/`): two interfaces with
//! static addresses, one of them leased by DHCP before, two persistent routes and the Eastern time
//! zone. The interfaces and routes are what regipy's `network_data` and `routes` give.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::networks::{SystemTime, system};

fn regipy_system() -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/SYSTEM.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

#[test]
fn networks_of_a_windows_7_system() {
    let hive = regipy_system();
    let networks = system(&hive, 1).unwrap();
    assert_eq!(networks.problems, Vec::<String>::new());
    let interfaces: Vec<String> = networks
        .interfaces
        .iter()
        .map(|i| {
            format!(
                "{} {:?} {} {} {} {}",
                i.guid,
                i.dhcp_enabled,
                i.ip_addresses.join(","),
                i.subnet_masks.join(","),
                i.default_gateways.join(","),
                i.name_servers.join(",")
            )
        })
        .collect();
    assert_eq!(
        interfaces,
        [
            "{698E50A9-4F58-4D86-B61D-F42E58DCACF6} Some(false) 10.3.58.5 255.255.255.0 10.3.58.1 10.3.58.4",
            "{6AAFC9A9-0542-4DB2-8760-CCFFA953737C} Some(false) 192.168.1.123 255.255.255.0 192.168.1.1 192.168.1.112",
            "{e29ac6c2-7037-11de-816d-806e6f6e6963} None    ",
        ]
    );
    // the second was leased by DHCP before it got a static address
    assert_eq!(
        (
            networks.interfaces[1].lease_obtained,
            networks.interfaces[1].lease_terminates
        ),
        (Some(1_289_408_803), Some(1_289_948_803))
    );
    assert!(
        networks
            .interfaces
            .iter()
            .all(|i| i.problems.is_empty() && i.subkey.is_none() && !i.replayed)
    );
    let routes: Vec<(&str, Option<&str>, Option<&str>)> = networks
        .routes
        .iter()
        .map(|r| {
            (
                r.value_name.as_str(),
                r.gateway.as_deref(),
                r.metric.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        routes,
        [
            (
                "0.0.0.0,0.0.0.0,192.168.1.1,-1",
                Some("192.168.1.1"),
                Some("-1")
            ),
            (
                "0.0.0.0,0.0.0.0,10.3.58.1,-1",
                Some("10.3.58.1"),
                Some("-1")
            ),
        ]
    );
    assert_eq!(networks.shares, Vec::new());
    assert_eq!(networks.port_proxies, Vec::new());
    // Eastern time: a summer and a winter local time
    let tz = networks.time_zone.unwrap();
    assert_eq!(
        (tz.name.as_deref(), tz.bias, tz.daylight_bias),
        (Some("Eastern Standard Time"), 300, -60)
    );
    let local = |month, day| SystemTime {
        year: 2012,
        month,
        day,
        hour: 7,
        minute: 48,
        second: 39,
        millisecond: 0,
        weekday: 0,
    };
    let utc = |t| {
        ys_registry_parser::filetime(tz.to_utc(&t).unwrap())
            .unwrap()
            .0
    };
    // 2012-04-04 07:48:39 EDT = 11:48:39 UTC; 2012-01-04 07:48:39 EST = 12:48:39 UTC
    assert_eq!(utc(local(4, 4)), 1_333_540_119);
    assert_eq!(utc(local(1, 4)), 1_325_681_319);
    assert!(system(&hive, 3).is_none());
}
