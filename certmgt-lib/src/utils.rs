use x509_parser::prelude::ASN1Time;


pub fn asn1_time_to_timestamp(asn1_time: &ASN1Time) -> i64 {
    asn1_time.timestamp()
    // let time_str = asn1_time.to_string();
    // let ts = time_str.replace(" GMT", "").replace(" UTC", "");
    //
    // if let Ok(dt) = NaiveDateTime::parse_from_str(&ts, "%b %e %H:%M:%S %Y") {
    //     return dt.and_utc().timestamp();
    // }
    //
    // // fallback diff code swapped...
    // let epoch = Asn1Time::from_unix(0).unwrap();
    // match epoch.diff(asn1_time.to) {
    //     Ok(diff) => diff.days as i64 * 86400 + diff.secs as i64,
    //     Err(_) => 0,
    // }
}
