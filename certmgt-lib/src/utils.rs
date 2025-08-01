use chrono::NaiveDateTime;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::nid::Nid;
use openssl::x509::X509NameRef;

pub fn parse_cert_field(cert: &X509NameRef, nid: Nid) -> Option<String> {
    cert.entries_by_nid(nid)
        .next()
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|data| data.to_string())
}

pub fn asn1_time_to_timestamp(asn1_time: &Asn1TimeRef) -> i64 {
    let time_str = asn1_time.to_string();
    let ts = time_str.replace(" GMT", "").replace(" UTC", "");

    if let Ok(dt) = NaiveDateTime::parse_from_str(&ts, "%b %e %H:%M:%S %Y") {
        return dt.and_utc().timestamp();
    }

    // fallback diff code swapped...
    let epoch = Asn1Time::from_unix(0).unwrap();
    match epoch.diff(asn1_time) {
        Ok(diff) => diff.days as i64 * 86400 + diff.secs as i64,
        Err(_) => 0,
    }
}
