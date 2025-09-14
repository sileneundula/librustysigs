use librustysigs::prelude::*;
use librustysigs::format::export_cert;


fn main() {
    let cert = RustySignaturesUsage::new();
    let public_cert = cert.publiccert();

    let signature = cert.sign("This message is being signed using ShulginSigning with hedged signatures","123456789");

    let output = export_cert(public_cert.clone()).unwrap();

    let signature_validility: bool = RustySignaturesUsage::verify(public_cert.clone(), signature);

    println!("{}",output);

    assert_eq!(signature_validility, true);
}