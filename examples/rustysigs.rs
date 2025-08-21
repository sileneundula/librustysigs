use librustysigs::prelude::*;


fn main() {
    let cert = RustySignaturesUsage::new();
    let public_cert = cert.publiccert();

    let signature = cert.sign("This message is being signed using ShulginSigning with hedged signatures","123456789");

    let signature_validility: bool = RustySignaturesUsage::verify(public_cert, signature);

    assert_eq!(signature_validility, true);
}