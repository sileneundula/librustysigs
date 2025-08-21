use crate::UserCertificate;
use crate::UserCertificatePriv;

use pem;

fn cert(cert: UserCertificate) -> Result<String,serde_yaml::Error> {
    serde_yaml::to_string(&cert)
}

#[test]
fn run(){
    let cert = UserCertificatePriv::generate();
    let certpub = cert.publiccert();

    let yaml = cert(certpub);
}