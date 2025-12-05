use crate::UserCertificate;
use crate::UserCertificatePriv;

use pem;
use toml;

pub fn export_cert(cert: UserCertificate) -> Result<String,toml::ser::Error> {
    toml::to_string_pretty(&cert)
}