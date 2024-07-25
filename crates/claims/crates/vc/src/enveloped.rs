use iref::uri::data::DataUrlBuf;
use serde::{Deserialize, Serialize};
use ssi_json_ld::syntax::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub struct EnvelopedVerifiableCredential {
    /// JSON-LD context object that defines at least `id` and `type`.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Data URL that expresses a secured verifiable credential using an
    /// enveloping security scheme such as [Securing Verifiable Credentials
    /// using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/).
    pub id: DataUrlBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub struct EnvelopedVerifiablePresentation {
    /// JSON-LD context object that defines at least `id` and `type`.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Data URL that expresses a secured verifiable credential using an
    /// enveloping security scheme such as [Securing Verifiable Credentials
    /// using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/).
    pub id: DataUrlBuf,
}
