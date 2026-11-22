//! Auto-unseal: the unseal key, wrapped by a KMS, so a restart opens the vault without people.
//!
//! The Shamir shares recover a 32-byte **unseal key**, which opens the root key. Enrolment (`pvlt kms-enroll`,
//! or `pvlt init --kms`) takes enough shares to recover that key once, has the KMS wrap it, and stores the
//! ciphertext in the key store. At start the server asks the KMS to unwrap it and opens the root key with it.
//! The shares are untouched and still work, so the KMS is a convenience and never the only way in.
//!
//! The KMS call is bound to this vault: the encryption context names the root key, so a ciphertext copied from
//! another vault does not decrypt here, and the configured key id is passed to Decrypt so a ciphertext made
//! under a different KMS key is refused. Access to the KMS key is the control: whoever may call `Decrypt` on it
//! can open the vault, so grant that to the server's identity alone and watch its use in CloudTrail.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use pvlt_core::audit::Auditor;
use pvlt_core::objects::ObjectStore;
use pvlt_core::seal::UnsealKey;
use pvlt_core::store::KeyStore;
use pvlt_format::Id;
use zeroize::Zeroizing;

use crate::app::App;
use crate::pg::KmsSeal;

/// Why a KMS call failed. [`Display`](fmt::Display) is fixed text: what a provider returns can name keys and
/// accounts, so it is kept apart in [`KmsError::detail`] for the operator's log and never put in a response.
#[derive(Debug)]
pub struct KmsError {
    what: &'static str,
    detail: String,
}

impl KmsError {
    /// A failure with a fixed description and the provider's own message for the operator's log.
    pub fn new(what: &'static str, detail: impl Into<String>) -> Self {
        Self {
            what,
            detail: detail.into(),
        }
    }

    /// The provider's message, for logs only.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for KmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.what)
    }
}

impl std::error::Error for KmsError {}

/// The encryption context both calls carry. It is not secret; it binds the ciphertext to this vault.
pub fn context(root_key_id: &Id) -> Vec<(&'static str, String)> {
    vec![
        ("pvlt", "unseal-key".to_owned()),
        ("root_key_id", hex::encode(root_key_id)),
    ]
}

/// A KMS that can wrap and unwrap the unseal key.
pub trait UnsealKms: Send + Sync {
    /// The provider name stored with the ciphertext (`aws-kms`).
    fn provider(&self) -> &'static str;

    /// The configured key id (an ARN or alias).
    fn key_id(&self) -> &str;

    /// Wraps `plaintext` under the key, with `context`.
    fn encrypt(
        &self,
        plaintext: &[u8],
        context: &[(&'static str, String)],
    ) -> impl Future<Output = Result<Vec<u8>, KmsError>> + Send;

    /// Unwraps `wrapped`. Must fail if it was made under another key or with another context.
    fn decrypt(
        &self,
        wrapped: &[u8],
        context: &[(&'static str, String)],
    ) -> impl Future<Output = Result<Vec<u8>, KmsError>> + Send;
}

/// Wraps the unseal key with the KMS, ready to store.
pub async fn enroll<M: UnsealKms>(
    kms: &M,
    root_key_id: &Id,
    key: &UnsealKey,
) -> Result<KmsSeal, KmsError> {
    let wrapped = kms.encrypt(key.expose(), &context(root_key_id)).await?;
    Ok(KmsSeal {
        root_key_id: *root_key_id,
        provider: kms.provider().to_owned(),
        key_id: kms.key_id().to_owned(),
        wrapped,
    })
}

/// Unwraps the stored unseal key. Refuses a record for another root key, another provider or another KMS key
/// before calling out.
pub async fn recover<M: UnsealKms>(
    kms: &M,
    root_key_id: &Id,
    seal: &KmsSeal,
) -> Result<UnsealKey, KmsError> {
    if seal.root_key_id != *root_key_id {
        return Err(KmsError::new(
            "the stored auto-unseal record is for a different vault",
            "",
        ));
    }
    if seal.provider != kms.provider() || seal.key_id != kms.key_id() {
        return Err(KmsError::new(
            "the stored auto-unseal record was made with a different KMS key than PVLT_KMS_KEY_ID",
            format!("stored {} {}", seal.provider, seal.key_id),
        ));
    }
    let plain = Zeroizing::new(kms.decrypt(&seal.wrapped, &context(root_key_id)).await?);
    UnsealKey::from_bytes(&plain)
        .map_err(|_| KmsError::new("the KMS returned a key of the wrong length", ""))
}

/// Tries to unseal `app` through the KMS once. `Ok(())` if it is unsealed afterwards (by this call or before).
pub async fn try_unseal<K, O, A, M>(
    app: &App<K, O, A>,
    kms: &M,
    seal: &KmsSeal,
) -> Result<(), KmsError>
where
    K: KeyStore,
    O: ObjectStore,
    A: Auditor,
    M: UnsealKms,
{
    if !app.engine.keyring().is_sealed() {
        return Ok(());
    }
    let key = recover(kms, &app.seal_config.root.id, seal).await?;
    app.unseal_with_key(&key).map_err(|e| {
        KmsError::new(
            "the unseal key from the KMS did not open the root key",
            e.to_string(),
        )
    })
}

/// Keeps trying until the vault is unsealed (through the KMS, or by hand). Used when the KMS is unreachable at
/// start, so a restart during a KMS outage recovers by itself afterwards.
pub async fn keep_trying<K, O, A, M>(app: Arc<App<K, O, A>>, kms: M, seal: KmsSeal, every: Duration)
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
    M: UnsealKms + 'static,
{
    loop {
        if !app.engine.keyring().is_sealed() {
            tracing::info!("the vault is unsealed; auto-unseal retries stop");
            return;
        }
        match try_unseal(&app, &kms, &seal).await {
            Ok(()) => {
                tracing::info!(key = %seal.key_id, "unsealed through the KMS");
                return;
            }
            Err(e) => tracing::error!(
                error = %e,
                detail = %e.detail(),
                "auto-unseal failed; retrying (the shares still unseal it)"
            ),
        }
        tokio::time::sleep(every).await;
    }
}

// --- AWS KMS ----------------------------------------------------------------------------------------------

/// Settings for AWS KMS, from `PVLT_KMS_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsConfig {
    /// The key: an ARN, or an alias (`alias/pvlt-unseal`).
    pub key_id: String,
    /// The region. Unset: the SDK's own resolution (environment, profile, instance metadata).
    pub region: Option<String>,
    /// A custom endpoint, for a VPC endpoint or a test stand-in. Plain `http` needs `PVLT_KMS_ALLOW_HTTP`.
    pub endpoint: Option<String>,
}

/// AWS KMS. Credentials come from the SDK's default chain: environment variables, a web identity or ECS task
/// role, or EC2 instance metadata.
pub struct AwsKms {
    client: aws_sdk_kms::Client,
    key_id: String,
}

impl AwsKms {
    /// Builds a client. Does not call AWS.
    pub async fn new(config: &KmsConfig) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &config.region {
            loader = loader.region(aws_config::Region::new(region.clone()));
        }
        if let Some(endpoint) = &config.endpoint {
            loader = loader.endpoint_url(endpoint.clone());
        }
        let shared = loader.load().await;
        Self {
            client: aws_sdk_kms::Client::new(&shared),
            key_id: config.key_id.clone(),
        }
    }
}

impl UnsealKms for AwsKms {
    fn provider(&self) -> &'static str {
        "aws-kms"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn encrypt(
        &self,
        plaintext: &[u8],
        context: &[(&'static str, String)],
    ) -> Result<Vec<u8>, KmsError> {
        let mut call = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext.to_vec()));
        for (k, v) in context {
            call = call.encryption_context(*k, v.clone());
        }
        let out = call.send().await.map_err(|e| {
            KmsError::new("the KMS refused to wrap the unseal key", format!("{e:?}"))
        })?;
        out.ciphertext_blob()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| KmsError::new("the KMS returned no ciphertext", ""))
    }

    async fn decrypt(
        &self,
        wrapped: &[u8],
        context: &[(&'static str, String)],
    ) -> Result<Vec<u8>, KmsError> {
        let mut call = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped.to_vec()));
        for (k, v) in context {
            call = call.encryption_context(*k, v.clone());
        }
        let out = call.send().await.map_err(|e| {
            KmsError::new("the KMS refused to unwrap the unseal key", format!("{e:?}"))
        })?;
        out.plaintext()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| KmsError::new("the KMS returned no plaintext", ""))
    }
}
