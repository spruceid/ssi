use iref::Uri;

use crate::{EncodedStatusMap, FromBytes};

use super::{MaybeCached, ProviderError, StatusMapProvider, TypedStatusMapProvider};

pub struct HttpClient<V> {
    client: reqwest::Client,
    verifier: V,
}

impl<V> HttpClient<V> {
    pub fn new(verifier: V) -> Self {
        Self {
            client: reqwest::Client::new(),
            verifier,
        }
    }
}

impl<V> StatusMapProvider<Uri> for HttpClient<V> {}

impl<T: EncodedStatusMap + FromBytes<V>, V> TypedStatusMapProvider<Uri, T> for HttpClient<V> {
    async fn get_typed(&self, url: &Uri) -> Result<MaybeCached<T::Decoded>, ProviderError> {
        match self.client.get(url.as_str()).send().await {
            Ok(response) => {
                let media_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .ok_or(ProviderError::MissingMediaType)?
                    .to_str()
                    .map_err(|_| ProviderError::InvalidMediaType)?
                    .to_owned();

                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| ProviderError::Internal(e.to_string()))?;
                let encoded = T::from_bytes(bytes.as_ref(), &media_type, &self.verifier)
                    .await
                    .map_err(|e| ProviderError::Encoded(e.to_string()))?;
                encoded
                    .decode()
                    .map_err(|e| ProviderError::Decoding(e.to_string()))
                    .map(MaybeCached::NotCached)
            }
            Err(e) => match e.status() {
                Some(reqwest::StatusCode::NOT_FOUND) => Err(ProviderError::NotFound),
                _ => Err(ProviderError::Internal(e.to_string())),
            },
        }
    }
}
