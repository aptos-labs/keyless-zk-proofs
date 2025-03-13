use anyhow::Result;
use serde::de::DeserializeOwned;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

pub async fn fetch_and_cache_resource<T: DeserializeOwned>(
    resource_url: &str,
    resource_holder: &RwLock<Option<T>>,
) -> Result<()> {
    let resource = reqwest::get(resource_url).await?.json::<T>().await?;
    *resource_holder.write().unwrap() = Some(resource);
    Ok(())
}

pub fn start_external_resource_refresh_loop<
    T: DeserializeOwned + ExternalResource + Send + Sync + 'static,
>(
    url: &str,
    refresh_interval: Duration,
    local_cache: Arc<RwLock<Option<T>>>,
) {
    info!(
        "Starting external resource refresh loop for {}",
        T::resource_name()
    );
    let url = url.to_string();
    let _handle = tokio::spawn(async move {
        loop {
            let result = fetch_and_cache_resource(&url, local_cache.as_ref()).await;
            match result {
                Ok(_vk) => {
                    debug!("fetch_and_cache_resource {} succeeded.", T::resource_name());
                }
                Err(e) => {
                    warn!(
                        "fetch_and_cache_resource {} failed: {}",
                        T::resource_name(),
                        e
                    );
                }
            }

            tokio::time::sleep(refresh_interval).await;
        }
    });
}

pub trait ExternalResource {
    fn resource_name() -> String;
}
