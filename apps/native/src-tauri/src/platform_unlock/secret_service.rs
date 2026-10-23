//! Linux: segreto casuale nel portachiavi della sessione (Secret Service via D-Bus).

use std::collections::HashMap;

use authenticator_session::format_id;
use secret_service::{EncryptionType, Item, SecretService};
use zeroize::Zeroizing;

use super::{APP_ID, Method, Secret, SlotId};

pub(super) const METHOD: Option<Method> = Some(Method::SecretService);

const LABEL: &str = "Authenticator: sblocco del vault";
const SECRET_LEN: usize = 32;

fn text(e: impl core::fmt::Display) -> String {
    format!("Portachiavi di sistema non disponibile: {e}")
}

async fn connect() -> Result<SecretService<'static>, String> {
    // Sessione cifrata (DH) con il servizio: il segreto non viaggia in chiaro sul bus.
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(text)
}

fn attributes(slot: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", APP_ID), ("slot", slot)])
}

pub(super) async fn available() -> bool {
    match connect().await {
        Ok(service) => service.get_default_collection().await.is_ok(),
        Err(_) => false,
    }
}

pub(super) async fn enroll(slot: SlotId) -> Result<Secret, String> {
    let mut secret = Zeroizing::new(vec![0u8; SECRET_LEN]);
    getrandom::fill(&mut secret).map_err(text)?;
    let service = connect().await?;
    let collection = service.get_default_collection().await.map_err(text)?;
    collection.ensure_unlocked().await.map_err(text)?;
    let slot = format_id(&slot);
    collection
        .create_item(
            LABEL,
            attributes(&slot),
            &secret,
            true,
            "application/octet-stream",
        )
        .await
        .map_err(text)?;
    Ok(secret)
}

pub(super) async fn secret(slot: SlotId) -> Result<Option<Secret>, String> {
    let service = connect().await?;
    let slot = format_id(&slot);
    let found = service
        .search_items(attributes(&slot))
        .await
        .map_err(text)?;
    let item: &Item<'_> = match (found.unlocked.first(), found.locked.first()) {
        (Some(item), _) => item,
        (None, Some(item)) => {
            // Portachiavi bloccato: il sistema chiede la password della sessione.
            item.ensure_unlocked().await.map_err(text)?;
            item
        }
        (None, None) => return Ok(None),
    };
    Ok(Some(Zeroizing::new(item.get_secret().await.map_err(text)?)))
}

pub(super) async fn forget(slot: SlotId) -> Result<(), String> {
    let service = connect().await?;
    let slot = format_id(&slot);
    let found = service
        .search_items(attributes(&slot))
        .await
        .map_err(text)?;
    for item in found.unlocked.iter().chain(&found.locked) {
        item.delete().await.map_err(text)?;
    }
    Ok(())
}
