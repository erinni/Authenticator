//! Genera il contesto Tauri e i permessi dei comandi dell'app.

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Ogni comando richiede un permesso esplicito (`allow-<comando>`) concesso dalle
    // capability: un comando dimenticato qui non è invocabile dalla webview.
    let manifest = tauri_build::AppManifest::new().commands(authenticator_commands());
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))?;
    Ok(())
}

const fn authenticator_commands() -> &'static [&'static str] {
    &[
        "load_vault",
        "save_vault",
        "create",
        "open",
        "open_recovery",
        "open_external",
        "external_slots",
        "verify",
        "lock",
        "seal",
        "accounts",
        "codes",
        "next_hotp",
        "add_uri",
        "remove",
        "import_data",
        "scan_qr",
        "change_password",
        "create_recovery_key",
        "set_external",
        "remove_external",
        "export_backup",
        "restore_backup",
        "platform_unlock",
        "enable_platform_unlock",
        "unlock_with_platform",
        "disable_platform_unlock",
    ]
}
