/// Connect to a WPA-Enterprise (802.1X) WiFi network using EAP authentication.
///
/// This example demonstrates using the builder pattern for creating EAP options,
/// which is useful for corporate/university WiFi networks that require 802.1X authentication.
use nmrs::{EapMethod, EapOptions, EapWithPhase2Options, NetworkManager, Phase2, WifiSecurity};


#[tokio::main]
async fn main() -> nmrs::Result<()> {
    let nm = NetworkManager::new().await?;

    // Use the builder pattern for a more readable EAP configuration
    let eap_opts = EapOptions::builder()
        .identity("user@company.com")
        .method(EapMethod::Peap(
            EapWithPhase2Options::builder()
                .password(std::env::var("WIFI_PASSWORD").expect("Set WIFI_PASSWORD env var"))
                .phase2(Phase2::Mschapv2)
                .anonymous_identity("anonymous@company.com")
                .build()?,
        ))
        .domain_suffix_match("company.com")
        .system_ca_certs(true)
        .build()?;

    let security = WifiSecurity::WpaEap { opts: eap_opts };

    println!("Connecting to enterprise WiFi network...");
    nm.connect("CorpNetwork", None, security).await?;

    println!("Successfully connected to enterprise WiFi!");

    Ok(())
}
