use super::access_point::SecurityFeatures;
use super::error::ConnectionError;
use serde::{Deserialize, Serialize};

/// Represents a Wi-Fi network discovered during a scan.
///
/// This struct contains information about a WiFi network that was discovered
/// by NetworkManager during a scan operation.
///
/// # Examples
///
/// ```no_run
/// use nmrs::NetworkManager;
///
/// # async fn example() -> nmrs::Result<()> {
/// let nm = NetworkManager::new().await?;
///
/// // Scan for networks (None = all Wi-Fi devices)
/// nm.scan_networks(None).await?;
/// let networks = nm.list_networks(None).await?;
///
/// for net in networks {
///     println!("SSID: {}", net.ssid);
///     println!("  Signal: {}%", net.strength.unwrap_or(0));
///     println!("  Secured: {}", net.secured);
///     
///     if let Some(freq) = net.frequency {
///         let band = if freq > 5000 { "5GHz" } else { "2.4GHz" };
///         println!("  Band: {}", band);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// Device interface name (e.g., "wlan0")
    pub device: String,
    /// Network SSID (name)
    pub ssid: String,
    /// Access point MAC address (BSSID)
    pub bssid: Option<String>,
    /// Signal strength (0-100)
    pub strength: Option<u8>,
    /// Frequency in MHz (e.g., 2437 for channel 6)
    pub frequency: Option<u32>,
    /// Whether the network requires authentication
    pub secured: bool,
    /// Whether the network uses WPA-PSK authentication
    pub is_psk: bool,
    /// Whether the network uses WPA-EAP (Enterprise) authentication
    pub is_eap: bool,
    /// Whether the access point is operating in AP (hotspot) mode
    pub is_hotspot: bool,
    /// Assigned IPv4 address with CIDR notation (only present when connected)
    pub ip4_address: Option<String>,
    /// Assigned IPv6 address with CIDR notation (only present when connected)
    pub ip6_address: Option<String>,
    /// BSSID of the strongest AP for this SSID.
    #[serde(default)]
    pub best_bssid: String,
    /// All known BSSIDs for this SSID, strongest first.
    #[serde(default)]
    pub bssids: Vec<String>,
    /// `true` if this network is currently active (connected).
    #[serde(default)]
    pub is_active: bool,
    /// `true` if a saved connection profile exists for this SSID.
    #[serde(default)]
    pub known: bool,
    /// Decoded security capabilities from NM flag triplet.
    #[serde(default)]
    pub security_features: SecurityFeatures,
}

/// Detailed information about a Wi-Fi network.
///
/// Contains comprehensive information about a WiFi network, including
/// connection status, signal quality, and technical details.
///
/// # Examples
///
/// ```no_run
/// use nmrs::NetworkManager;
///
/// # async fn example() -> nmrs::Result<()> {
/// let nm = NetworkManager::new().await?;
/// let networks = nm.list_networks(None).await?;
///
/// if let Some(network) = networks.first() {
///     let info = nm.show_details(network).await?;
///     
///     println!("Network: {}", info.ssid);
///     println!("Signal: {} {}", info.strength, info.bars);
///     println!("Security: {}", info.security);
///     println!("Status: {}", info.status);
///     
///     if let Some(rate) = info.rate_mbps {
///         println!("Speed: {} Mbps", rate);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Network SSID (name)
    pub ssid: String,
    /// Access point MAC address (BSSID)
    pub bssid: String,
    /// Signal strength (0-100)
    pub strength: u8,
    /// Frequency in MHz
    pub freq: Option<u32>,
    /// WiFi channel number
    pub channel: Option<u16>,
    /// Operating mode (e.g., "infrastructure")
    pub mode: String,
    /// Connection speed in Mbps
    pub rate_mbps: Option<u32>,
    /// Visual signal strength representation (e.g., "▂▄▆█")
    pub bars: String,
    /// Security type description
    pub security: String,
    /// Connection status
    pub status: String,
    /// Assigned IPv4 address with CIDR notation (only present when connected)
    pub ip4_address: Option<String>,
    /// Assigned IPv6 address with CIDR notation (only present when connected)
    pub ip6_address: Option<String>,
}

/// For some EAP related fields, NetworkManager accepts either path to a file or just the data.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathOrBlob {
    /// Absolute path to a file on the system, without any file:// prefix.
    Path(String),
    /// Raw data.
    Blob(Vec<u8>),
}

impl PathOrBlob {
    pub fn from_path(path: impl Into<String>) -> Self {
        Self::Path(path.into())
    }

    pub fn from_blob(blob: impl Into<Vec<u8>>) -> Self {
        Self::Blob(blob.into())
    }
}

/// Options used for EAP-PEAP and EAP-TTLS.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapWithPhase2Options {
    /// Password for authentication
    pub password: String,
    /// Anonymous outer identity (for privacy)
    pub anonymous_identity: Option<String>,
    /// Phase 2 inner authentication method
    pub phase2: Phase2,
}

impl Default for EapWithPhase2Options {
    fn default() -> Self {
        Self {
            password: String::new(),
            anonymous_identity: None,
            phase2: Phase2::Mschapv2,
        }
    }
}

impl EapWithPhase2Options {
    /// Creates a new `EapWithPhase2Options` with the minimum required fields.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapWithPhase2Options, Phase2};
    ///
    /// let opts = EapWithPhase2Options::new("password")
    ///     .with_phase2(Phase2::Mschapv2);
    /// ```
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            anonymous_identity: None,
            phase2: Phase2::Mschapv2,
        }
    }

    /// Creates a new `EapWithPhase2Options` builder.
    ///
    /// This provides an alternative way to construct EAP-PEAP and EAP-TTLS options with a fluent API,
    /// making it clearer what each configuration option does.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapWithPhase2Options, Phase2};
    ///
    /// let opts = EapWithPhase2Options::builder()
    ///     .password("my_password")
    ///     .anonymous_identity("anonymous")
    ///     .phase2(Phase2::Mschapv2)
    ///     .build()
    ///     .expect("all required fields set");
    /// ```
    #[must_use]
    pub fn builder() -> EapWithPhase2OptionsBuilder {
        EapWithPhase2OptionsBuilder::default()
    }

    /// Sets the anonymous identity for privacy.
    #[must_use]
    pub fn with_anonymous_identity(mut self, anonymous_identity: impl Into<String>) -> Self {
        self.anonymous_identity = Some(anonymous_identity.into());
        self
    }

    /// Sets the Phase 2 authentication method.
    #[must_use]
    pub fn with_phase2(mut self, phase2: Phase2) -> Self {
        self.phase2 = phase2;
        self
    }
}

/// Builder for constructing `EapWithPhase2OptionsBuilder` with a fluent API.
///
/// This builder provides an ergonomic way to create EAP-PEAP and EAP-TTLS
/// authentication options, making the configuration more explicit and readable.
///
/// # Examples
///
/// ```rust
/// use nmrs::{EapWithPhase2Options, Phase2};
///
/// let opts = EapWithPhase2Options::builder()
///     .password("my_password")
///     .anonymous_identity("anonymous@company.com")
///     .phase2(Phase2::Mschapv2)
///     .build()
///     .expect("all required fields set");
/// ```
#[derive(Debug, Default)]
pub struct EapWithPhase2OptionsBuilder {
    password: Option<String>,
    anonymous_identity: Option<String>,
    phase2: Option<Phase2>,
}

impl EapWithPhase2OptionsBuilder {
    /// Sets the password for authentication.
    ///
    /// This is a required field.
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Sets the anonymous outer identity for privacy.
    ///
    /// This identity is sent in the clear during the initial handshake,
    /// while the real identity is protected inside the TLS tunnel.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::EapWithPhase2Options;
    ///
    /// let builder = EapWithPhase2Options::builder()
    ///     .anonymous_identity("anonymous@company.com");
    /// ```
    #[must_use]
    pub fn anonymous_identity(mut self, anonymous_identity: impl Into<String>) -> Self {
        self.anonymous_identity = Some(anonymous_identity.into());
        self
    }

    /// Sets the Phase 2 (inner) authentication method.
    ///
    /// This is a required field. MSCHAPv2 is commonly used with PEAP,
    /// while PAP is often used with TTLS.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapWithPhase2Options, Phase2};
    ///
    /// let builder = EapWithPhase2Options::builder()
    ///     .phase2(Phase2::Mschapv2);
    /// ```
    #[must_use]
    pub fn phase2(mut self, phase2: Phase2) -> Self {
        self.phase2 = Some(phase2);
        self
    }

    /// Builds the `EapWithPhase2Options` from the configured values.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionError::IncompleteBuilder`](crate::ConnectionError::IncompleteBuilder)
    /// if any required field is missing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapWithPhase2Options, Phase2};
    ///
    /// let opts = EapWithPhase2Options::builder()
    ///     .password("password")
    ///     .phase2(Phase2::Mschapv2)
    ///     .build()
    ///     .expect("all required fields set");
    /// ```
    #[must_use = "use the these options with EapMethod::Peap/EapMethod::Ttls or handle the error"]
    pub fn build(self) -> Result<EapWithPhase2Options, ConnectionError> {
        Ok(EapWithPhase2Options {
            password: self.password.ok_or_else(|| {
                ConnectionError::IncompleteBuilder(
                    "EAP password is required (use .password())".into(),
                )
            })?,
            anonymous_identity: self.anonymous_identity,
            phase2: self.phase2.ok_or_else(|| {
                ConnectionError::IncompleteBuilder(
                    "EAP phase 2 method is required (use .phase2())".into(),
                )
            })?,
        })
    }
}

// Options used for EAP-TLS.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapTlsOptions {
    /// Private key of the client certificate, either as a file or just the data.
    pub private_key: PathOrBlob,
    /// Password for the private key file
    pub private_key_password: Option<String>,
    /// Client certificate file, either as a file or just the data.
    pub certificate: PathOrBlob,
}

impl Default for EapTlsOptions {
    fn default() -> Self {
        Self {
            private_key: PathOrBlob::Path(String::new()),
            private_key_password: None,
            certificate: PathOrBlob::Path(String::new()),
        }
    }
}

impl EapTlsOptions {
    /// Creates a new `EapTlsOptions` with the minimum required fields.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapTlsOptions, PathOrBlob};
    ///
    /// let opts = EapTlsOptions::new(PathOrBlob::from_path("/etc/ssl/certs/client.key"), PathOrBlob::from_path("/etc/ssl/certs/client.crt"))
    ///     .with_private_key_password("password");
    /// ```
    pub fn new(private_key: PathOrBlob, certificate: PathOrBlob) -> Self {
        Self {
            private_key,
            private_key_password: None,
            certificate,
        }
    }

    /// Creates a new `EapTlsOptions` builder.
    ///
    /// This provides an alternative way to construct EAP-TLS options with a fluent API,
    /// making it clearer what each configuration option does.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapTlsOptions, PathOrBlob};
    ///
    /// let opts = EapTlsOptions::builder()
    ///     .certificate(PathOrBlob::from_path("/etc/ssl/certs/client.key"))
    ///     .private_key(PathOrBlob::from_path("/etc/ssl/certs/client.crt"))
    ///     .private_key_password("my_password")
    ///     .build()
    ///     .expect("all required fields set");
    /// ```
    #[must_use]
    pub fn builder() -> EapTlsOptionsBuilder {
        EapTlsOptionsBuilder::default()
    }

    /// Sets the password of the private key file.
    #[must_use]
    pub fn with_private_key_password(mut self, private_key_password: impl Into<String>) -> Self {
        self.private_key_password = Some(private_key_password.into());
        self
    }
}

/// Builder for constructing `EapTlsOptions` with a fluent API.
///
/// This builder provides an ergonomic way to create EAP-TLS
/// authentication options, making the configuration more explicit and readable.
///
/// # Examples
///
/// ```rust
/// use nmrs::{EapTlsOptions, PathOrBlob};
///
/// let opts = EapTlsOptions::builder()
///     .certificate(PathOrBlob::from_path("/etc/ssl/certs/client.key"))
///     .private_key(PathOrBlob::from_path("/etc/ssl/certs/client.crt"))
///     .private_key_password("my_password")
///     .build()
///     .expect("all required fields set");
/// ```
#[derive(Debug, Default)]
pub struct EapTlsOptionsBuilder {
    certificate: Option<PathOrBlob>,
    private_key: Option<PathOrBlob>,
    private_key_password: Option<String>,
}

impl EapTlsOptionsBuilder {
    /// Sets the path to the client certificate.
    ///
    /// This is a required field.
    #[must_use]
    pub fn certificate(mut self, certificate: PathOrBlob) -> Self {
        self.certificate = Some(certificate);
        self
    }

    /// Sets the path to the client private key.
    ///
    /// This is a required field.
    #[must_use]
    pub fn private_key(mut self, private_key: PathOrBlob) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the password used by the private key file.
    ///
    /// This is an optional field.
    #[must_use]
    pub fn private_key_password(mut self, private_key_password: impl Into<String>) -> Self {
        self.private_key_password = Some(private_key_password.into());
        self
    }

    /// Builds the `EapWithPhase2Options` from the configured values.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionError::IncompleteBuilder`](crate::ConnectionError::IncompleteBuilder)
    /// if any required field is missing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapTlsOptions, PathOrBlob, Phase2};
    ///
    /// let opts = EapTlsOptions::builder()
    ///     .certificate(PathOrBlob::from_path("/etc/ssl/certs/client.key"))
    ///     .private_key(PathOrBlob::from_path("/etc/ssl/certs/client.crt"))
    ///     .build()
    ///     .expect("all required fields set");
    /// ```
    #[must_use = "use the these options with EapMethod::Tls or handle the error"]
    pub fn build(self) -> Result<EapTlsOptions, ConnectionError> {
        Ok(EapTlsOptions {
            certificate: self.certificate.ok_or_else(|| {
                ConnectionError::IncompleteBuilder(
                    "certificate file is required (use .certificate())".into(),
                )
            })?,
            private_key: self.private_key.ok_or_else(|| {
                ConnectionError::IncompleteBuilder(
                    "private key file is required (use .private_key())".into(),
                )
            })?,
            private_key_password: self.private_key_password,
        })
    }
}

/// EAP (Extensible Authentication Protocol) method for WPA-Enterprise Wi-Fi.
///
/// These are the outer authentication methods used in 802.1X authentication.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapMethod {
    /// Protected EAP (PEAPv0) - tunnels inner authentication in TLS.
    /// Most commonly used with MSCHAPv2 inner authentication.
    Peap(EapWithPhase2Options),
    /// Tunneled TLS (EAP-TTLS) - similar to PEAP but more flexible.
    /// Can use various inner authentication methods like PAP or MSCHAPv2.
    Ttls(EapWithPhase2Options),
    /// TLS - Certificate-based authentication.
    Tls(EapTlsOptions),
}

/// Phase 2 (inner) authentication methods for EAP connections.
///
/// These methods run inside the TLS tunnel established by the outer
/// EAP method (PEAP or TTLS).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase2 {
    /// Microsoft Challenge Handshake Authentication Protocol v2.
    /// More secure than PAP, commonly used with PEAP.
    Mschapv2,
    /// Password Authentication Protocol.
    /// Simple plaintext password (protected by TLS tunnel).
    /// Often used with TTLS.
    Pap,
}

/// EAP options for WPA-EAP (Enterprise) Wi-Fi connections.
///
/// Configuration for 802.1X authentication, commonly used in corporate
/// and educational networks.
///
/// # Examples
///
/// ## PEAP with MSCHAPv2 (Common Corporate Setup)
///
/// ```rust
/// use nmrs::{EapOptions, EapMethod, EapWithPhase2Options, Phase2};
///
/// let opts = EapOptions::new("employee@company.com")
///     .with_domain_suffix_match("company.com")
///     .with_system_ca_certs(true)  // Use system certificate store
///     .with_method(EapMethod::Peap(EapWithPhase2Options::new("my_password")
///         .with_anonymous_identity("anonymous@company.com")
///         .with_phase2(Phase2::Mschapv2)));
/// ```
///
/// ## TTLS with PAP (Alternative Setup)
///
/// ```rust
/// use nmrs::{EapOptions, EapMethod, EapWithPhase2Options, PathOrBlob, Phase2};
///
/// let opts = EapOptions::new("student@university.edu")
///     .with_ca_cert(PathOrBlob::from_path("/etc/ssl/certs/university-ca.pem"))
///     .with_method(EapMethod::Ttls(EapWithPhase2Options::new("password")
///         .with_phase2(Phase2::Pap)));
/// ```
/// // TODO: Example EAP-TLS.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapOptions {
    /// User identity (usually email or username)
    pub identity: String,
    /// Domain to match against server certificate
    pub domain_suffix_match: Option<String>,
    /// Path to CA certificate file
    pub ca_cert: Option<PathOrBlob>,
    /// Use system CA certificate store
    pub system_ca_certs: bool,
    /// EAP method (PEAP or TTLS)
    pub method: EapMethod,
}

impl Default for EapOptions {
    fn default() -> Self {
        Self {
            identity: String::new(),
            domain_suffix_match: None,
            ca_cert: None,
            system_ca_certs: false,
            method: EapMethod::Peap(EapWithPhase2Options::default()),
        }
    }
}

impl EapOptions {
    /// Creates a new `EapOptions` with the minimum required fields.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapOptions, EapMethod, EapWithPhase2Options, Phase2};
    ///
    /// let opts = EapOptions::new("user@example.com")
    ///     .with_method(EapMethod::Peap(EapWithPhase2Options::new("password")
    ///         .with_phase2(Phase2::Mschapv2)));
    /// ```
    pub fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            ..Default::default()
        }
    }

    /// Creates a new `EapOptions` builder.
    ///
    /// This provides an alternative way to construct EAP options with a fluent API,
    /// making it clearer what each configuration option does.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapOptions, EapMethod, EapWithPhase2Options, Phase2};
    ///
    /// let opts = EapOptions::builder()
    ///     .identity("user@company.com")
    ///     .method(EapMethod::Peap(EapWithPhase2Options::builder()
    ///         .password("my_password")
    ///         .phase2(Phase2::Mschapv2)
    ///         .build()
    ///         .expect("all required fields set")))
    ///     .domain_suffix_match("company.com")
    ///     .system_ca_certs(true)
    ///     .build()
    ///     .expect("all required fields set");
    /// ```
    #[must_use]
    pub fn builder() -> EapOptionsBuilder {
        EapOptionsBuilder::default()
    }

    /// Sets the domain suffix to match against the server certificate.
    #[must_use]
    pub fn with_domain_suffix_match(mut self, domain: impl Into<String>) -> Self {
        self.domain_suffix_match = Some(domain.into());
        self
    }

    /// Sets the path to the CA certificate file.
    #[must_use]
    pub fn with_ca_cert(mut self, ca_cert: PathOrBlob) -> Self {
        self.ca_cert = Some(ca_cert);
        self
    }

    /// Sets whether to use the system CA certificate store.
    #[must_use]
    pub fn with_system_ca_certs(mut self, use_system: bool) -> Self {
        self.system_ca_certs = use_system;
        self
    }

    /// Sets the EAP method (PEAP or TTLS).
    #[must_use]
    pub fn with_method(mut self, method: EapMethod) -> Self {
        self.method = method;
        self
    }
}

/// Builder for constructing `EapOptions` with a fluent API.
///
/// This builder provides an ergonomic way to create EAP (Enterprise WiFi)
/// authentication options, making the configuration more explicit and readable.
///
/// # Examples
///
/// ## PEAP with MSCHAPv2 (Common Corporate Setup)
///
/// ```rust
/// use nmrs::{EapOptions, EapMethod, EapWithPhase2Options, Phase2};
///
/// let opts = EapOptions::builder()
///     .identity("user@company.com")
///     .method(EapMethod::Peap(EapWithPhase2Options::builder()
///         .password("my_password")
///         .phase2(Phase2::Mschapv2)
///         .anonymous_identity("anonymous@company.com")
///         .build()
///         .expect("all required fields set")))
///     .domain_suffix_match("company.com")
///     .system_ca_certs(true)
///     .build()
///     .expect("all required fields set");
/// ```
///
/// ## TTLS with PAP
///
/// ```rust
/// use nmrs::{EapOptions, EapMethod, EapWithPhase2Options, Phase2, PathOrBlob};
///
/// let opts = EapOptions::builder()
///     .identity("student@university.edu")
///     .method(EapMethod::Peap(EapWithPhase2Options::builder()
///         .password("password")
///         .phase2(Phase2::Pap)
///         .anonymous_identity("anonymous@company.com")
///         .build()
///         .expect("all required fields set")))
///     .ca_cert(PathOrBlob::from_path("/etc/ssl/certs/university-ca.pem"))
///     .build()
///     .expect("all required fields set");
/// ```
///
/// ## TLS
///
/// ```rust
/// use nmrs::{EapOptions, EapMethod, EapTlsOptions, Phase2, PathOrBlob};
///
/// let opts = EapOptions::builder()
///     .identity("student@university.edu")
///     .method(EapMethod::Tls(EapTlsOptions::builder()
///         .certificate(PathOrBlob::from_path("/etc/ssl/certs/client.key"))
///         .private_key(PathOrBlob::from_path("/etc/ssl/certs/client.crt"))
///         .private_key_password("my_password")
///         .build()
///         .expect("all required fields set")))
///     .ca_cert(PathOrBlob::from_path("/etc/ssl/certs/university-ca.pem"))
///     .build()
///     .expect("all required fields set");
/// ```
#[derive(Debug, Default)]
pub struct EapOptionsBuilder {
    identity: Option<String>,
    domain_suffix_match: Option<String>,
    ca_cert: Option<PathOrBlob>,
    system_ca_certs: bool,
    method: Option<EapMethod>,
}

impl EapOptionsBuilder {
    /// Sets the user identity (usually email or username).
    ///
    /// This is a required field.
    #[must_use]
    pub fn identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Sets the domain suffix to match against the server certificate.
    ///
    /// This provides additional security by verifying the server's certificate
    /// matches the expected domain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::EapOptions;
    ///
    /// let builder = EapOptions::builder()
    ///     .domain_suffix_match("company.com");
    /// ```
    #[must_use]
    pub fn domain_suffix_match(mut self, domain: impl Into<String>) -> Self {
        self.domain_suffix_match = Some(domain.into());
        self
    }

    /// Sets the path to the CA certificate file.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapOptions, PathOrBlob};
    ///
    /// let builder = EapOptions::builder()
    ///     .ca_cert(PathOrBlob::from_path("/etc/ssl/certs/company-ca.pem"));
    /// ```
    #[must_use]
    pub fn ca_cert(mut self, ca_cert: PathOrBlob) -> Self {
        self.ca_cert = Some(ca_cert);
        self
    }

    /// Sets whether to use the system CA certificate store.
    ///
    /// When enabled, the system's trusted CA certificates will be used
    /// to validate the server certificate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::EapOptions;
    ///
    /// let builder = EapOptions::builder()
    ///     .system_ca_certs(true);
    /// ```
    #[must_use]
    pub fn system_ca_certs(mut self, use_system: bool) -> Self {
        self.system_ca_certs = use_system;
        self
    }

    /// Sets the EAP method (PEAP or TTLS).
    ///
    /// This is a required field. PEAP is more common in corporate environments,
    /// while TTLS offers more flexibility in inner authentication methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapOptions, EapMethod, EapWithPhase2Options};
    ///
    /// let builder = EapOptions::builder()
    ///     .method(EapMethod::Peap(EapWithPhase2Options::default()));
    /// ```
    #[must_use]
    pub fn method(mut self, method: EapMethod) -> Self {
        self.method = Some(method);
        self
    }

    /// Builds the `EapOptions` from the configured values.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionError::IncompleteBuilder`](crate::ConnectionError::IncompleteBuilder)
    /// if any required field is missing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nmrs::{EapOptions, EapMethod, Phase2, EapWithPhase2Options};
    ///
    /// let opts = EapOptions::builder()
    ///     .identity("user@example.com")
    ///     .method(EapMethod::Peap(EapWithPhase2Options::builder()
    ///         .password("password")
    ///         .phase2(Phase2::Mschapv2)
    ///         .build()
    ///         .expect("all required fields set")))
    ///     .build()
    ///     .expect("all required fields set");
    /// ```
    #[must_use = "use the EAP options with WifiSecurity::WpaEap or handle the error"]
    pub fn build(self) -> Result<EapOptions, ConnectionError> {
        if let Some(EapMethod::Tls(..)) = self.method
            && self.ca_cert.is_none()
            && !self.system_ca_certs
        {
            return Err(ConnectionError::IncompleteBuilder(
                "EAP_TLS requires a CA certificate (use .ca_cert_path() or .system_ca_certs())"
                    .into(),
            ));
        }

        Ok(EapOptions {
            identity: self.identity.ok_or_else(|| {
                ConnectionError::IncompleteBuilder(
                    "EAP identity is required (use .identity())".into(),
                )
            })?,
            domain_suffix_match: self.domain_suffix_match,
            ca_cert: self.ca_cert,
            system_ca_certs: self.system_ca_certs,
            method: self.method.ok_or_else(|| {
                ConnectionError::IncompleteBuilder("EAP method is required (use .method())".into())
            })?,
        })
    }
}

/// Wi-Fi connection security types.
///
/// Represents the authentication method for connecting to a WiFi network.
///
/// # Variants
///
/// - [`Open`](WifiSecurity::Open) - No authentication required (open network)
/// - [`WpaPsk`](WifiSecurity::WpaPsk) - WPA/WPA2/WPA3 Personal (password-based)
/// - [`WpaEap`](WifiSecurity::WpaEap) - WPA/WPA2 Enterprise (802.1X authentication)
///
/// # Examples
///
/// ## Open Network
///
/// ```rust
/// use nmrs::WifiSecurity;
///
/// let security = WifiSecurity::Open;
/// ```
///
/// ## Password-Protected Network
///
/// ```no_run
/// use nmrs::{NetworkManager, WifiSecurity};
///
/// # async fn example() -> nmrs::Result<()> {
/// let nm = NetworkManager::new().await?;
///
/// nm.connect("HomeWiFi", None, WifiSecurity::WpaPsk {
///     psk: "my_secure_password".into()
/// }).await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Enterprise Network (WPA-EAP)
///
/// ```no_run
/// use nmrs::{NetworkManager, WifiSecurity, EapOptions, EapMethod, EapWithPhase2Options, Phase2};
///
/// # async fn example() -> nmrs::Result<()> {
/// let nm = NetworkManager::new().await?;
///
/// let eap_opts = EapOptions::new("user@company.com")
///     .with_domain_suffix_match("company.com")
///     .with_system_ca_certs(true)
///     .with_method(EapMethod::Peap(EapWithPhase2Options::new("password")
///         .with_phase2(Phase2::Mschapv2)));
///
/// nm.connect("CorpWiFi", None, WifiSecurity::WpaEap {
///     opts: eap_opts
/// }).await?;
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiSecurity {
    /// Open network (no authentication)
    Open,
    /// WPA-PSK (password-based authentication)
    WpaPsk {
        /// Pre-shared key (password)
        psk: String,
    },
    /// WPA-EAP (Enterprise authentication via 802.1X)
    WpaEap {
        /// EAP configuration options
        opts: EapOptions,
    },
}

impl WifiSecurity {
    /// Returns `true` if this security type requires authentication.
    #[must_use]
    pub fn secured(&self) -> bool {
        !matches!(self, WifiSecurity::Open)
    }

    /// Returns `true` if this is a WPA-PSK (password-based) security type.
    #[must_use]
    pub fn is_psk(&self) -> bool {
        matches!(self, WifiSecurity::WpaPsk { .. })
    }

    /// Returns `true` if this is a WPA-EAP (Enterprise/802.1X) security type.
    #[must_use]
    pub fn is_eap(&self) -> bool {
        matches!(self, WifiSecurity::WpaEap { .. })
    }
}

impl Network {
    /// Merges another access point's information into this network.
    ///
    /// When multiple access points share the same SSID (e.g., mesh networks),
    /// this method keeps the strongest signal and combines security flags.
    /// Used internally during network scanning to deduplicate results.
    pub fn merge_ap(&mut self, other: &Network) {
        if let Some(ref b) = other.bssid
            && !self.bssids.contains(b)
        {
            self.bssids.push(b.clone());
        }

        if other.strength.unwrap_or(0) > self.strength.unwrap_or(0) {
            self.strength = other.strength;
            self.frequency = other.frequency;
            self.bssid = other.bssid.clone();
            self.best_bssid = other.best_bssid.clone();
            self.security_features = other.security_features;
        }

        self.secured |= other.secured;
        self.is_psk |= other.is_psk;
        self.is_eap |= other.is_eap;
        self.is_hotspot |= other.is_hotspot;
        self.is_active |= other.is_active;
        self.known |= other.known;

        if self.ip4_address.is_none() {
            self.ip4_address.clone_from(&other.ip4_address);
        }
        if self.ip6_address.is_none() {
            self.ip6_address.clone_from(&other.ip6_address);
        }
        if self.device.is_empty() {
            self.device.clone_from(&other.device);
        }
    }
}

#[cfg(test)]
mod network_merge_tests {
    use super::Network;

    #[test]
    fn merge_ap_keeps_ip_and_device_when_stronger_ap_has_none() {
        let mut weaker_connected = Network {
            device: "wlan0".into(),
            ssid: "net".into(),
            bssid: Some("aa:aa:aa:aa:aa:aa".into()),
            strength: Some(20),
            frequency: Some(5200),
            secured: true,
            is_psk: true,
            is_eap: false,
            is_hotspot: false,
            ip4_address: Some("192.168.1.5/24".into()),
            ip6_address: Some("fe80::1/64".into()),
            best_bssid: "aa:aa:aa:aa:aa:aa".into(),
            bssids: vec!["aa:aa:aa:aa:aa:aa".into()],
            is_active: true,
            known: false,
            security_features: Default::default(),
        };
        let stronger = Network {
            device: String::new(),
            ssid: "net".into(),
            bssid: Some("bb:bb:bb:bb:bb:bb".into()),
            strength: Some(90),
            frequency: Some(5200),
            secured: true,
            is_psk: true,
            is_eap: false,
            is_hotspot: false,
            ip4_address: None,
            ip6_address: None,
            best_bssid: "bb:bb:bb:bb:bb:bb".into(),
            bssids: vec!["bb:bb:bb:bb:bb:bb".into()],
            is_active: false,
            known: false,
            security_features: Default::default(),
        };
        weaker_connected.merge_ap(&stronger);
        assert_eq!(weaker_connected.strength, Some(90));
        assert_eq!(weaker_connected.bssid, Some("bb:bb:bb:bb:bb:bb".into()));
        assert_eq!(weaker_connected.best_bssid, "bb:bb:bb:bb:bb:bb");
        assert_eq!(weaker_connected.ip4_address, Some("192.168.1.5/24".into()));
        assert_eq!(weaker_connected.ip6_address, Some("fe80::1/64".into()));
        assert_eq!(weaker_connected.device, "wlan0");
        assert!(weaker_connected.is_active);
        assert_eq!(weaker_connected.bssids.len(), 2);
    }
}
