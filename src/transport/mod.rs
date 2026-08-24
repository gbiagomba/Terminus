pub mod http12;
pub mod http3;
// Foundation transport consumed by the smuggling/desync modules (other agents).
// Allow dead_code until those call sites land so the build stays warning-clean.
#[allow(dead_code)]
pub mod raw;
pub mod traits;
pub mod types;

pub use http12::Http12Transport;
pub use http3::Http3Transport;
#[allow(unused_imports)]
pub use raw::{build_raw_request, RawExchange, RawHttp1Transport};
pub use traits::HttpTransport;
pub use types::{HttpVersion, TerminusRequest, TransportConfig};
