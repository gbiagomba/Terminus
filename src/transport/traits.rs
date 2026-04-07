use anyhow::Result;
use async_trait::async_trait;

use crate::transport::types::{TerminusRequest, TerminusResponse};

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn send(&self, request: TerminusRequest) -> Result<TerminusResponse>;
}
