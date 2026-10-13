//! Talks to the root helper over its Unix socket.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::proto::{self, Request, Response};

/// A helper-side failure (or transport error, code "helper_unavailable").
#[derive(Debug, Clone)]
pub struct HelperError {
    pub code: String,
    pub msg: String,
    pub plan: Vec<String>,
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

pub type CallFuture<'a> = Pin<Box<dyn Future<Output = Result<Response, HelperError>> + Send + 'a>>;

/// Anything that answers helper requests (the real socket client, or a
/// fake in tests and the demo).
pub trait HelperApi: Send + Sync {
    fn call(&self, req: Request) -> CallFuture<'_>;
}

/// Calls the helper and decodes the result.
pub async fn call_as<T: DeserializeOwned>(
    h: &dyn HelperApi,
    req: Request,
) -> Result<(T, Response), HelperError> {
    let resp = h.call(req).await?;
    let v = serde_json::from_value(resp.result.clone()).map_err(|e| HelperError {
        code: proto::CODE_INTERNAL.into(),
        msg: format!("decode result: {e}"),
        plan: vec![],
    })?;
    Ok((v, resp))
}

pub struct Client {
    pub socket: PathBuf,
    pub timeout: Duration,
}

impl Client {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Client {
            socket: socket.into(),
            timeout: Duration::from_secs(600),
        }
    }

    async fn call_inner(&self, req: Request) -> Result<Response, HelperError> {
        let unavailable = |m: String| HelperError {
            code: "helper_unavailable".into(),
            msg: m,
            plan: vec![],
        };
        let mut c = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| unavailable(format!("helper unavailable: {e}")))?;
        let mut b = serde_json::to_vec(&req).map_err(|e| unavailable(e.to_string()))?;
        b.push(b'\n');
        c.write_all(&b)
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        let mut line = Vec::new();
        BufReader::new(c.take(proto::MAX_MESSAGE as u64))
            .read_until(b'\n', &mut line)
            .await
            .map_err(|e| unavailable(format!("helper read: {e}")))?;
        let resp: Response = serde_json::from_slice(&line)
            .map_err(|e| unavailable(format!("helper response: {e}")))?;
        if !resp.ok {
            return Err(HelperError {
                code: resp.code.clone(),
                msg: resp.error.clone(),
                plan: resp.plan.clone(),
            });
        }
        Ok(resp)
    }
}

impl HelperApi for Client {
    fn call(&self, req: Request) -> CallFuture<'_> {
        Box::pin(async move {
            match tokio::time::timeout(self.timeout, self.call_inner(req)).await {
                Ok(r) => r,
                Err(_) => Err(HelperError {
                    code: "helper_unavailable".into(),
                    msg: "helper timed out".into(),
                    plan: vec![],
                }),
            }
        })
    }
}

pub fn params<T: serde::Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or_default()
}
