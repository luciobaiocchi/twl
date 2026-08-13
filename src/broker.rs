use crate::project::HttpMethod;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_MAX_BODY_BYTES: u64 = 16 << 20;
pub const FORWARD_HEADERS: &[&str] = &["content-type", "accept"];

/// A trusted destination and its credential. `Debug` never exposes the credential.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Route {
    #[zeroize(skip)]
    pub name: String,
    #[zeroize(skip)]
    pub upstream: String,
    pub key: String,
}

impl fmt::Debug for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Route")
            .field("name", &self.name)
            .field("upstream", &self.upstream)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerRequest {
    pub method: HttpMethod,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_BODY_BYTES,
            max_response_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerError {
    InvalidRequest,
    RouteNotFound,
    RequestTooLarge,
    ResponseTooLarge,
    UpstreamUnreachable,
    SecretReflection,
}

impl BrokerError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::RouteNotFound => "CAPABILITY_NOT_FOUND",
            Self::RequestTooLarge => "REQUEST_TOO_LARGE",
            Self::ResponseTooLarge => "RESPONSE_TOO_LARGE",
            Self::UpstreamUnreachable => "UPSTREAM_UNREACHABLE",
            Self::SecretReflection => "SECRET_REFLECTION",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "request is malformed or contains unsupported fields",
            Self::RouteNotFound => "trusted route was not found",
            Self::RequestTooLarge => "request body exceeds the configured limit",
            Self::ResponseTooLarge => "upstream response exceeds the configured limit",
            Self::UpstreamUnreachable => "upstream is unreachable",
            Self::SecretReflection => "upstream response contained protected credential data",
        }
    }

    pub fn application_status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::RouteNotFound => 404,
            Self::RequestTooLarge => 413,
            Self::ResponseTooLarge | Self::UpstreamUnreachable | Self::SecretReflection => 502,
        }
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for BrokerError {}

struct BrokerInner {
    routes: Vec<Route>,
    agent: ureq::Agent,
}

/// Security-critical upstream executor shared by every Towel frontend.
#[derive(Clone)]
pub struct Broker(Arc<BrokerInner>);

impl Broker {
    pub fn new(routes: Vec<Route>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout(Duration::from_secs(120))
            .build();
        Self(Arc::new(BrokerInner { routes, agent }))
    }

    pub fn routes(&self) -> &[Route] {
        &self.0.routes
    }

    pub fn execute_route(
        &self,
        route_name: &str,
        request: BrokerRequest,
        limits: RequestLimits,
    ) -> Result<BrokerResponse, BrokerError> {
        validate_origin_path(&request.path)?;
        if let Some(query) = request.query.as_deref() {
            validate_query(query)?;
        }
        validate_headers(&request.headers)?;
        if request.body.len() as u64 > limits.max_request_bytes {
            return Err(BrokerError::RequestTooLarge);
        }

        let route = self
            .0
            .routes
            .iter()
            .find(|route| route.name == route_name)
            .ok_or(BrokerError::RouteNotFound)?;
        let target = target_url(route, &request.path, request.query.as_deref());
        self.forward(route, &target, request, limits.max_response_bytes)
    }

    fn forward(
        &self,
        route: &Route,
        target: &str,
        request: BrokerRequest,
        max_response_bytes: u64,
    ) -> Result<BrokerResponse, BrokerError> {
        let mut upstream = self.0.agent.request(request.method.as_str(), target);
        for (name, value) in &request.headers {
            if FORWARD_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                upstream = upstream.set(name, value);
            }
        }
        upstream = upstream.set("authorization", &format!("Bearer {}", route.key));

        let response = match if request.body.is_empty() {
            upstream.call()
        } else {
            upstream.send_bytes(&request.body)
        } {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(_) => return Err(BrokerError::UpstreamUnreachable),
        };
        let status = response.status();
        let content_type = canonical_content_type(response.header("content-type")).to_string();
        let body = read_limited(response.into_reader(), max_response_bytes)
            .map_err(|_| BrokerError::ResponseTooLarge)?;
        if self
            .0
            .routes
            .iter()
            .any(|candidate| contains_secret(&body, &candidate.key))
        {
            return Err(BrokerError::SecretReflection);
        }
        Ok(BrokerResponse {
            status,
            content_type,
            body,
        })
    }
}

pub fn validate_origin_path(path: &str) -> Result<(), BrokerError> {
    if !crate::http::origin_path_is_normalized(path) {
        return Err(BrokerError::InvalidRequest);
    }
    Ok(())
}

pub fn validate_query(query: &str) -> Result<(), BrokerError> {
    if !crate::http::query_is_safe(query) {
        return Err(BrokerError::InvalidRequest);
    }
    Ok(())
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), BrokerError> {
    if headers.iter().any(|(name, value)| {
        name.is_empty()
            || name
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-')
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    }) {
        return Err(BrokerError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn target_url(route: &Route, path: &str, query: Option<&str>) -> String {
    let mut target = format!(
        "{}/{}",
        route.upstream.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    target
}

pub(crate) fn read_limited(reader: impl Read, maximum: u64) -> Result<Vec<u8>, ()> {
    let mut data = Vec::new();
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|_| ())?;
    if data.len() as u64 > maximum {
        return Err(());
    }
    Ok(data)
}

fn canonical_content_type(value: Option<&str>) -> &'static str {
    let value = value.unwrap_or_default().to_ascii_lowercase();
    if value.starts_with("application/json") {
        "application/json"
    } else if value.starts_with("text/event-stream") {
        "text/event-stream"
    } else if value.starts_with("text/") {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_secret(data: &[u8], key: &str) -> bool {
    let bearer = format!("Bearer {key}");
    [key, bearer.as_str()].iter().any(|secret| {
        contains_bytes(data, secret.as_bytes())
            || contains_bytes(data, STANDARD.encode(secret).as_bytes())
            || contains_bytes(data, STANDARD_NO_PAD.encode(secret).as_bytes())
            || contains_bytes(data, URL_SAFE_NO_PAD.encode(secret).as_bytes())
    })
}
