use crate::broker::{
    validate_origin_path, validate_query, Broker, BrokerError, BrokerRequest, BrokerResponse,
    RequestLimits, Route, DEFAULT_MAX_BODY_BYTES,
};
use crate::project::{AgentCapability, HttpMethod, ModelError, Project};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, BufRead, Write};
use std::str::FromStr;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_PROTOCOL_LINE_BYTES: usize = 24 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityInvocation {
    pub capability: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    CapabilityNotFound,
    MethodDenied,
    PathDenied,
    InvalidRequest,
    RequestTooLarge,
    ResponseTooLarge,
    UpstreamUnreachable,
    SecretReflection,
    ProtocolMismatch,
}

impl CapabilityError {
    pub fn code(self) -> &'static str {
        match self {
            Self::CapabilityNotFound => "CAPABILITY_NOT_FOUND",
            Self::MethodDenied => "METHOD_DENIED",
            Self::PathDenied => "PATH_DENIED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::RequestTooLarge => "REQUEST_TOO_LARGE",
            Self::ResponseTooLarge => "RESPONSE_TOO_LARGE",
            Self::UpstreamUnreachable => "UPSTREAM_UNREACHABLE",
            Self::SecretReflection => "SECRET_REFLECTION",
            Self::ProtocolMismatch => "PROTOCOL_MISMATCH",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::CapabilityNotFound => "capability was not found",
            Self::MethodDenied => "capability does not allow this HTTP method",
            Self::PathDenied => "capability does not allow this path",
            Self::InvalidRequest => "request is malformed or contains unsupported fields",
            Self::RequestTooLarge => "request exceeds the configured size limit",
            Self::ResponseTooLarge => "upstream response exceeds the configured size limit",
            Self::UpstreamUnreachable => "upstream is unreachable",
            Self::SecretReflection => "upstream response contained protected credential data",
            Self::ProtocolMismatch => "unsupported or missing capability protocol handshake",
        }
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for CapabilityError {}

impl From<BrokerError> for CapabilityError {
    fn from(error: BrokerError) -> Self {
        match error {
            BrokerError::InvalidRequest => Self::InvalidRequest,
            BrokerError::RouteNotFound => Self::CapabilityNotFound,
            BrokerError::RequestTooLarge => Self::RequestTooLarge,
            BrokerError::ResponseTooLarge => Self::ResponseTooLarge,
            BrokerError::UpstreamUnreachable => Self::UpstreamUnreachable,
            BrokerError::SecretReflection => Self::SecretReflection,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityDescriptor<'a> {
    name: &'a str,
    description: &'a str,
    methods: Vec<&'static str>,
    path_prefixes: &'a [String],
    max_response_bytes: u64,
}

impl<'a> From<&'a AgentCapability> for CapabilityDescriptor<'a> {
    fn from(capability: &'a AgentCapability) -> Self {
        Self {
            name: capability.name(),
            description: capability.description(),
            methods: capability
                .policy()
                .methods()
                .iter()
                .map(|method| method.as_str())
                .collect(),
            path_prefixes: capability.policy().path_prefixes(),
            max_response_bytes: capability.policy().max_response_bytes(),
        }
    }
}

/// Resolves named, narrowed authority before calling the shared broker core.
#[derive(Clone)]
pub struct CapabilityBroker {
    capabilities: Vec<AgentCapability>,
    broker: Broker,
}

impl CapabilityBroker {
    pub fn from_project(project: Project) -> Result<Self, ModelError> {
        project.validate()?;
        let (_, project_routes, capabilities) = project.into_parts();
        let capability_routes: HashSet<_> = capabilities
            .iter()
            .map(|capability| capability.route())
            .collect();
        let routes = project_routes
            .into_iter()
            .filter(|route| capability_routes.contains(route.name()))
            .map(|route| {
                let (name, upstream, key, _) = route.into_parts();
                Route {
                    name,
                    upstream,
                    key,
                }
            })
            .collect();
        drop(capability_routes);
        Self::new(routes, capabilities)
    }

    pub fn new(routes: Vec<Route>, capabilities: Vec<AgentCapability>) -> Result<Self, ModelError> {
        let route_names: HashSet<_> = routes.iter().map(|route| route.name.as_str()).collect();
        let mut names = HashSet::new();
        for capability in &capabilities {
            capability.validate()?;
            if !names.insert(capability.name()) {
                return Err(ModelError::DuplicateCapability);
            }
            if !route_names.contains(capability.route()) {
                return Err(ModelError::MissingCapabilityRoute);
            }
        }
        Ok(Self {
            capabilities,
            broker: Broker::new(routes),
        })
    }

    pub fn capabilities(&self) -> &[AgentCapability] {
        &self.capabilities
    }

    pub fn descriptors(&self) -> Vec<CapabilityDescriptor<'_>> {
        self.capabilities.iter().map(Into::into).collect()
    }

    pub fn invoke(
        &self,
        invocation: CapabilityInvocation,
    ) -> Result<BrokerResponse, CapabilityError> {
        let capability = self
            .capabilities
            .iter()
            .find(|candidate| candidate.name() == invocation.capability)
            .ok_or(CapabilityError::CapabilityNotFound)?;
        let method = HttpMethod::from_str(&invocation.method)
            .map_err(|_| CapabilityError::InvalidRequest)?;
        if !capability.policy().allows_method(method) {
            return Err(CapabilityError::MethodDenied);
        }
        validate_origin_path(&invocation.path).map_err(|_| CapabilityError::InvalidRequest)?;
        if !capability.policy().allows_path(&invocation.path) {
            return Err(CapabilityError::PathDenied);
        }
        if let Some(query) = invocation.query.as_deref() {
            validate_query(query).map_err(|_| CapabilityError::InvalidRequest)?;
        }
        if invocation
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            return Err(CapabilityError::InvalidRequest);
        }

        self.broker
            .execute_route(
                capability.route(),
                BrokerRequest {
                    method,
                    path: invocation.path,
                    query: invocation.query,
                    headers: invocation.headers,
                    body: invocation.body,
                },
                RequestLimits {
                    max_request_bytes: DEFAULT_MAX_BODY_BYTES,
                    max_response_bytes: capability.policy().max_response_bytes(),
                },
            )
            .map_err(Into::into)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloRequest {
    op: String,
    protocol: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListRequest {
    id: Value,
    op: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvokeRequest {
    id: Value,
    op: String,
    capability: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_encoding: Option<BodyEncoding>,
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum BodyEncoding {
    Utf8,
    Base64,
}

enum Frame {
    Data(Vec<u8>),
    Oversized,
    Eof,
}

/// Serve protocol v1 until EOF. Stdout receives protocol frames only.
pub fn serve_stdio(
    broker: CapabilityBroker,
    mut input: impl BufRead,
    mut output: impl Write,
) -> io::Result<()> {
    let mut initialized = false;
    loop {
        let frame = read_frame(&mut input)?;
        let line = match frame {
            Frame::Eof => return Ok(()),
            Frame::Oversized => {
                write_error(&mut output, None, CapabilityError::RequestTooLarge)?;
                continue;
            }
            Frame::Data(line) => line,
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            write_error(&mut output, None, CapabilityError::InvalidRequest)?;
            continue;
        }
        let value: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(_) => {
                write_error(&mut output, None, CapabilityError::InvalidRequest)?;
                continue;
            }
        };
        let operation = value.get("op").and_then(Value::as_str).unwrap_or_default();
        if operation == "hello" {
            let request: HelloRequest = match serde_json::from_value(value) {
                Ok(request) => request,
                Err(_) => {
                    write_error(&mut output, None, CapabilityError::InvalidRequest)?;
                    continue;
                }
            };
            if request.op != "hello" || request.protocol != PROTOCOL_VERSION {
                write_error(&mut output, None, CapabilityError::ProtocolMismatch)?;
                continue;
            }
            initialized = true;
            write_json(
                &mut output,
                &json!({
                    "ok": true,
                    "protocol": PROTOCOL_VERSION,
                    "server": "twl",
                    "capability_count": broker.capabilities().len()
                }),
            )?;
            continue;
        }
        if !initialized {
            write_error(
                &mut output,
                value.get("id").cloned(),
                CapabilityError::ProtocolMismatch,
            )?;
            continue;
        }
        match operation {
            "list" => {
                let request: ListRequest = match serde_json::from_value(value) {
                    Ok(request) => request,
                    Err(_) => {
                        write_error(&mut output, None, CapabilityError::InvalidRequest)?;
                        continue;
                    }
                };
                if request.op != "list" {
                    write_error(
                        &mut output,
                        Some(request.id),
                        CapabilityError::InvalidRequest,
                    )?;
                    continue;
                }
                write_json(
                    &mut output,
                    &json!({
                        "id": request.id,
                        "ok": true,
                        "capabilities": broker.descriptors()
                    }),
                )?;
            }
            "invoke" => {
                let request: InvokeRequest = match serde_json::from_value(value) {
                    Ok(request) => request,
                    Err(_) => {
                        write_error(&mut output, None, CapabilityError::InvalidRequest)?;
                        continue;
                    }
                };
                if request.op != "invoke" {
                    write_error(
                        &mut output,
                        Some(request.id),
                        CapabilityError::InvalidRequest,
                    )?;
                    continue;
                }
                let id = request.id.clone();
                match invocation_from_request(request).and_then(|request| broker.invoke(request)) {
                    Ok(response) => write_json(
                        &mut output,
                        &json!({
                            "id": id,
                            "ok": true,
                            "status": response.status,
                            "content_type": response.content_type,
                            "body_encoding": "base64",
                            "body": STANDARD.encode(response.body)
                        }),
                    )?,
                    Err(error) => write_error(&mut output, Some(id), error)?,
                }
            }
            _ => write_error(
                &mut output,
                value.get("id").cloned(),
                CapabilityError::InvalidRequest,
            )?,
        }
    }
}

fn invocation_from_request(
    request: InvokeRequest,
) -> Result<CapabilityInvocation, CapabilityError> {
    let body = match (request.body, request.body_encoding) {
        (None, None | Some(BodyEncoding::Utf8)) => Vec::new(),
        (None, Some(BodyEncoding::Base64)) => return Err(CapabilityError::InvalidRequest),
        (Some(body), None | Some(BodyEncoding::Utf8)) => body.into_bytes(),
        (Some(body), Some(BodyEncoding::Base64)) => STANDARD
            .decode(body)
            .map_err(|_| CapabilityError::InvalidRequest)?,
    };
    if body.len() as u64 > DEFAULT_MAX_BODY_BYTES {
        return Err(CapabilityError::RequestTooLarge);
    }
    let mut headers: Vec<_> = request.headers.into_iter().collect();
    if let Some(content_type) = request.content_type {
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        {
            return Err(CapabilityError::InvalidRequest);
        }
        headers.push(("content-type".into(), content_type));
    }
    Ok(CapabilityInvocation {
        capability: request.capability,
        method: request.method,
        path: request.path,
        query: request.query,
        headers,
        body,
    })
}

fn read_frame(input: &mut impl BufRead) -> io::Result<Frame> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() && !oversized {
                Ok(Frame::Eof)
            } else if oversized {
                Ok(Frame::Oversized)
            } else {
                Ok(Frame::Data(line))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if !oversized {
            let payload = if newline.is_some() {
                &available[..consumed - 1]
            } else {
                &available[..consumed]
            };
            if line.len().saturating_add(payload.len()) > MAX_PROTOCOL_LINE_BYTES {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(payload);
            }
        }
        input.consume(consumed);
        if newline.is_some() {
            return if oversized {
                Ok(Frame::Oversized)
            } else {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                Ok(Frame::Data(line))
            };
        }
    }
}

fn write_error(
    output: &mut impl Write,
    id: Option<Value>,
    error: CapabilityError,
) -> io::Result<()> {
    let mut response = json!({
        "ok": false,
        "error": {"code": error.code(), "message": error.message()}
    });
    if let Some(id) = id {
        response["id"] = id;
    }
    write_json(output, &response)
}

fn write_json(output: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::{ProjectRoute, DEFAULT_CAPABILITY_RESPONSE_BYTES};

    #[test]
    fn project_session_keeps_only_capability_referenced_credentials() {
        let project = Project::with_capabilities(
            "demo".into(),
            vec![
                ProjectRoute::agent_only(
                    "github".into(),
                    "https://api.github.com".into(),
                    "github-secret".into(),
                )
                .unwrap(),
                ProjectRoute::agent_only(
                    "unused".into(),
                    "https://unused.example.test".into(),
                    "unused-secret".into(),
                )
                .unwrap(),
            ],
            vec![AgentCapability::new(
                "github-read".into(),
                "Read repository data.".into(),
                "github".into(),
                [HttpMethod::GET],
                vec!["/repos/".into()],
                DEFAULT_CAPABILITY_RESPONSE_BYTES,
            )
            .unwrap()],
        )
        .unwrap();

        let broker = CapabilityBroker::from_project(project).unwrap();
        assert_eq!(broker.broker.routes().len(), 1);
        assert_eq!(broker.broker.routes()[0].name, "github");
    }
}
