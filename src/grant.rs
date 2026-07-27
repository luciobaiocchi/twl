use crate::config::SessionLimits;
use crate::policy::{RoutePolicy, SecretValue, VaultPayload, MAX_ROUTES_PER_SESSION};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    pub route_ids: Vec<String>,
    pub limits: SessionLimits,
}

#[derive(Debug)]
pub struct GrantedRoute {
    pub id: String,
    pub policy: RoutePolicy,
    pub credential: SecretValue,
}

#[derive(Debug)]
pub struct TrustedGrant {
    pub routes: Vec<GrantedRoute>,
}

/// Interface implemented by an opened local vault today and by a trusted
/// control-plane grant provider in a future integration.
pub trait GrantProvider {
    fn issue_grant(&self, request: &GrantRequest) -> Result<TrustedGrant, String>;
}

impl GrantProvider for VaultPayload {
    fn issue_grant(&self, request: &GrantRequest) -> Result<TrustedGrant, String> {
        self.validate()?;
        if request.route_ids.is_empty() {
            return Err("a grant must contain at least one route".into());
        }
        if request.route_ids.len() > MAX_ROUTES_PER_SESSION {
            return Err(format!(
                "a grant may contain at most {MAX_ROUTES_PER_SESSION} routes"
            ));
        }

        let mut unique = BTreeSet::new();
        let mut routes = Vec::with_capacity(request.route_ids.len());
        for id in &request.route_ids {
            if !unique.insert(id) {
                return Err(format!("route {id} was requested more than once"));
            }
            let mut policy = self
                .routes
                .get(id)
                .cloned()
                .ok_or_else(|| format!("trusted vault does not define route {id}"))?;
            apply_limits(&mut policy, &request.limits);
            let credential = self
                .credentials
                .get(&policy.credential)
                .cloned()
                .ok_or_else(|| format!("route {id} references an unknown credential"))?;
            routes.push(GrantedRoute {
                id: id.clone(),
                policy,
                credential,
            });
        }

        let grant = TrustedGrant { routes };
        grant.validate()?;
        Ok(grant)
    }
}

impl TrustedGrant {
    pub fn validate(&self) -> Result<(), String> {
        if self.routes.is_empty() {
            return Err("a grant must contain at least one route".into());
        }
        if self.routes.len() > MAX_ROUTES_PER_SESSION {
            return Err(format!(
                "a grant may contain at most {MAX_ROUTES_PER_SESSION} routes"
            ));
        }

        let mut ids = BTreeSet::new();
        let mut credentials = BTreeMap::new();
        for route in &self.routes {
            if !ids.insert(&route.id) {
                return Err(format!("grant contains duplicate route {}", route.id));
            }
            if let Some(existing) = credentials.get(&route.policy.credential) {
                if existing != &route.credential {
                    return Err(
                        "grant contains conflicting values for one credential reference".into(),
                    );
                }
            } else {
                credentials.insert(route.policy.credential.clone(), route.credential.clone());
            }
        }
        for route in &self.routes {
            route.policy.validate(&route.id, &credentials)?;
        }
        Ok(())
    }
}

fn apply_limits(policy: &mut RoutePolicy, limits: &SessionLimits) {
    if let Some(value) = limits.max_requests {
        policy.request_count_budget = policy.request_count_budget.min(value);
    }
    if let Some(value) = limits.max_request_bytes {
        policy.max_request_bytes = policy.max_request_bytes.min(value);
    }
    if let Some(value) = limits.max_response_bytes {
        policy.max_response_bytes = policy.max_response_bytes.min(value);
    }
    if let Some(value) = limits.max_concurrent_requests {
        policy.max_concurrent_requests = policy.max_concurrent_requests.min(value);
    }
    if let Some(value) = limits.session_expiry_seconds {
        policy.session_expiry_seconds = policy.session_expiry_seconds.min(value);
    }
}
