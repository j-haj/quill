//! REST gateway router

use crate::converter::{merge_path_params, parse_query_params, MessageConverter};
use crate::error::{GatewayError, GatewayResult};
use crate::mapping::{HttpMethod, RouteMapping};
use crate::openapi::{OpenApiSpec, OpenApiSpecBuilder};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, MethodRouter},
    Json, Router,
};
use http_body_util::BodyExt;
use quill_client::QuillClient;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};

/// REST gateway state
#[derive(Clone)]
struct GatewayState {
    client: Arc<QuillClient>,
    routes: Arc<Vec<RouteMapping>>,
    converter: Option<Arc<MessageConverter>>,
}

/// REST gateway for Quill RPC services
pub struct RestGateway {
    router: Router,
    openapi_spec: OpenApiSpec,
}

impl RestGateway {
    /// Get the Axum router
    pub fn router(self) -> Router {
        self.router
    }

    /// Get the OpenAPI specification
    pub fn openapi_spec(&self) -> &OpenApiSpec {
        &self.openapi_spec
    }

    /// Get OpenAPI spec as JSON
    pub fn openapi_json(&self) -> Result<String, serde_json::Error> {
        self.openapi_spec.to_json()
    }
}

/// REST gateway builder
pub struct RestGatewayBuilder {
    client: Arc<QuillClient>,
    routes: Vec<RouteMapping>,
    title: String,
    version: String,
    description: Option<String>,
    base_path: String,
    converter: Option<MessageConverter>,
}

impl RestGatewayBuilder {
    /// Create a new REST gateway builder
    pub fn new(client: QuillClient) -> Self {
        Self {
            client: Arc::new(client),
            routes: Vec::new(),
            title: "Quill REST API".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            base_path: "/api".to_string(),
            converter: None,
        }
    }

    /// Set message converter from descriptor bytes
    ///
    /// This enables JSON ↔ Protobuf conversion for RPC calls.
    /// Without a converter, the gateway can only forward raw bytes.
    pub fn with_descriptor_bytes(mut self, descriptor_bytes: &[u8]) -> GatewayResult<Self> {
        self.converter = Some(MessageConverter::from_bytes(descriptor_bytes)?);
        Ok(self)
    }

    /// Set message converter directly
    pub fn with_converter(mut self, converter: MessageConverter) -> Self {
        self.converter = Some(converter);
        self
    }

    /// Set API title
    pub fn title(mut self, title: &str) -> Self {
        self.title = title.to_string();
        self
    }

    /// Set API version
    pub fn version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    /// Set API description
    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set base path for all routes
    pub fn base_path(mut self, base_path: &str) -> Self {
        self.base_path = base_path.to_string();
        self
    }

    /// Add a route mapping
    pub fn route(mut self, route: RouteMapping) -> Self {
        self.routes.push(route);
        self
    }

    /// Add multiple routes
    pub fn routes(mut self, routes: Vec<RouteMapping>) -> Self {
        self.routes.extend(routes);
        self
    }

    /// Build the REST gateway
    pub fn build(self) -> RestGateway {
        let state = GatewayState {
            client: self.client.clone(),
            routes: Arc::new(self.routes.clone()),
            converter: self.converter.clone().map(Arc::new),
        };

        // Build router with all routes
        let mut router = Router::new();

        // Add OpenAPI spec endpoint
        let openapi_spec = self.build_openapi_spec();
        let openapi_json = openapi_spec.to_json().unwrap_or_else(|_| "{}".to_string());
        let openapi_router = Router::new().route(
            "/openapi.json",
            get(move || async move { Json(openapi_json) }),
        );

        router = router.merge(openapi_router);

        // Add routes
        for route in &self.routes {
            for http_mapping in &route.http_mappings {
                let path_template = format!("{}{}", self.base_path, http_mapping.url_template.template());
                let method_router = create_method_router(http_mapping.http_method, state.clone());

                router = router.route(&path_template, method_router);
            }
        }

        RestGateway {
            router,
            openapi_spec,
        }
    }

    fn build_openapi_spec(&self) -> OpenApiSpec {
        let mut builder = OpenApiSpecBuilder::new(&self.title, &self.version);

        if let Some(desc) = &self.description {
            builder = builder.description(desc);
        }

        builder.routes(self.routes.clone()).build()
    }
}

/// Create method router for specific HTTP method
fn create_method_router(http_method: HttpMethod, state: GatewayState) -> MethodRouter {
    match http_method {
        HttpMethod::Get => get(handle_get).with_state(state),
        HttpMethod::Post => axum::routing::post(handle_post).with_state(state),
        HttpMethod::Put => axum::routing::put(handle_put).with_state(state),
        HttpMethod::Patch => axum::routing::patch(handle_patch).with_state(state),
        HttpMethod::Delete => axum::routing::delete(handle_delete).with_state(state),
    }
}

/// Handle GET requests
async fn handle_get(
    State(state): State<GatewayState>,
    Path(params): Path<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response, GatewayResponse> {
    handle_request(state, HttpMethod::Get, params, req).await
}

/// Handle POST requests
async fn handle_post(
    State(state): State<GatewayState>,
    Path(params): Path<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response, GatewayResponse> {
    handle_request(state, HttpMethod::Post, params, req).await
}

/// Handle PUT requests
async fn handle_put(
    State(state): State<GatewayState>,
    Path(params): Path<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response, GatewayResponse> {
    handle_request(state, HttpMethod::Put, params, req).await
}

/// Handle PATCH requests
async fn handle_patch(
    State(state): State<GatewayState>,
    Path(params): Path<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response, GatewayResponse> {
    handle_request(state, HttpMethod::Patch, params, req).await
}

/// Handle DELETE requests
async fn handle_delete(
    State(state): State<GatewayState>,
    Path(params): Path<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response, GatewayResponse> {
    handle_request(state, HttpMethod::Delete, params, req).await
}

/// Handle request and route to RPC
async fn handle_request(
    state: GatewayState,
    http_method: HttpMethod,
    params: HashMap<String, String>,
    req: Request<Body>,
) -> Result<Response, GatewayResponse> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|s| s.to_string());

    debug!(
        "Handling {} request to {} with params: {:?}",
        http_method.as_str(),
        path,
        params
    );

    // Find matching route
    let route = find_matching_route(&state.routes, &path, http_method)?;
    let service = &route.service;
    let method = &route.method;

    info!("Routing to {}/{}", service, method);

    // Get the converter (required for JSON ↔ Protobuf conversion)
    let converter = state
        .converter
        .as_ref()
        .ok_or(GatewayError::NoConverter)?;

    // Parse request body as JSON
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| GatewayError::InvalidRequestBody(format!("Failed to read body: {}", e)))?
        .to_bytes();

    let mut json_body: Value = if body_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body_bytes).map_err(|e| {
            GatewayError::InvalidRequestBody(format!("Invalid JSON body: {}", e))
        })?
    };

    // Merge path parameters into JSON body
    merge_path_params(&mut json_body, &params)?;

    // Merge query parameters for GET requests
    if http_method == HttpMethod::Get {
        let query_params = parse_query_params(query.as_deref());
        merge_path_params(&mut json_body, &query_params)?;
    }

    debug!("Request JSON: {:?}", json_body);

    // Convert JSON to Protobuf
    let request_bytes = converter.json_to_proto(service, method, &json_body)?;

    // Make RPC call
    let response_bytes = state
        .client
        .call(service, method, request_bytes)
        .await
        .map_err(|e| GatewayError::RpcCall(e.to_string()))?;

    // Convert Protobuf response to JSON
    let response_json = converter.proto_to_json(service, method, &response_bytes)?;

    debug!("Response JSON: {:?}", response_json);

    // Return JSON response
    Ok(Json(response_json).into_response())
}

/// Find matching route for the given path and HTTP method
fn find_matching_route<'a>(
    routes: &'a [RouteMapping],
    path: &str,
    http_method: HttpMethod,
) -> GatewayResult<&'a RouteMapping> {
    for route in routes {
        for mapping in &route.http_mappings {
            if mapping.http_method == http_method && mapping.url_template.matches(path) {
                return Ok(route);
            }
        }
    }

    Err(GatewayError::RouteNotFound(format!(
        "{} {}",
        http_method.as_str(),
        path
    )))
}

/// Gateway response wrapper for error handling
struct GatewayResponse(GatewayError);

impl IntoResponse for GatewayResponse {
    fn into_response(self) -> Response {
        let problem = self.0.to_problem_details();
        let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        (status, Json(problem)).into_response()
    }
}

impl From<GatewayError> for GatewayResponse {
    fn from(err: GatewayError) -> Self {
        error!("Gateway error: {}", err);
        GatewayResponse(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quill_client::client::ClientBuilder;

    #[test]
    fn test_gateway_builder() {
        let client = ClientBuilder::new()
            .base_url("http://localhost:8080")
            .build()
            .unwrap();

        let route = RouteMapping::new("users.v1.UserService", "GetUser")
            .add_mapping(HttpMethod::Get, "/v1/users/{id}")
            .unwrap();

        let gateway = RestGatewayBuilder::new(client)
            .title("Test API")
            .version("1.0.0")
            .description("Test REST API")
            .route(route)
            .build();

        assert_eq!(gateway.openapi_spec().info.title, "Test API");
        assert_eq!(gateway.openapi_spec().info.version, "1.0.0");
    }

    #[test]
    fn test_openapi_json_generation() {
        let client = ClientBuilder::new()
            .base_url("http://localhost:8080")
            .build()
            .unwrap();

        let route = RouteMapping::new("users.v1.UserService", "GetUser")
            .add_mapping(HttpMethod::Get, "/v1/users/{id}")
            .unwrap();

        let gateway = RestGatewayBuilder::new(client)
            .route(route)
            .build();

        let json = gateway.openapi_json();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("openapi"));
    }

    #[test]
    fn test_find_matching_route() {
        let routes = vec![
            RouteMapping::new("users.v1.UserService", "GetUser")
                .add_mapping(HttpMethod::Get, "/v1/users/{id}")
                .unwrap(),
            RouteMapping::new("users.v1.UserService", "CreateUser")
                .add_mapping(HttpMethod::Post, "/v1/users")
                .unwrap(),
            RouteMapping::new("posts.v1.PostService", "GetPost")
                .add_mapping(HttpMethod::Get, "/v1/posts/{id}")
                .unwrap(),
        ];

        // Test matching GET /v1/users/123
        let result = find_matching_route(&routes, "/v1/users/123", HttpMethod::Get);
        assert!(result.is_ok());
        let route = result.unwrap();
        assert_eq!(route.service, "users.v1.UserService");
        assert_eq!(route.method, "GetUser");

        // Test matching POST /v1/users
        let result = find_matching_route(&routes, "/v1/users", HttpMethod::Post);
        assert!(result.is_ok());
        let route = result.unwrap();
        assert_eq!(route.method, "CreateUser");

        // Test matching GET /v1/posts/456
        let result = find_matching_route(&routes, "/v1/posts/456", HttpMethod::Get);
        assert!(result.is_ok());
        let route = result.unwrap();
        assert_eq!(route.service, "posts.v1.PostService");
    }

    #[test]
    fn test_find_matching_route_not_found() {
        let routes = vec![
            RouteMapping::new("users.v1.UserService", "GetUser")
                .add_mapping(HttpMethod::Get, "/v1/users/{id}")
                .unwrap(),
        ];

        // Test non-existent path
        let result = find_matching_route(&routes, "/v1/unknown/123", HttpMethod::Get);
        assert!(result.is_err());
        match result {
            Err(GatewayError::RouteNotFound(_)) => {}
            _ => panic!("Expected RouteNotFound error"),
        }

        // Test wrong HTTP method
        let result = find_matching_route(&routes, "/v1/users/123", HttpMethod::Delete);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_matching_route_multiple_methods() {
        let routes = vec![
            RouteMapping::new("users.v1.UserService", "GetUser")
                .add_mapping(HttpMethod::Get, "/v1/users/{id}")
                .unwrap()
                .add_mapping(HttpMethod::Delete, "/v1/users/{id}")
                .unwrap(),
        ];

        // Test GET matches
        let result = find_matching_route(&routes, "/v1/users/123", HttpMethod::Get);
        assert!(result.is_ok());

        // Test DELETE matches same route
        let result = find_matching_route(&routes, "/v1/users/456", HttpMethod::Delete);
        assert!(result.is_ok());
    }

    #[test]
    fn test_gateway_with_base_path() {
        let client = ClientBuilder::new()
            .base_url("http://localhost:8080")
            .build()
            .unwrap();

        let route = RouteMapping::new("users.v1.UserService", "GetUser")
            .add_mapping(HttpMethod::Get, "/users/{id}")
            .unwrap();

        let _gateway = RestGatewayBuilder::new(client)
            .base_path("/api/v2")
            .route(route)
            .build();

        // The gateway should prefix routes with /api/v2
    }

    #[test]
    fn test_gateway_error_to_problem_details() {
        let err = GatewayError::RouteNotFound("/api/v1/unknown".to_string());
        let problem = err.to_problem_details();
        assert_eq!(problem.status, 404);
        assert_eq!(problem.title, "Route Not Found");

        let err = GatewayError::RpcNotFound("Service.Method".to_string());
        let problem = err.to_problem_details();
        assert_eq!(problem.status, 404);
        assert_eq!(problem.title, "RPC Not Found");

        let err = GatewayError::RpcCall("Connection refused".to_string());
        let problem = err.to_problem_details();
        assert_eq!(problem.status, 500);

        let err = GatewayError::NoConverter;
        let problem = err.to_problem_details();
        assert_eq!(problem.status, 500);
    }
}
