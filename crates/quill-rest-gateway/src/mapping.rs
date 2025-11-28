//! URL and HTTP method mapping for REST gateway

use crate::error::{GatewayError, GatewayResult};
use std::collections::HashMap;

/// HTTP methods supported by the gateway
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    /// Parse HTTP method from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(HttpMethod::Get),
            "POST" => Some(HttpMethod::Post),
            "PUT" => Some(HttpMethod::Put),
            "PATCH" => Some(HttpMethod::Patch),
            "DELETE" => Some(HttpMethod::Delete),
            _ => None,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// URL template with path parameters
/// Example: "/api/v1/users/{id}" or "/api/v1/posts/{post_id}/comments/{comment_id}"
#[derive(Debug, Clone)]
pub struct UrlTemplate {
    /// Raw template string
    template: String,
    /// Path segments (static or parameter)
    segments: Vec<UrlSegment>,
}

#[derive(Debug, Clone)]
enum UrlSegment {
    Static(String),
    Parameter(String), // Parameter name without braces
}

impl UrlTemplate {
    /// Create a new URL template
    pub fn new(template: &str) -> GatewayResult<Self> {
        let segments = Self::parse_template(template)?;
        Ok(Self {
            template: template.to_string(),
            segments,
        })
    }

    /// Parse template into segments
    fn parse_template(template: &str) -> GatewayResult<Vec<UrlSegment>> {
        let mut segments = Vec::new();

        for part in template.split('/') {
            if part.is_empty() {
                continue;
            }

            if part.starts_with('{') && part.ends_with('}') {
                // Path parameter
                let param_name = &part[1..part.len() - 1];
                if param_name.is_empty() {
                    return Err(GatewayError::InvalidRequestBody(
                        "Empty parameter name in URL template".to_string(),
                    ));
                }
                segments.push(UrlSegment::Parameter(param_name.to_string()));
            } else if part.contains('{') || part.contains('}') {
                return Err(GatewayError::InvalidRequestBody(
                    format!("Invalid parameter syntax in URL template: {}", part),
                ));
            } else {
                // Static segment
                segments.push(UrlSegment::Static(part.to_string()));
            }
        }

        Ok(segments)
    }

    /// Match a request path against this template and extract parameters
    pub fn match_path(&self, path: &str) -> Option<HashMap<String, String>> {
        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if path_parts.len() != self.segments.len() {
            return None;
        }

        let mut params = HashMap::new();

        for (segment, part) in self.segments.iter().zip(path_parts.iter()) {
            match segment {
                UrlSegment::Static(expected) => {
                    if expected != part {
                        return None;
                    }
                }
                UrlSegment::Parameter(name) => {
                    params.insert(name.clone(), part.to_string());
                }
            }
        }

        Some(params)
    }

    /// Get the template string
    pub fn template(&self) -> &str {
        &self.template
    }

    /// Get parameter names from the template
    pub fn parameter_names(&self) -> Vec<String> {
        self.segments
            .iter()
            .filter_map(|seg| match seg {
                UrlSegment::Parameter(name) => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    /// Check if a path matches this template (without extracting parameters)
    pub fn matches(&self, path: &str) -> bool {
        self.match_path(path).is_some()
    }
}

/// HTTP method mapping for a specific RPC method
#[derive(Debug, Clone)]
pub struct HttpMethodMapping {
    /// HTTP method (GET, POST, etc.)
    pub http_method: HttpMethod,
    /// URL template with path parameters
    pub url_template: UrlTemplate,
}

impl HttpMethodMapping {
    /// Create a new HTTP method mapping
    pub fn new(http_method: HttpMethod, url_template: &str) -> GatewayResult<Self> {
        Ok(Self {
            http_method,
            url_template: UrlTemplate::new(url_template)?,
        })
    }
}

/// Route mapping from REST to RPC
#[derive(Debug, Clone)]
pub struct RouteMapping {
    /// RPC service name (e.g., "media.v1.ImageService")
    pub service: String,
    /// RPC method name (e.g., "GetMetadata")
    pub method: String,
    /// HTTP method mappings
    pub http_mappings: Vec<HttpMethodMapping>,
}

impl RouteMapping {
    /// Create a new route mapping
    pub fn new(service: &str, method: &str) -> Self {
        Self {
            service: service.to_string(),
            method: method.to_string(),
            http_mappings: Vec::new(),
        }
    }

    /// Add an HTTP method mapping
    pub fn add_mapping(mut self, http_method: HttpMethod, url_template: &str) -> GatewayResult<Self> {
        self.http_mappings.push(HttpMethodMapping::new(http_method, url_template)?);
        Ok(self)
    }

    /// Find matching HTTP mapping for a request
    pub fn find_mapping(&self, http_method: HttpMethod, path: &str) -> Option<(HttpMethodMapping, HashMap<String, String>)> {
        for mapping in &self.http_mappings {
            if mapping.http_method == http_method {
                if let Some(params) = mapping.url_template.match_path(path) {
                    return Some((mapping.clone(), params));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_from_str() {
        assert_eq!(HttpMethod::from_str("GET"), Some(HttpMethod::Get));
        assert_eq!(HttpMethod::from_str("post"), Some(HttpMethod::Post));
        assert_eq!(HttpMethod::from_str("PUT"), Some(HttpMethod::Put));
        assert_eq!(HttpMethod::from_str("INVALID"), None);
    }

    #[test]
    fn test_url_template_static() {
        let template = UrlTemplate::new("/api/v1/users").unwrap();

        // Should match exact path
        let params = template.match_path("/api/v1/users");
        assert!(params.is_some());
        assert_eq!(params.unwrap().len(), 0);

        // Should not match different path
        assert!(template.match_path("/api/v1/posts").is_none());
    }

    #[test]
    fn test_url_template_with_parameter() {
        let template = UrlTemplate::new("/api/v1/users/{id}").unwrap();

        let params = template.match_path("/api/v1/users/123").unwrap();
        assert_eq!(params.get("id"), Some(&"123".to_string()));

        // Wrong path should not match
        assert!(template.match_path("/api/v1/posts/123").is_none());

        // Wrong number of segments
        assert!(template.match_path("/api/v1/users").is_none());
    }

    #[test]
    fn test_url_template_multiple_parameters() {
        let template = UrlTemplate::new("/api/v1/posts/{post_id}/comments/{comment_id}").unwrap();

        let params = template.match_path("/api/v1/posts/456/comments/789").unwrap();
        assert_eq!(params.get("post_id"), Some(&"456".to_string()));
        assert_eq!(params.get("comment_id"), Some(&"789".to_string()));
    }

    #[test]
    fn test_url_template_parameter_names() {
        let template = UrlTemplate::new("/api/v1/users/{user_id}/posts/{post_id}").unwrap();
        let names = template.parameter_names();
        assert_eq!(names, vec!["user_id", "post_id"]);
    }

    #[test]
    fn test_route_mapping() {
        let mapping = RouteMapping::new("users.v1.UserService", "GetUser")
            .add_mapping(HttpMethod::Get, "/api/v1/users/{id}")
            .unwrap();

        let result = mapping.find_mapping(HttpMethod::Get, "/api/v1/users/123");
        assert!(result.is_some());

        let (_, params) = result.unwrap();
        assert_eq!(params.get("id"), Some(&"123".to_string()));

        // POST should not match
        assert!(mapping.find_mapping(HttpMethod::Post, "/api/v1/users/123").is_none());
    }
}
