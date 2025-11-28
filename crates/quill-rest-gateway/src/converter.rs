//! JSON to Protobuf conversion utilities
//!
//! Provides bidirectional conversion between JSON and Protobuf messages
//! using dynamic message reflection via prost-reflect.

use crate::error::{GatewayError, GatewayResult};
use bytes::Bytes;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, DeserializeOptions};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Message converter for JSON ↔ Protobuf conversion
#[derive(Clone)]
pub struct MessageConverter {
    pool: Arc<DescriptorPool>,
}

impl MessageConverter {
    /// Create a new message converter from a descriptor pool
    pub fn new(pool: DescriptorPool) -> Self {
        Self {
            pool: Arc::new(pool),
        }
    }

    /// Create a message converter from descriptor bytes
    pub fn from_bytes(descriptor_bytes: &[u8]) -> GatewayResult<Self> {
        let pool = DescriptorPool::decode(descriptor_bytes).map_err(|e| {
            GatewayError::InternalError(format!("Failed to decode descriptor set: {}", e))
        })?;
        Ok(Self::new(pool))
    }

    /// Get message descriptor for a service method's input type
    pub fn get_input_descriptor(
        &self,
        service: &str,
        method: &str,
    ) -> GatewayResult<MessageDescriptor> {
        // Find the service
        let service_desc = self
            .pool
            .services()
            .find(|s| s.full_name() == service || s.name() == service)
            .ok_or_else(|| {
                GatewayError::RpcNotFound(format!("Service '{}' not found", service))
            })?;

        // Find the method
        let method_desc = service_desc
            .methods()
            .find(|m| m.name() == method)
            .ok_or_else(|| {
                GatewayError::RpcNotFound(format!(
                    "Method '{}' not found in service '{}'",
                    method, service
                ))
            })?;

        Ok(method_desc.input())
    }

    /// Get message descriptor for a service method's output type
    pub fn get_output_descriptor(
        &self,
        service: &str,
        method: &str,
    ) -> GatewayResult<MessageDescriptor> {
        let service_desc = self
            .pool
            .services()
            .find(|s| s.full_name() == service || s.name() == service)
            .ok_or_else(|| {
                GatewayError::RpcNotFound(format!("Service '{}' not found", service))
            })?;

        let method_desc = service_desc
            .methods()
            .find(|m| m.name() == method)
            .ok_or_else(|| {
                GatewayError::RpcNotFound(format!(
                    "Method '{}' not found in service '{}'",
                    method, service
                ))
            })?;

        Ok(method_desc.output())
    }

    /// Convert JSON to Protobuf bytes
    pub fn json_to_proto(
        &self,
        service: &str,
        method: &str,
        json: &Value,
    ) -> GatewayResult<Bytes> {
        let descriptor = self.get_input_descriptor(service, method)?;
        self.json_to_proto_with_descriptor(&descriptor, json)
    }

    /// Convert JSON to Protobuf bytes using a specific descriptor
    pub fn json_to_proto_with_descriptor(
        &self,
        descriptor: &MessageDescriptor,
        json: &Value,
    ) -> GatewayResult<Bytes> {
        // Use prost-reflect's deserialize support to convert JSON to DynamicMessage
        let json_string = json.to_string();
        let mut deserializer = serde_json::Deserializer::from_str(&json_string);
        let options = DeserializeOptions::default();
        let message = DynamicMessage::deserialize_with_options(
            descriptor.clone(),
            &mut deserializer,
            &options,
        )
        .map_err(|e| {
            GatewayError::InvalidRequestBody(format!(
                "Failed to convert JSON to message '{}': {}",
                descriptor.full_name(),
                e
            ))
        })?;

        // Encode to protobuf bytes
        let buf = message.encode_to_vec();
        Ok(Bytes::from(buf))
    }

    /// Convert Protobuf bytes to JSON
    pub fn proto_to_json(
        &self,
        service: &str,
        method: &str,
        proto_bytes: &[u8],
    ) -> GatewayResult<Value> {
        let descriptor = self.get_output_descriptor(service, method)?;
        self.proto_to_json_with_descriptor(&descriptor, proto_bytes)
    }

    /// Convert Protobuf bytes to JSON using a specific descriptor
    pub fn proto_to_json_with_descriptor(
        &self,
        descriptor: &MessageDescriptor,
        proto_bytes: &[u8],
    ) -> GatewayResult<Value> {
        // Decode protobuf bytes into dynamic message
        let message = DynamicMessage::decode(descriptor.clone(), proto_bytes).map_err(|e| {
            GatewayError::InternalError(format!("Failed to decode protobuf response: {}", e))
        })?;

        // Serialize to JSON
        let json = serde_json::to_value(&message).map_err(|e| {
            GatewayError::InternalError(format!("Failed to convert response to JSON: {}", e))
        })?;

        Ok(json)
    }
}

/// Merge path parameters into a JSON object
pub fn merge_path_params(
    json: &mut Value,
    params: &HashMap<String, String>,
) -> GatewayResult<()> {
    match json {
        Value::Object(map) => {
            for (key, value) in params {
                map.insert(key.clone(), Value::String(value.clone()));
            }
            Ok(())
        }
        Value::Null => {
            // If body is null/empty, create object from params
            let mut map = serde_json::Map::new();
            for (key, value) in params {
                map.insert(key.clone(), Value::String(value.clone()));
            }
            *json = Value::Object(map);
            Ok(())
        }
        _ => Err(GatewayError::InvalidRequestBody(
            "Request body must be a JSON object to merge path parameters".to_string(),
        )),
    }
}

/// Parse query parameters from request URI
pub fn parse_query_params(query: Option<&str>) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(query_str) = query {
        for pair in query_str.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                // URL decode
                let decoded_key = urlencoding_decode(key);
                let decoded_value = urlencoding_decode(value);
                params.insert(decoded_key, decoded_value);
            }
        }
    }
    params
}

/// Simple URL decoding (handles common cases)
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_path_params_into_object() {
        let mut json = serde_json::json!({
            "name": "test"
        });
        let mut params = HashMap::new();
        params.insert("id".to_string(), "123".to_string());

        merge_path_params(&mut json, &params).unwrap();

        assert_eq!(json["id"], "123");
        assert_eq!(json["name"], "test");
    }

    #[test]
    fn test_merge_path_params_into_null() {
        let mut json = Value::Null;
        let mut params = HashMap::new();
        params.insert("id".to_string(), "456".to_string());

        merge_path_params(&mut json, &params).unwrap();

        assert_eq!(json["id"], "456");
    }

    #[test]
    fn test_merge_path_params_into_array_fails() {
        let mut json = serde_json::json!([1, 2, 3]);
        let params = HashMap::new();

        let result = merge_path_params(&mut json, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_query_params() {
        let params = parse_query_params(Some("foo=bar&baz=qux"));
        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_parse_query_params_with_encoding() {
        let params = parse_query_params(Some("name=hello%20world&value=foo+bar"));
        assert_eq!(params.get("name"), Some(&"hello world".to_string()));
        assert_eq!(params.get("value"), Some(&"foo bar".to_string()));
    }

    #[test]
    fn test_urlencoding_decode() {
        assert_eq!(urlencoding_decode("hello%20world"), "hello world");
        assert_eq!(urlencoding_decode("foo+bar"), "foo bar");
        assert_eq!(urlencoding_decode("test%3D123"), "test=123");
    }
}
