//! Client code generation for Quill services

use crate::{method_type, MethodType, QuillConfig};
use heck::ToSnakeCase;
use prost_build::{Method, Service};
use quote::{format_ident, quote};

/// Generate client code for a service
pub fn generate_client(service: &Service, config: &QuillConfig) -> Option<String> {
    let client_name = format_ident!("{}Client", service.name);
    let client_mod_name = format_ident!("{}_client", service.name.to_snake_case());

    let _service_name = &service.name;
    let methods = generate_methods(service, config);

    let code = quote! {
        /// Generated client for #service_name service
        pub mod #client_mod_name {
            use quill_client::QuillClient;
            use quill_core::QuillError;
            use bytes::Bytes;
            use std::pin::Pin;
            use futures::Stream;
            use prost::Message;

            /// Client for the #service_name service
            pub struct #client_name {
                client: QuillClient,
            }

            impl #client_name {
                /// Create a new client with the given QuillClient
                pub fn new(client: QuillClient) -> Self {
                    Self { client }
                }

                /// Create a new client with a base URL
                pub fn connect(url: impl Into<String>) -> Result<Self, QuillError> {
                    let client = QuillClient::builder()
                        .base_url(url)
                        .build()
                        .map_err(|e| QuillError::Transport(e))?;
                    Ok(Self::new(client))
                }

                #methods
            }
        }
    };

    Some(code.to_string())
}

/// Generate methods for all RPCs in the service
fn generate_methods(service: &Service, config: &QuillConfig) -> proc_macro2::TokenStream {
    let mut methods = proc_macro2::TokenStream::new();

    for method in &service.methods {
        let method_code = generate_method(service, method, config);
        methods.extend(method_code);
    }

    methods
}

/// Generate a single method based on its streaming type
fn generate_method(
    service: &Service,
    method: &Method,
    _config: &QuillConfig,
) -> proc_macro2::TokenStream {
    let method_name = format_ident!("{}", method.name.to_snake_case());

    // Use super:: to reference message types from parent module
    let input_type_path = format!("super::{}", method.input_type);
    let output_type_path = format!("super::{}", method.output_type);
    let input_type: proc_macro2::TokenStream = input_type_path.parse().unwrap();
    let output_type: proc_macro2::TokenStream = output_type_path.parse().unwrap();

    let service_name = &service.name;
    let rpc_method = &method.name;

    match method_type(method) {
        MethodType::Unary => {
            quote! {
                /// Unary RPC: #rpc_method
                pub async fn #method_name(
                    &self,
                    request: &#input_type,
                ) -> Result<#output_type, QuillError> {
                    let request_bytes = request.encode_to_vec();
                    let response_bytes = self.client.call(
                        #service_name,
                        #rpc_method,
                        Bytes::from(request_bytes),
                    ).await?;

                    #output_type::decode(&response_bytes[..])
                        .map_err(|e| QuillError::Rpc(format!("Failed to decode response: {}", e)))
                }
            }
        }
        MethodType::ServerStreaming => {
            quote! {
                /// Server streaming RPC: #rpc_method
                pub async fn #method_name(
                    &self,
                    request: &#input_type,
                ) -> Result<Pin<Box<dyn Stream<Item = Result<#output_type, QuillError>> + Send>>, QuillError> {
                    use futures::StreamExt;

                    let request_bytes = request.encode_to_vec();
                    let stream = self.client.call_server_streaming(
                        #service_name,
                        #rpc_method,
                        Bytes::from(request_bytes),
                    ).await?;

                    let mapped_stream = stream.map(|result| {
                        result.and_then(|bytes| {
                            #output_type::decode(&bytes[..])
                                .map_err(|e| QuillError::Rpc(format!("Failed to decode response: {}", e)))
                        })
                    });

                    Ok(Box::pin(mapped_stream))
                }
            }
        }
        MethodType::ClientStreaming => {
            quote! {
                /// Client streaming RPC: #rpc_method
                pub async fn #method_name(
                    &self,
                    request_stream: impl Stream<Item = Result<#input_type, QuillError>> + Send + 'static,
                ) -> Result<#output_type, QuillError> {
                    use futures::StreamExt;

                    let byte_stream = request_stream.map(|result| {
                        result.and_then(|msg| {
                            Ok(Bytes::from(msg.encode_to_vec()))
                        })
                    });

                    let response_bytes = self.client.client_streaming(
                        #service_name,
                        #rpc_method,
                        Box::pin(byte_stream),
                    ).await?;

                    #output_type::decode(&response_bytes[..])
                        .map_err(|e| QuillError::Rpc(format!("Failed to decode response: {}", e)))
                }
            }
        }
        MethodType::BidirectionalStreaming => {
            quote! {
                /// Bidirectional streaming RPC: #rpc_method
                pub async fn #method_name(
                    &self,
                    request_stream: impl Stream<Item = Result<#input_type, QuillError>> + Send + 'static,
                ) -> Result<Pin<Box<dyn Stream<Item = Result<#output_type, QuillError>> + Send>>, QuillError> {
                    use futures::StreamExt;

                    let byte_stream = request_stream.map(|result| {
                        result.and_then(|msg| {
                            Ok(Bytes::from(msg.encode_to_vec()))
                        })
                    });

                    let stream = self.client.bidirectional_streaming(
                        #service_name,
                        #rpc_method,
                        Box::pin(byte_stream),
                    ).await?;

                    let mapped_stream = stream.map(|result| {
                        result.and_then(|bytes| {
                            #output_type::decode(&bytes[..])
                                .map_err(|e| QuillError::Decode(e.to_string()))
                        })
                    });

                    Ok(Box::pin(mapped_stream))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_build::{Method, Service};

    fn make_test_service() -> Service {
        Service {
            name: "TestService".to_string(),
            proto_name: "TestService".to_string(),
            package: "test.v1".to_string(),
            comments: Default::default(),
            options: Default::default(),
            methods: vec![
                Method {
                    name: "UnaryCall".to_string(),
                    proto_name: "UnaryCall".to_string(),
                    comments: Default::default(),
                    input_type: "Request".to_string(),
                    output_type: "Response".to_string(),
                    input_proto_type: "Request".to_string(),
                    output_proto_type: "Response".to_string(),
                    options: Default::default(),
                    client_streaming: false,
                    server_streaming: false,
                },
            ],
        }
    }

    #[test]
    fn test_generate_client() {
        let service = make_test_service();
        let config = QuillConfig::default();
        let code = generate_client(&service, &config);

        assert!(code.is_some());
        let code = code.unwrap();
        assert!(code.contains("TestServiceClient"));
        assert!(code.contains("test_service_client"));
        assert!(code.contains("unary_call"));
    }

    #[test]
    fn test_generate_client_with_prefix() {
        let service = make_test_service();
        let config = QuillConfig::new().with_package_prefix("myapp");
        let code = generate_client(&service, &config);

        assert!(code.is_some());
    }
}
