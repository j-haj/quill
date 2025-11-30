//! Server code generation for Quill services

use crate::{method_type, MethodType, QuillConfig};
use heck::ToSnakeCase;
use prost_build::{Method, Service};
use quote::{format_ident, quote};

/// Generate server code for a service
pub fn generate_server(service: &Service, _config: &QuillConfig) -> Option<String> {
    let trait_name = format_ident!("{}", service.name);
    let server_mod_name = format_ident!("{}_server", service.name.to_snake_case());

    let _service_name = &service.name;
    let trait_methods = generate_trait_methods(service);
    let route_handlers = generate_route_handlers(service);

    let code = quote! {
        /// Generated server for #service_name service
        pub mod #server_mod_name {
            use quill_server::{ServerBuilder, streaming::RpcResponse};
            use quill_core::QuillError;
            use bytes::Bytes;
            use std::pin::Pin;
            use std::sync::Arc;
            use futures::Stream;
            use prost::Message;

            /// Service trait for #service_name
            #[async_trait::async_trait]
            pub trait #trait_name: Send + Sync + 'static {
                #trait_methods
            }

            /// Register the service implementation with a ServerBuilder
            pub fn add_service<S: #trait_name>(
                builder: ServerBuilder,
                service: S,
            ) -> ServerBuilder {
                let service = Arc::new(service);
                let mut builder = builder;

                #route_handlers

                builder
            }
        }
    };

    Some(code.to_string())
}

/// Generate trait methods for all RPCs in the service
fn generate_trait_methods(service: &Service) -> proc_macro2::TokenStream {
    let mut methods = proc_macro2::TokenStream::new();

    for method in &service.methods {
        let method_code = generate_trait_method(method);
        methods.extend(method_code);
    }

    methods
}

/// Generate a single trait method based on its streaming type
fn generate_trait_method(method: &Method) -> proc_macro2::TokenStream {
    let method_name = format_ident!("{}", method.name.to_snake_case());

    // Use super:: to reference message types from parent module
    let input_type_path = format!("super::{}", method.input_type);
    let output_type_path = format!("super::{}", method.output_type);
    let input_type: proc_macro2::TokenStream = input_type_path.parse().unwrap();
    let output_type: proc_macro2::TokenStream = output_type_path.parse().unwrap();

    let method_doc = format!("Handle {} RPC", method.name);

    match method_type(method) {
        MethodType::Unary => {
            quote! {
                #[doc = #method_doc]
                async fn #method_name(
                    &self,
                    request: #input_type,
                ) -> Result<#output_type, QuillError>;
            }
        }
        MethodType::ServerStreaming => {
            quote! {
                #[doc = #method_doc]
                async fn #method_name(
                    &self,
                    request: #input_type,
                ) -> Result<Pin<Box<dyn Stream<Item = Result<#output_type, QuillError>> + Send>>, QuillError>;
            }
        }
        MethodType::ClientStreaming => {
            quote! {
                #[doc = #method_doc]
                async fn #method_name(
                    &self,
                    request_stream: Pin<Box<dyn Stream<Item = Result<#input_type, QuillError>> + Send>>,
                ) -> Result<#output_type, QuillError>;
            }
        }
        MethodType::BidirectionalStreaming => {
            quote! {
                #[doc = #method_doc]
                async fn #method_name(
                    &self,
                    request_stream: Pin<Box<dyn Stream<Item = Result<#input_type, QuillError>> + Send>>,
                ) -> Result<Pin<Box<dyn Stream<Item = Result<#output_type, QuillError>> + Send>>, QuillError>;
            }
        }
    }
}

/// Generate route handlers for all RPCs
fn generate_route_handlers(service: &Service) -> proc_macro2::TokenStream {
    let mut handlers = proc_macro2::TokenStream::new();

    let service_name = &service.name;

    for method in &service.methods {
        let handler_code = generate_route_handler(service_name, method);
        handlers.extend(handler_code);
    }

    handlers
}

/// Generate a single route handler based on streaming type
fn generate_route_handler(service_name: &str, method: &Method) -> proc_macro2::TokenStream {
    let method_name = format_ident!("{}", method.name.to_snake_case());

    // Use super:: to reference message types from parent module
    let input_type_path = format!("super::{}", method.input_type);
    let output_type_path = format!("super::{}", method.output_type);
    let input_type: proc_macro2::TokenStream = input_type_path.parse().unwrap();
    let _output_type: proc_macro2::TokenStream = output_type_path.parse().unwrap();

    let rpc_method = &method.name;

    let path = format!("{}/{}", service_name, rpc_method);

    match method_type(method) {
        MethodType::Unary => {
            quote! {
                {
                    let service = service.clone();
                    builder = builder.register(#path, move |request_bytes: Bytes| {
                        let service = service.clone();
                        async move {
                            let request = #input_type::decode(&request_bytes[..])
                                .map_err(|e| QuillError::Rpc(format!("Failed to decode: {}", e)))?;

                            let response = service.#method_name(request).await?;
                            Ok(Bytes::from(response.encode_to_vec()))
                        }
                    });
                }
            }
        }
        MethodType::ServerStreaming => {
            quote! {
                {
                    let service = service.clone();
                    builder = builder.register_streaming(
                        #path,
                        move |request_bytes: Bytes| {
                            let service = service.clone();
                            async move {
                                let request = #input_type::decode(&request_bytes[..])
                                    .map_err(|e| QuillError::Rpc(format!("Failed to decode: {}", e)))?;

                                let response_stream = service.#method_name(request).await?;

                                use futures::StreamExt;
                                let byte_stream = response_stream.map(|result| {
                                    result.and_then(|msg| {
                                        Ok(Bytes::from(msg.encode_to_vec()))
                                    })
                                });

                                Ok(RpcResponse::Streaming(Box::pin(byte_stream)))
                            }
                        },
                    );
                }
            }
        }
        MethodType::ClientStreaming => {
            quote! {
                {
                    let service = service.clone();
                    builder = builder.register_client_streaming(
                        #path,
                        move |request_stream: quill_server::router::RequestStream| {
                            let service = service.clone();
                            async move {
                                use futures::StreamExt;
                                use prost::Message;

                                // Map the byte stream to typed messages
                                let typed_stream = request_stream.map(|result| {
                                    result.and_then(|bytes| {
                                        #input_type::decode(&bytes[..])
                                            .map_err(|e| QuillError::Rpc(format!("Failed to decode: {}", e)))
                                    })
                                });

                                let response = service.#method_name(Box::pin(typed_stream)).await?;
                                Ok(RpcResponse::Unary(Bytes::from(response.encode_to_vec())))
                            }
                        },
                    );
                }
            }
        }
        MethodType::BidirectionalStreaming => {
            quote! {
                {
                    let service = service.clone();
                    builder = builder.register_bidi_streaming(
                        #path,
                        move |request_stream: quill_server::router::RequestStream| {
                            let service = service.clone();
                            async move {
                                use futures::StreamExt;
                                use prost::Message;

                                // Map the byte stream to typed messages
                                let typed_stream = request_stream.map(|result| {
                                    result.and_then(|bytes| {
                                        #input_type::decode(&bytes[..])
                                            .map_err(|e| QuillError::Rpc(format!("Failed to decode: {}", e)))
                                    })
                                });

                                let response_stream = service.#method_name(Box::pin(typed_stream)).await?;

                                // Map typed responses back to bytes
                                let byte_stream = response_stream.map(|result| {
                                    result.and_then(|msg| {
                                        Ok(Bytes::from(msg.encode_to_vec()))
                                    })
                                });

                                Ok(RpcResponse::Streaming(Box::pin(byte_stream)))
                            }
                        },
                    );
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
    fn test_generate_server() {
        let service = make_test_service();
        let config = QuillConfig::default();
        let code = generate_server(&service, &config);

        assert!(code.is_some());
        let code = code.unwrap();
        assert!(code.contains("TestService"));
        assert!(code.contains("test_service_server"));
        assert!(code.contains("unary_call"));
        assert!(code.contains("add_service"));
    }

    #[test]
    fn test_generate_server_with_streaming() {
        let mut service = make_test_service();
        service.methods.push(Method {
            name: "ServerStream".to_string(),
            proto_name: "ServerStream".to_string(),
            comments: Default::default(),
            input_type: "Request".to_string(),
            output_type: "Response".to_string(),
            input_proto_type: "Request".to_string(),
            output_proto_type: "Response".to_string(),
            options: Default::default(),
            client_streaming: false,
            server_streaming: true,
        });

        let config = QuillConfig::default();
        let code = generate_server(&service, &config);

        assert!(code.is_some());
        let code = code.unwrap();
        assert!(code.contains("server_stream"));
    }

    #[test]
    fn test_generate_server_with_client_streaming() {
        let mut service = make_test_service();
        service.methods.push(Method {
            name: "ClientStream".to_string(),
            proto_name: "ClientStream".to_string(),
            comments: Default::default(),
            input_type: "Request".to_string(),
            output_type: "Response".to_string(),
            input_proto_type: "Request".to_string(),
            output_proto_type: "Response".to_string(),
            options: Default::default(),
            client_streaming: true,
            server_streaming: false,
        });

        let config = QuillConfig::default();
        let code = generate_server(&service, &config);

        assert!(code.is_some());
        let code = code.unwrap();
        // Verify client streaming method is generated
        assert!(code.contains("client_stream"));
        // Verify register_client_streaming is used
        assert!(code.contains("register_client_streaming"));
        // Verify request_stream parameter
        assert!(code.contains("request_stream"));
    }

    #[test]
    fn test_generate_server_with_bidi_streaming() {
        let mut service = make_test_service();
        service.methods.push(Method {
            name: "BidiStream".to_string(),
            proto_name: "BidiStream".to_string(),
            comments: Default::default(),
            input_type: "Request".to_string(),
            output_type: "Response".to_string(),
            input_proto_type: "Request".to_string(),
            output_proto_type: "Response".to_string(),
            options: Default::default(),
            client_streaming: true,
            server_streaming: true,
        });

        let config = QuillConfig::default();
        let code = generate_server(&service, &config);

        assert!(code.is_some());
        let code = code.unwrap();
        // Verify bidi streaming method is generated
        assert!(code.contains("bidi_stream"));
        // Verify register_bidi_streaming is used
        assert!(code.contains("register_bidi_streaming"));
        // Verify request_stream parameter
        assert!(code.contains("request_stream"));
        // Verify response_stream is returned
        assert!(code.contains("response_stream"));
    }

    #[test]
    fn test_generate_server_all_streaming_types() {
        let mut service = make_test_service();
        // Server streaming
        service.methods.push(Method {
            name: "ServerStream".to_string(),
            proto_name: "ServerStream".to_string(),
            comments: Default::default(),
            input_type: "Request".to_string(),
            output_type: "Response".to_string(),
            input_proto_type: "Request".to_string(),
            output_proto_type: "Response".to_string(),
            options: Default::default(),
            client_streaming: false,
            server_streaming: true,
        });
        // Client streaming
        service.methods.push(Method {
            name: "ClientStream".to_string(),
            proto_name: "ClientStream".to_string(),
            comments: Default::default(),
            input_type: "Request".to_string(),
            output_type: "Response".to_string(),
            input_proto_type: "Request".to_string(),
            output_proto_type: "Response".to_string(),
            options: Default::default(),
            client_streaming: true,
            server_streaming: false,
        });
        // Bidi streaming
        service.methods.push(Method {
            name: "BidiStream".to_string(),
            proto_name: "BidiStream".to_string(),
            comments: Default::default(),
            input_type: "Request".to_string(),
            output_type: "Response".to_string(),
            input_proto_type: "Request".to_string(),
            output_proto_type: "Response".to_string(),
            options: Default::default(),
            client_streaming: true,
            server_streaming: true,
        });

        let config = QuillConfig::default();
        let code = generate_server(&service, &config);

        assert!(code.is_some());
        let code = code.unwrap();
        // Verify all methods are generated
        assert!(code.contains("unary_call"));
        assert!(code.contains("server_stream"));
        assert!(code.contains("client_stream"));
        assert!(code.contains("bidi_stream"));
        // Verify all registration methods are used
        assert!(code.contains("builder = builder . register"));  // unary
        assert!(code.contains("register_streaming"));  // server streaming
        assert!(code.contains("register_client_streaming"));
        assert!(code.contains("register_bidi_streaming"));
    }
}
