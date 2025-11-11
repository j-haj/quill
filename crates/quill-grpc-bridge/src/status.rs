//! gRPC status code to HTTP status and Problem Details mapping

use http::StatusCode;
use quill_core::ProblemDetails;
use tonic::Code;

/// Convert gRPC status code to HTTP status code
///
/// Maps gRPC canonical error codes to appropriate HTTP status codes
/// following common REST API conventions.
pub fn grpc_to_http_status(code: Code) -> StatusCode {
    match code {
        Code::Ok => StatusCode::OK,
        Code::Cancelled => StatusCode::from_u16(499).unwrap(), // Client Closed Request
        Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        Code::InvalidArgument => StatusCode::BAD_REQUEST,
        Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        Code::NotFound => StatusCode::NOT_FOUND,
        Code::AlreadyExists => StatusCode::CONFLICT,
        Code::PermissionDenied => StatusCode::FORBIDDEN,
        Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        Code::Aborted => StatusCode::CONFLICT,
        Code::OutOfRange => StatusCode::BAD_REQUEST,
        Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
        Code::Unauthenticated => StatusCode::UNAUTHORIZED,
    }
}

/// Convert HTTP status code to gRPC status code
pub fn http_to_grpc_status(status: StatusCode) -> Code {
    match status.as_u16() {
        200..=299 => Code::Ok,
        400 => Code::InvalidArgument,
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::NotFound,
        409 => Code::AlreadyExists,
        412 => Code::FailedPrecondition,
        429 => Code::ResourceExhausted,
        499 => Code::Cancelled,
        500 => Code::Internal,
        501 => Code::Unimplemented,
        503 => Code::Unavailable,
        504 => Code::DeadlineExceeded,
        _ => Code::Unknown,
    }
}

/// Convert gRPC status to Quill Problem Details
///
/// Creates a Problem Details structure following RFC 7807 from a gRPC status.
pub fn grpc_to_problem_details(code: Code, message: String) -> ProblemDetails {
    let http_status = grpc_to_http_status(code);

    ProblemDetails {
        type_uri: format!("urn:grpc:status:{}", code_to_string(code)),
        title: code_to_title(code),
        status: http_status.as_u16(),
        detail: Some(message),
        instance: None,
        quill_proto_type: None,
        quill_proto_detail_base64: None,
    }
}

/// Convert HTTP status and Problem Details to gRPC status
pub fn problem_details_to_grpc_status(details: &ProblemDetails) -> (Code, String) {
    let code = http_to_grpc_status(
        StatusCode::from_u16(details.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    );

    let message = details.detail.clone()
        .unwrap_or_else(|| details.title.clone());

    (code, message)
}

fn code_to_string(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

fn code_to_title(code: Code) -> String {
    match code {
        Code::Ok => "OK".to_string(),
        Code::Cancelled => "Request Cancelled".to_string(),
        Code::Unknown => "Unknown Error".to_string(),
        Code::InvalidArgument => "Invalid Argument".to_string(),
        Code::DeadlineExceeded => "Deadline Exceeded".to_string(),
        Code::NotFound => "Not Found".to_string(),
        Code::AlreadyExists => "Already Exists".to_string(),
        Code::PermissionDenied => "Permission Denied".to_string(),
        Code::ResourceExhausted => "Resource Exhausted".to_string(),
        Code::FailedPrecondition => "Failed Precondition".to_string(),
        Code::Aborted => "Aborted".to_string(),
        Code::OutOfRange => "Out of Range".to_string(),
        Code::Unimplemented => "Unimplemented".to_string(),
        Code::Internal => "Internal Error".to_string(),
        Code::Unavailable => "Service Unavailable".to_string(),
        Code::DataLoss => "Data Loss".to_string(),
        Code::Unauthenticated => "Unauthenticated".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_to_http_status() {
        assert_eq!(grpc_to_http_status(Code::Ok), StatusCode::OK);
        assert_eq!(grpc_to_http_status(Code::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(grpc_to_http_status(Code::InvalidArgument), StatusCode::BAD_REQUEST);
        assert_eq!(grpc_to_http_status(Code::Unauthenticated), StatusCode::UNAUTHORIZED);
        assert_eq!(grpc_to_http_status(Code::PermissionDenied), StatusCode::FORBIDDEN);
        assert_eq!(grpc_to_http_status(Code::Internal), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_http_to_grpc_status() {
        assert_eq!(http_to_grpc_status(StatusCode::OK), Code::Ok);
        assert_eq!(http_to_grpc_status(StatusCode::NOT_FOUND), Code::NotFound);
        assert_eq!(http_to_grpc_status(StatusCode::BAD_REQUEST), Code::InvalidArgument);
        assert_eq!(http_to_grpc_status(StatusCode::UNAUTHORIZED), Code::Unauthenticated);
        assert_eq!(http_to_grpc_status(StatusCode::FORBIDDEN), Code::PermissionDenied);
    }

    #[test]
    fn test_grpc_to_problem_details() {
        let details = grpc_to_problem_details(
            Code::NotFound,
            "User not found".to_string()
        );

        assert_eq!(details.status, 404);
        assert_eq!(details.title, "Not Found");
        assert_eq!(details.detail, Some("User not found".to_string()));
        assert!(details.type_uri.contains("NOT_FOUND"));
    }

    #[test]
    fn test_problem_details_to_grpc_status() {
        let details = ProblemDetails {
            type_uri: "urn:quill:error:404".to_string(),
            title: "Not Found".to_string(),
            status: 404,
            detail: Some("Resource not found".to_string()),
            instance: None,
            quill_proto_type: None,
            quill_proto_detail_base64: None,
        };

        let (code, message) = problem_details_to_grpc_status(&details);
        assert_eq!(code, Code::NotFound);
        assert_eq!(message, "Resource not found");
    }

    #[test]
    fn test_roundtrip_conversion() {
        let original_code = Code::PermissionDenied;
        let http_status = grpc_to_http_status(original_code);
        let converted_code = http_to_grpc_status(http_status);

        assert_eq!(original_code, converted_code);
    }
}
