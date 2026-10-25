use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug, Clone, Copy)]
pub struct KnownError {
    pub code: &'static str,
    pub message: &'static str,
}

pub const INTERNAL_SERVER_ERROR: KnownError = KnownError {
    code: "A001",
    message: "Server error",
};
pub const FAILED_TO_GET_SYSTEM_STATS: KnownError = KnownError {
    code: "A010",
    message: "Failed to get system stats",
};
pub const FAILED_TO_GET_USERS_STATS: KnownError = KnownError {
    code: "A011",
    message: "Failed to get users stats",
};
pub const FAILED_TO_GET_INBOUND_STATS: KnownError = KnownError {
    code: "A012",
    message: "Failed to get inbound stats",
};
pub const FAILED_TO_GET_OUTBOUND_STATS: KnownError = KnownError {
    code: "A013",
    message: "Failed to get outbound stats",
};
pub const FAILED_TO_GET_INBOUNDS_STATS: KnownError = KnownError {
    code: "A015",
    message: "Failed to get inbounds stats",
};
pub const FAILED_TO_GET_OUTBOUNDS_STATS: KnownError = KnownError {
    code: "A016",
    message: "Failed to get outbounds stats",
};
pub const FAILED_TO_GET_COMBINED_STATS: KnownError = KnownError {
    code: "A017",
    message: "Failed to get combined stats",
};
pub const FAILED_TO_GET_GEOCHECK: KnownError = KnownError {
    code: "A018",
    message: "Failed to get geocheck report",
};

/// Body filled in with `path` / `timestamp` by the response middleware.
#[derive(Debug, Clone)]
pub struct ErrorPayload {
    pub status: StatusCode,
    pub message: String,
    pub error_code: String,
}

#[derive(Debug, Clone)]
pub struct ApiError(pub ErrorPayload);

impl ApiError {
    pub fn known(e: KnownError) -> Self {
        Self::with(e, e.message.to_string())
    }

    pub fn with(e: KnownError, message: String) -> Self {
        Self(ErrorPayload {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
            error_code: e.code.to_string(),
        })
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::with(INTERNAL_SERVER_ERROR, message.into())
    }

    pub fn validation(errors: Vec<String>) -> Self {
        Self(ErrorPayload {
            status: StatusCode::BAD_REQUEST,
            message: serde_json::json!({
                "statusCode": 400,
                "message": "Validation failed",
                "errors": errors.iter().map(|m| serde_json::json!({ "message": m })).collect::<Vec<_>>(),
            })
            .to_string(),
            error_code: "VALIDATION".into(),
        })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = self.0.status.into_response();
        resp.extensions_mut().insert(self.0);
        resp
    }
}
