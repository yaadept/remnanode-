//! REST routes (`/node/...`) and the internal socket routes Xray talks to.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, Validation};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tower_http::{compression::CompressionLayer, decompression::RequestDecompressionLayer};

use crate::{
    app::App,
    dto::*,
    error::*,
    http::{ConnInfo, Kill},
    plugin::SyncPlugin,
    xray::service::StartRequest,
};

type Ctx = State<Arc<App>>;
type ApiResult = Result<Json<Value>, ApiError>;

const BODY_LIMIT: usize = 1000 * 1024 * 1024;

fn wrap(v: impl Serialize) -> Json<Value> {
    Json(json!({ "response": v }))
}

// ------------------------------------------------------------------ extractor

pub struct ValidJson<T>(pub T);

impl<S, T> FromRequest<S> for ValidJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Validate,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| ApiError::validation(vec![e.to_string()]))?;
        let value: T = serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::validation(vec![e.to_string()]))?;
        let errors = value.validate();
        if errors.is_empty() {
            Ok(Self(value))
        } else {
            Err(ApiError::validation(errors))
        }
    }
}

// ------------------------------------------------------------------ middleware

/// Drops the connection without a reply. The handler then parks forever so the response can
/// never race the teardown; the connection task is dropped as soon as the token fires.
async fn destroy(req_ext: &axum::http::Extensions) -> Response {
    if let Some(Kill(token)) = req_ext.get::<Kill>() {
        token.cancel();
    }
    std::future::pending().await
}

async fn not_found(req: Request) -> Response {
    destroy(req.extensions()).await
}

fn jwt_validation() -> Validation {
    let mut v = Validation::new(Algorithm::RS256);
    // passport-jwt: `exp` is honoured when present but not required.
    v.required_spec_claims.clear();
    v.validate_exp = true;
    v.validate_nbf = true;
    v.leeway = 0;
    v.validate_aud = false;
    v
}

async fn jwt_auth(State(app): Ctx, req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            let (scheme, rest) = h.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
        });
    let valid = token
        .is_some_and(|t| jsonwebtoken::decode::<Value>(t, &app.jwt_key, &jwt_validation()).is_ok());
    if valid {
        return next.run(req).await;
    }
    let ip = req
        .extensions()
        .get::<ConnInfo>()
        .and_then(|c| c.0)
        .map(|a| a.ip().to_string());
    tracing::error!(
        "Incorrect SECRET_KEY or JWT! Request dropped. URL: {}, IP: {}",
        req.uri(),
        ip.unwrap_or_default()
    );
    destroy(req.extensions()).await
}

/// Turns `ApiError` markers into the JSON error bodies of the original service.
async fn render_errors(req: Request, next: Next) -> Response {
    let path = req.uri().to_string();
    let resp = next.run(req).await;
    let Some(p) = resp.extensions().get::<ErrorPayload>().cloned() else {
        return resp;
    };
    let body = if p.error_code == "VALIDATION" {
        serde_json::from_str::<Value>(&p.message)
            .unwrap_or_else(|_| json!({ "message": p.message }))
    } else {
        json!({
            "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "path": path,
            "message": p.message,
            "errorCode": p.error_code,
        })
    };
    (p.status, Json(body)).into_response()
}

// ------------------------------------------------------------------ public router

pub fn node_router(app: Arc<App>) -> Router {
    Router::new()
        // xray
        .route("/node/xray/start", post(xray_start))
        .route("/node/xray/stop", get(xray_stop))
        .route("/node/xray/healthcheck", get(xray_health))
        // handler
        .route("/node/handler/add-user", post(add_user))
        .route("/node/handler/remove-user", post(remove_user))
        .route("/node/handler/add-users", post(add_users))
        .route("/node/handler/remove-users", post(remove_users))
        .route(
            "/node/handler/drop-users-connections",
            post(drop_users_connections),
        )
        .route("/node/handler/drop-ips", post(drop_ips))
        // stats
        .route("/node/stats/get-user-online-status", post(user_online))
        .route("/node/stats/get-geocheck", post(geocheck))
        .route("/node/stats/get-system-stats", get(system_stats))
        .route("/node/stats/get-users-stats", post(users_stats))
        .route("/node/stats/get-inbound-stats", post(inbound_stats))
        .route("/node/stats/get-outbound-stats", post(outbound_stats))
        .route("/node/stats/get-all-inbounds-stats", post(all_inbounds))
        .route("/node/stats/get-all-outbounds-stats", post(all_outbounds))
        .route("/node/stats/get-combined-stats", post(combined))
        .route("/node/stats/get-user-ip-list", post(user_ip_list))
        .route("/node/stats/get-users-ip-list", get(users_ip_list))
        // plugin
        .route("/node/plugin/sync", post(plugin_sync))
        .route(
            "/node/plugin/torrent-blocker/collect",
            post(collect_reports),
        )
        .route("/node/plugin/nftables/block-ips", post(block_ips))
        .route("/node/plugin/nftables/unblock-ips", post(unblock_ips))
        .route(
            "/node/plugin/nftables/recreate-tables",
            post(recreate_tables),
        )
        .route_layer(middleware::from_fn_with_state(app.clone(), jwt_auth))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .layer(middleware::from_fn(render_errors))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(CompressionLayer::new())
        .layer(RequestDecompressionLayer::new())
        .with_state(app)
}

// ------------------------------------------------------------------ xray

async fn xray_start(
    State(app): Ctx,
    Extension(conn): Extension<ConnInfo>,
    ValidJson(body): ValidJson<StartRequest>,
) -> ApiResult {
    let ip = conn.0.map(|a| a.ip().to_string()).unwrap_or_default();
    Ok(wrap(app.xray.start(body, &ip).await))
}

async fn xray_stop(State(app): Ctx) -> ApiResult {
    tracing::info!("Remnawave requested to stop Xray.");
    let stopped = app.xray.stop(true, false).await;
    Ok(wrap(json!({ "isStopped": stopped })))
}

async fn xray_health(State(app): Ctx) -> ApiResult {
    Ok(wrap(app.xray.health()))
}

// ------------------------------------------------------------------ handler

async fn add_user(State(app): Ctx, ValidJson(b): ValidJson<AddUserRequest>) -> ApiResult {
    Ok(wrap(app.add_user(b).await?))
}

async fn remove_user(State(app): Ctx, ValidJson(b): ValidJson<RemoveUserRequest>) -> ApiResult {
    Ok(wrap(app.remove_user(b).await?))
}

async fn add_users(State(app): Ctx, ValidJson(b): ValidJson<AddUsersRequest>) -> ApiResult {
    Ok(wrap(app.add_users(b).await?))
}

async fn remove_users(State(app): Ctx, ValidJson(b): ValidJson<RemoveUsersRequest>) -> ApiResult {
    Ok(wrap(app.remove_users(b).await?))
}

async fn drop_users_connections(
    State(app): Ctx,
    ValidJson(b): ValidJson<DropUsersConnectionsRequest>,
) -> ApiResult {
    Ok(wrap(
        json!({ "success": app.drop_users_connections(b).await }),
    ))
}

async fn drop_ips(State(app): Ctx, ValidJson(b): ValidJson<DropIpsRequest>) -> ApiResult {
    Ok(wrap(json!({ "success": app.drop_ips(b) })))
}

// ------------------------------------------------------------------ stats

async fn user_online(State(app): Ctx, ValidJson(b): ValidJson<UsernameRequest>) -> ApiResult {
    Ok(wrap(
        json!({ "isOnline": app.user_online(&b.username).await }),
    ))
}

async fn geocheck(State(app): Ctx, ValidJson(b): ValidJson<GeocheckRequest>) -> ApiResult {
    Ok(wrap(app.geocheck(b).await?))
}

async fn system_stats(State(app): Ctx) -> ApiResult {
    Ok(wrap(app.system_stats().await?))
}

async fn users_stats(State(app): Ctx, ValidJson(b): ValidJson<ResetRequest>) -> ApiResult {
    Ok(wrap(json!({ "users": app.users_stats(b.reset).await? })))
}

async fn inbound_stats(State(app): Ctx, ValidJson(b): ValidJson<TagResetRequest>) -> ApiResult {
    Ok(wrap(app.inbound_stats(&b.tag, b.reset).await?))
}

async fn outbound_stats(State(app): Ctx, ValidJson(b): ValidJson<TagResetRequest>) -> ApiResult {
    Ok(wrap(app.outbound_stats(&b.tag, b.reset).await?))
}

async fn all_inbounds(State(app): Ctx, ValidJson(b): ValidJson<ResetRequest>) -> ApiResult {
    Ok(wrap(
        json!({ "inbounds": app.all_inbounds(b.reset, FAILED_TO_GET_INBOUNDS_STATS).await? }),
    ))
}

async fn all_outbounds(State(app): Ctx, ValidJson(b): ValidJson<ResetRequest>) -> ApiResult {
    Ok(wrap(
        json!({ "outbounds": app.all_outbounds(b.reset).await? }),
    ))
}

async fn combined(State(app): Ctx, ValidJson(b): ValidJson<ResetRequest>) -> ApiResult {
    let inbounds = app
        .all_inbounds(b.reset, FAILED_TO_GET_COMBINED_STATS)
        .await?;
    let outbounds = app
        .all_outbounds(b.reset)
        .await
        .map_err(|_| ApiError::known(FAILED_TO_GET_COMBINED_STATS))?;
    Ok(wrap(
        json!({ "inbounds": inbounds, "outbounds": outbounds }),
    ))
}

async fn user_ip_list(State(app): Ctx, ValidJson(b): ValidJson<UserIdRequest>) -> ApiResult {
    Ok(wrap(json!({ "ips": app.user_ip_list(&b.user_id).await })))
}

async fn users_ip_list(State(app): Ctx) -> ApiResult {
    Ok(wrap(json!({ "users": app.users_ip_list().await })))
}

// ------------------------------------------------------------------ plugin

async fn plugin_sync(State(app): Ctx, ValidJson(b): ValidJson<SyncRequest>) -> ApiResult {
    let plugin: Option<SyncPlugin> = b.plugin;
    let outcome = app.plugins.sync(plugin).await;
    if outcome.remove_torrent_outbound {
        app.remove_torrent_outbound().await;
    }
    if outcome.stop_xray {
        app.xray.stop(false, true).await;
    }
    Ok(wrap(json!({ "accepted": outcome.accepted })))
}

async fn collect_reports(State(app): Ctx) -> ApiResult {
    Ok(wrap(json!({ "reports": app.plugins.collect_reports() })))
}

async fn block_ips(State(app): Ctx, ValidJson(b): ValidJson<BlockIpsRequest>) -> ApiResult {
    let ips: Vec<(String, u64)> = b
        .ips
        .into_iter()
        .map(|i| (i.ip, i.timeout.max(0.0) as u64))
        .collect();
    Ok(wrap(
        json!({ "accepted": app.plugins.block_ips(&ips).await }),
    ))
}

async fn unblock_ips(State(app): Ctx, ValidJson(b): ValidJson<UnblockIpsRequest>) -> ApiResult {
    Ok(wrap(
        json!({ "accepted": app.plugins.unblock_ips(&b.ips).await }),
    ))
}

async fn recreate_tables(State(app): Ctx) -> ApiResult {
    Ok(wrap(
        json!({ "accepted": app.plugins.recreate_tables_endpoint().await }),
    ))
}

// ------------------------------------------------------------------ internal router (Xray -> node)

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn token_auth(State(app): Ctx, req: Request, next: Next) -> Response {
    let token = req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("token="))
            .map(str::to_string)
    });
    let expected = &app.cfg.internal_rest_token;
    if !expected.is_empty()
        && token
            .as_deref()
            .is_some_and(|t| ct_eq(t.as_bytes(), expected.as_bytes()))
    {
        return next.run(req).await;
    }
    destroy(req.extensions()).await
}

pub fn internal_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/internal/get-config", get(internal_get_config))
        .route("/internal/webhook", post(internal_webhook))
        .route_layer(middleware::from_fn_with_state(app.clone(), token_auth))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(app)
}

async fn internal_get_config(State(app): Ctx) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        app.internal.xray_config_json(),
    )
        .into_response()
}

async fn internal_webhook(State(app): Ctx, body: Bytes) -> StatusCode {
    match serde_json::from_slice::<Value>(&body) {
        Ok(v) => {
            let plugins = app.plugins.clone();
            tokio::spawn(async move { plugins.handle_xray_webhook(v).await });
            StatusCode::OK
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"a"));
    }
}
