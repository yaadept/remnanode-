//! Port of `generateApiConfig`: wraps the panel's Xray config with the API plumbing
//! (stats, gRPC API inbound, routing rule) and the optional torrent-blocker pieces.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

pub const API_TAG: &str = "REMNAWAVE_API";
pub const API_INBOUND_TAG: &str = "REMNAWAVE_API_INBOUND";
pub const TORRENT_BLOCKER_OUTBOUND_TAG: &str = "RW_TB_OUTBOUND_BLOCK";
pub const INTERNAL_WEBHOOK_PATH: &str = "/internal/webhook";

#[derive(Debug, Clone, Default)]
pub struct TorrentBlockerState {
    pub enabled: bool,
    pub include_rule_tags: HashSet<String>,
    pub rule_position: i64,
}

pub struct InternalParams<'a> {
    pub socket_path: &'a str,
    pub token: &'a str,
    pub xtls_api_socket_path: &'a str,
}

pub fn generate_api_config(
    config: &Map<String, Value>,
    tb: &TorrentBlockerState,
    internal: &InternalParams,
    has_cap_net_admin: bool,
) -> Map<String, Value> {
    // policy: only level 0 survives, with our stats flags forced on.
    let mut level0 = config
        .get("policy")
        .and_then(|p| p.get("levels"))
        .and_then(|l| l.get("0"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    level0.insert("statsUserUplink".into(), json!(true));
    level0.insert("statsUserDownlink".into(), json!(true));
    level0.insert("statsUserOnline".into(), json!(has_cap_net_admin));
    let policy = json!({
        "levels": { "0": level0 },
        "system": {
            "statsInboundDownlink": true,
            "statsInboundUplink": true,
            "statsOutboundDownlink": true,
            "statsOutboundUplink": true,
        },
    });

    let mut inbounds = vec![json!({
        "tag": API_INBOUND_TAG,
        "listen": format!("@{}", internal.xtls_api_socket_path),
        "protocol": "tunnel",
    })];
    if let Some(Value::Array(user)) = config.get("inbounds") {
        inbounds.extend(user.iter().cloned());
    }

    let mut outbounds: Vec<Value> = match config.get("outbounds") {
        Some(Value::Array(o)) => o.clone(),
        _ => Vec::new(),
    };

    let mut routing = match config.get("routing") {
        Some(Value::Object(r)) => r.clone(),
        _ => Map::new(),
    };
    let mut rules = vec![json!({ "inboundTag": [API_INBOUND_TAG], "outboundTag": API_TAG })];
    if let Some(Value::Array(user_rules)) = routing.get("rules") {
        rules.extend(
            user_rules
                .iter()
                .filter(|r| r.get("outboundTag").and_then(Value::as_str) != Some(API_TAG))
                .cloned(),
        );
    }

    if tb.enabled {
        let webhook_url = format!(
            "@{}:{}?token={}",
            internal.socket_path, INTERNAL_WEBHOOK_PATH, internal.token
        );

        outbounds.push(json!({ "tag": TORRENT_BLOCKER_OUTBOUND_TAG, "protocol": "blackhole" }));

        let idx = resolve_rule_index(tb.rule_position, rules.len());
        rules.insert(
            idx,
            json!({
                "protocol": ["bittorrent"],
                "outboundTag": TORRENT_BLOCKER_OUTBOUND_TAG,
                "webhook": { "url": webhook_url, "deduplication": 5 },
            }),
        );

        if !tb.include_rule_tags.is_empty() {
            for rule in rules.iter_mut() {
                let tagged = rule
                    .get("ruleTag")
                    .and_then(Value::as_str)
                    .is_some_and(|t| tb.include_rule_tags.contains(t));
                if tagged {
                    rule["webhook"] = json!({ "url": webhook_url, "deduplication": 5 });
                }
            }
        }
    }

    routing.insert("rules".into(), Value::Array(rules));

    let mut result = config.clone();
    result.insert("stats".into(), json!({}));
    result.insert(
        "api".into(),
        json!({ "services": ["HandlerService", "StatsService", "RoutingService"], "tag": API_TAG }),
    );
    result.insert("inbounds".into(), Value::Array(inbounds));
    result.insert("outbounds".into(), Value::Array(outbounds));
    result.insert("policy".into(), policy);
    result.insert("routing".into(), Value::Object(routing));
    result
}

fn resolve_rule_index(position: i64, rules_len: usize) -> usize {
    let user_rules = rules_len.saturating_sub(1);
    if position <= 0 {
        return 1;
    }
    1 + (position as usize).min(user_rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> InternalParams<'static> {
        InternalParams {
            socket_path: "rwint-x",
            token: "tok",
            xtls_api_socket_path: "xtls-api-x",
        }
    }

    fn base() -> Map<String, Value> {
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"tag": "in1", "protocol": "vless"}],
            "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}],
            "routing": { "rules": [
                {"outboundTag": "REMNAWAVE_API", "inboundTag": ["evil"]},
                {"ruleTag": "r1", "outboundTag": "DIRECT", "network": "tcp"},
                {"ruleTag": "r2", "outboundTag": "DIRECT", "network": "udp"},
            ]},
            "policy": {"levels": {"0": {"handshake": 4}, "1": {"handshake": 9}}},
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn wraps_config_with_api_plumbing() {
        let out = generate_api_config(&base(), &TorrentBlockerState::default(), &params(), true);
        assert_eq!(out["stats"], json!({}));
        assert_eq!(out["api"]["tag"], "REMNAWAVE_API");
        let inbounds = out["inbounds"].as_array().unwrap();
        assert_eq!(inbounds[0]["tag"], "REMNAWAVE_API_INBOUND");
        assert_eq!(inbounds[0]["listen"], "@xtls-api-x");
        assert_eq!(inbounds[1]["tag"], "in1");
        let rules = out["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3, "spoofed API rule is dropped, ours is first");
        assert_eq!(rules[0]["outboundTag"], "REMNAWAVE_API");
        assert_eq!(out["policy"]["levels"]["0"]["handshake"], 4);
        assert_eq!(out["policy"]["levels"]["0"]["statsUserOnline"], true);
        assert!(out["policy"]["levels"].get("1").is_none());
        assert_eq!(out["log"]["loglevel"], "warning");
    }

    #[test]
    fn online_stats_follow_capability() {
        let out = generate_api_config(&base(), &TorrentBlockerState::default(), &params(), false);
        assert_eq!(out["policy"]["levels"]["0"]["statsUserOnline"], false);
    }

    #[test]
    fn torrent_blocker_rule_and_outbound() {
        let tb = TorrentBlockerState {
            enabled: true,
            include_rule_tags: ["r2".to_string()].into(),
            rule_position: 1,
        };
        let out = generate_api_config(&base(), &tb, &params(), true);
        let rules = out["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[2]["protocol"], json!(["bittorrent"]));
        assert_eq!(
            rules[2]["webhook"]["url"],
            "@rwint-x:/internal/webhook?token=tok"
        );
        // position 1 -> after the first user rule
        let r2 = rules.iter().find(|r| r["ruleTag"] == "r2").unwrap();
        assert!(r2.get("webhook").is_some());
        let r1 = rules.iter().find(|r| r["ruleTag"] == "r1").unwrap();
        assert!(r1.get("webhook").is_none());
        let outs = out["outbounds"].as_array().unwrap();
        assert_eq!(outs.last().unwrap()["tag"], "RW_TB_OUTBOUND_BLOCK");
    }

    #[test]
    fn rule_index_clamps() {
        assert_eq!(resolve_rule_index(0, 3), 1);
        assert_eq!(resolve_rule_index(-5, 3), 1);
        assert_eq!(resolve_rule_index(1, 3), 2);
        assert_eq!(resolve_rule_index(1000, 3), 3);
    }
}
