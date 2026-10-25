//! State shared between the REST handlers and the Xray process: the config Xray pulls
//! on start, and the per-inbound user fingerprints used to decide whether a restart
//! is needed (port of `InternalService`).

use std::{
    collections::{BTreeSet, HashMap},
    sync::Mutex,
    time::Instant,
};

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::hashed_set::HashedSet;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundHash {
    #[allow(dead_code)]
    pub users_count: f64,
    pub hash: String,
    pub tag: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hashes {
    pub empty_config: String,
    pub inbounds: Vec<InboundHash>,
}

#[derive(Default)]
struct Inner {
    xray_config: Option<Map<String, Value>>,
    empty_config_hash: Option<String>,
    inbounds: HashMap<String, HashedSet>,
    xtls_config_inbounds: BTreeSet<String>,
}

#[derive(Default)]
pub struct InternalState {
    inner: Mutex<Inner>,
}

impl InternalState {
    /// The stored config serialized in place (no deep copy of a possibly huge document).
    pub fn xray_config_json(&self) -> Vec<u8> {
        let g = self.inner.lock().unwrap();
        match &g.xray_config {
            Some(cfg) => serde_json::to_vec(cfg).unwrap_or_else(|_| b"{}".to_vec()),
            None => b"{}".to_vec(),
        }
    }

    pub fn extract_users_from_config(&self, hashes: &Hashes, new_config: Map<String, Value>) {
        let mut g = self.inner.lock().unwrap();
        Self::cleanup_locked(&mut g);

        g.empty_config_hash = Some(hashes.empty_config.clone());

        tracing::info!("Starting user extraction from inbounds...");
        tracing::info!("▸ Empty Config Hash: {}", hashes.empty_config);
        let started = Instant::now();

        if let Some(Value::Array(inbounds)) = new_config.get("inbounds") {
            let valid: HashMap<&str, &str> = hashes
                .inbounds
                .iter()
                .map(|i| (i.tag.as_str(), i.hash.as_str()))
                .collect();

            for inbound in inbounds {
                let Some(tag) = inbound.get("tag").and_then(Value::as_str) else {
                    continue;
                };
                if tag.is_empty() || !valid.contains_key(tag) {
                    continue;
                }
                let mut users = HashedSet::new();
                if let Some(Value::Array(clients)) = inbound.pointer("/settings/clients") {
                    for client in clients {
                        if let Some(id) = client.get("id").and_then(Value::as_str)
                            && !id.is_empty()
                        {
                            users.add(id);
                        }
                    }
                }
                g.inbounds.insert(tag.to_string(), users);
            }

            let tags: Vec<String> = g.inbounds.keys().cloned().collect();
            for tag in tags {
                g.xtls_config_inbounds.insert(tag.clone());
                let users = &g.inbounds[&tag];
                tracing::info!(
                    "▸ {tag} · {} users · {} ({})",
                    users.len(),
                    users.hash64_string(),
                    valid.get(tag.as_str()).copied().unwrap_or("N/A")
                );
            }
        }

        g.xray_config = Some(new_config);
        tracing::info!("User extraction completed in {:?}", started.elapsed());
    }

    pub fn is_need_restart_core(&self, incoming: &Hashes) -> bool {
        let g = self.inner.lock().unwrap();
        let Some(empty) = &g.empty_config_hash else {
            return true;
        };

        if &incoming.empty_config != empty {
            tracing::warn!("Detected changes in Xray Core base configuration");
            return true;
        }
        if incoming.inbounds.len() != g.inbounds.len() {
            tracing::warn!("Number of Xray Core inbounds has changed");
            return true;
        }
        for (tag, users) in &g.inbounds {
            let Some(remote) = incoming.inbounds.iter().find(|i| &i.tag == tag) else {
                tracing::warn!("Inbound {tag} no longer exists in Xray Core configuration");
                return true;
            };
            if users.hash64_string() != remote.hash {
                tracing::warn!(
                    "User configuration changed for inbound {tag} ({} → {})",
                    users.hash64_string(),
                    remote.hash
                );
                return true;
            }
        }
        tracing::info!("Xray Core configuration is up-to-date - no restart required");
        false
    }

    pub fn add_user_to_inbound(&self, tag: &str, user: &str) {
        let mut g = self.inner.lock().unwrap();
        // Deliberate deviation from upstream: an inbound that just received a user must stay
        // addressable by `remove-user`, even if the add-user cleanup pass dropped it while it
        // was still empty.
        g.xtls_config_inbounds.insert(tag.to_string());
        match g.inbounds.get_mut(tag) {
            Some(set) => set.add(user),
            None => {
                tracing::warn!("Inbound {tag} not found in inboundsHashMap, creating new one");
                let mut set = HashedSet::new();
                set.add(user);
                g.inbounds.insert(tag.to_string(), set);
            }
        }
    }

    pub fn remove_user_from_inbound(&self, tag: &str, user: &str) {
        let mut g = self.inner.lock().unwrap();
        let Some(set) = g.inbounds.get_mut(tag) else {
            return;
        };
        set.delete(user);
        if set.len() == 0 {
            g.xtls_config_inbounds.remove(tag);
            g.inbounds.remove(tag);
            tracing::warn!("Inbound {tag} has no users, clearing inboundsHashMap.");
        }
    }

    pub fn xtls_config_inbounds(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .xtls_config_inbounds
            .iter()
            .cloned()
            .collect()
    }

    pub fn add_xtls_config_inbound(&self, tag: &str) {
        self.inner
            .lock()
            .unwrap()
            .xtls_config_inbounds
            .insert(tag.to_string());
    }

    pub fn cleanup(&self) {
        let mut g = self.inner.lock().unwrap();
        Self::cleanup_locked(&mut g);
    }

    fn cleanup_locked(g: &mut Inner) {
        tracing::info!("Cleaning up internal service.");
        g.inbounds.clear();
        g.xtls_config_inbounds.clear();
        g.xray_config = None;
        g.empty_config_hash = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hashes(empty: &str, inbounds: &[(&str, &str)]) -> Hashes {
        Hashes {
            empty_config: empty.into(),
            inbounds: inbounds
                .iter()
                .map(|(t, h)| InboundHash {
                    users_count: 0.0,
                    hash: (*h).into(),
                    tag: (*t).into(),
                })
                .collect(),
        }
    }

    fn config(ids: &[&str]) -> Map<String, Value> {
        let clients: Vec<_> = ids.iter().map(|i| json!({"id": i})).collect();
        json!({"inbounds": [{"tag": "vless-in", "settings": {"clients": clients}}, {"tag": "ignored"}]})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn restart_decision_follows_fingerprints() {
        let st = InternalState::default();
        assert!(
            st.is_need_restart_core(&hashes("e", &[])),
            "nothing loaded yet"
        );

        let mut expect = HashedSet::new();
        expect.add("11111111-1111-1111-1111-111111111111");
        let h = expect.hash64_string();

        st.extract_users_from_config(
            &hashes("e", &[("vless-in", &h)]),
            config(&["11111111-1111-1111-1111-111111111111"]),
        );
        assert!(!st.is_need_restart_core(&hashes("e", &[("vless-in", &h)])));
        assert!(st.is_need_restart_core(&hashes("other", &[("vless-in", &h)])));
        assert!(st.is_need_restart_core(&hashes("e", &[("vless-in", "deadbeef")])));
        assert!(st.is_need_restart_core(&hashes("e", &[])));
    }

    #[test]
    fn added_user_keeps_inbound_addressable_for_removal() {
        let st = InternalState::default();
        st.extract_users_from_config(
            &hashes("e", &[("vless-in", "0000000000000000")]),
            config(&[]),
        );
        // add-user flow: register tag, cleanup pass on the (empty) inbound, then add
        st.add_xtls_config_inbound("vless-in");
        st.remove_user_from_inbound("vless-in", "u1");
        assert!(st.xtls_config_inbounds().is_empty());
        st.add_user_to_inbound("vless-in", "u1");
        assert_eq!(st.xtls_config_inbounds(), vec!["vless-in".to_string()]);
    }

    #[test]
    fn live_user_changes_update_the_fingerprint() {
        let st = InternalState::default();
        st.extract_users_from_config(
            &hashes("e", &[("vless-in", "0000000000000000")]),
            config(&[]),
        );
        st.add_user_to_inbound("vless-in", "u1");
        let mut expect = HashedSet::new();
        expect.add("u1");
        assert!(!st.is_need_restart_core(&hashes("e", &[("vless-in", &expect.hash64_string())])));
        st.remove_user_from_inbound("vless-in", "u1");
        assert!(
            st.xtls_config_inbounds().is_empty(),
            "empty inbound is dropped like upstream"
        );
    }
}
