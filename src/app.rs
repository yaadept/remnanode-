use std::sync::Arc;

use jsonwebtoken::DecodingKey;

use crate::{
    config::Config,
    internal::InternalState,
    plugin::PluginService,
    sys::{self, NetworkStats},
    xray::service::XrayService,
};

pub struct App {
    pub cfg: Arc<Config>,
    pub xray: Arc<XrayService>,
    pub internal: Arc<InternalState>,
    pub plugins: Arc<PluginService>,
    pub net: NetworkStats,
    pub jwt_key: DecodingKey,
    pub cap_net_admin: bool,
    pub geocheck_running: std::sync::atomic::AtomicBool,
}

impl App {
    pub fn new(
        cfg: Arc<Config>,
        xray: Arc<XrayService>,
        internal: Arc<InternalState>,
        plugins: Arc<PluginService>,
        net: NetworkStats,
        jwt_key: DecodingKey,
    ) -> Arc<Self> {
        let cap_net_admin = sys::has_cap_net_admin();
        if cap_net_admin {
            tracing::info!("[OK] CAP_NET_ADMIN is available");
        } else {
            tracing::warn!("CAP_NET_ADMIN is not available.");
        }
        Arc::new(Self {
            cfg,
            xray,
            internal,
            plugins,
            net,
            jwt_key,
            cap_net_admin,
            geocheck_running: Default::default(),
        })
    }
}
