use anyhow::{Context, Result};
use tun::AbstractDevice;

pub struct TunConfig {
    pub name: Option<String>,
    pub mtu: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    #[allow(dead_code)]
    pub setup_addresses: bool,
}

pub fn create_tun(cfg: &TunConfig) -> Result<tun::Device> {
    let mut tun_cfg = tun::Configuration::default();

    tun_cfg.layer(tun::Layer::L3);

    if let Some(ref name) = cfg.name {
        tun_cfg.tun_name(name);
    }

    #[cfg(target_os = "linux")]
    tun_cfg.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let dev = tun::create(&tun_cfg).context("failed to create TUN device")?;

    log::info!(
        "TUN device created: {}",
        dev.tun_name().unwrap_or_else(|_| "unknown".into())
    );
    Ok(dev)
}

pub async fn configure_tun(cfg: &TunConfig, dev: &tun::Device) -> Result<()> {
    use futures::stream::TryStreamExt;

    let tun_name = dev
        .tun_name()
        .context("failed to get TUN device name")?
        .clone();

    let (connection, handle, _) =
        rtnetlink::new_connection().context("failed to create netlink connection")?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(tun_name.clone()).execute();
    let link = links
        .try_next()
        .await
        .context("failed to query link")?
        .context("TUN device not found via netlink")?;
    let link_index = link.header.index;

    handle
        .link()
        .set(
            rtnetlink::LinkUnspec::new_with_index(link_index)
                .mtu(cfg.mtu)
                .build(),
        )
        .execute()
        .await
        .context("failed to set MTU")?;
    log::info!("MTU set to {}", cfg.mtu);

    if let Some(ref ipv4) = cfg.ipv4 {
        let addr: std::net::Ipv4Addr = ipv4.parse().context("invalid IPv4 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V4(addr), 32)
            .execute()
            .await
            .context("failed to add IPv4 address")?;
        log::info!("IPv4 address {addr}/32 added");
    }

    if let Some(ref ipv6) = cfg.ipv6 {
        let addr: std::net::Ipv6Addr = ipv6.parse().context("invalid IPv6 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V6(addr), 128)
            .execute()
            .await
            .context("failed to add IPv6 address")?;
        log::info!("IPv6 address {addr}/128 added");
    }

    handle
        .link()
        .set(
            rtnetlink::LinkUnspec::new_with_index(link_index)
                .up()
                .build(),
        )
        .execute()
        .await
        .context("failed to bring link up")?;
    log::info!("Link {tun_name} is UP");

    Ok(())
}
