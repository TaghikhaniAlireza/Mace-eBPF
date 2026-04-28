#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = aegis_ebpf::SensorConfig::default();
    let mut rx = aegis_ebpf::start_sensor(config).await?;

    log::info!("Sensor started. Listening for memory events...");
    while let Some(event) = rx.recv().await {
        log::debug!(
            "[{}] tgid={} pid={} comm={} type={:?} addr=0x{:x} flags=0x{:x} ret={}",
            event.timestamp_ns,
            event.tgid,
            event.pid,
            String::from_utf8_lossy(&event.comm).trim_matches('\0'),
            event.event_type,
            event.addr,
            event.flags,
            event.ret
        );
    }
    Ok(())
}
