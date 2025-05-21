use zero_edge::dht::{NodeId, PublicDht, PublicDhtConfig};
use zero_edge::network::{NetworkManager, NetworkConfig};
use zero_edge::identity::UserIdentity;
use zero_edge::identity::device::DeviceType;
use zero_edge::nat::NatTraversal;

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use log::{info, warn};
use env_logger::Env;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    info!("Starting ZeroEdge node...");
    
    // 生成身份
    info!("Generating identity...");
    let identity = UserIdentity::new("ZeroEdge Node".to_string())?;
    let user_id = identity.id.clone();
    let keypair = identity.keypair.clone();
    
    // 显示身份信息
    info!("User ID: {}", user_id);
    
    // 创建设备
    info!("Creating device...");
    let device = zero_edge::identity::DeviceInfo::new(
        "My Device".to_string(),
        &keypair,
        DeviceType::Desktop,
        Some(user_id.clone()),
    )?;
    
    // 打印设备ID
    info!("Device ID: {}", device.device_id);
    
    // 配置本地地址
    let local_addr = SocketAddr::from_str("0.0.0.0:0")?;
    
    // 获取NAT映射
    info!("Discovering NAT mapping...");
    let stun_servers = vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun2.l.google.com:19302".to_string(),
    ];
    
    let mut nat_traversal = NatTraversal::new(local_addr, stun_servers.clone());
    
    match nat_traversal.discover_mapping().await {
        Ok(mapping) => {
            info!("NAT mapping discovered: {}", mapping.public_addr);
            info!("NAT type: {}", mapping.nat_type);
        },
        Err(e) => {
            warn!("Failed to discover NAT mapping: {}", e);
        }
    }
    
    // 创建DHT配置 - 不使用default()方法
    let node_id = NodeId::from_public_key(&keypair.public)?;
    
    // 手动创建PublicDhtConfig而不是使用default()
    let dht_config = PublicDhtConfig {
        local_id: node_id,
        local_public_key: keypair.public.clone(),
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400), // 24小时
        node_ttl: Duration::from_secs(7200),    // 2小时
        refresh_interval: Duration::from_secs(3600), // 1小时
        republish_interval: Duration::from_secs(43200), // 12小时
        replication_factor: 3,
    };
    
    // 创建DHT
    info!("Creating DHT...");
    let dht = PublicDht::new(dht_config);
    
    // 启动DHT
    info!("Starting DHT...");
    dht.start().await?;
    
    // 创建网络配置
    let mut network_config = NetworkConfig::default();
    network_config.local_address = local_addr;
    
    // 创建网络管理器
    info!("Creating network manager...");
    let network = NetworkManager::new(network_config, stun_servers).await?;
    
    // 启动网络
    info!("Starting network...");
    network.start().await?;
    
    // 简单的指令循环
    info!("ZeroEdge node is running. Press Ctrl+C to exit.");
    info!("Use 'help' for available commands.");
    
    // 持续运行
    loop {
        sleep(Duration::from_secs(1)).await;
    }
}
