use zero_edge::dht::{NodeId, PublicDht, PublicDhtConfig};
use zero_edge::network::{NetworkManager, NetworkConfig};
use zero_edge::identity::UserIdentity;
use zero_edge::identity::device::DeviceType;
use zero_edge::nat::NatTraversal;
use zero_edge::cli::CommandProcessor;

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use std::sync::Arc;
use log::{info, warn, error};
use env_logger::Env;
use tokio::sync::mpsc;
use tokio::task;
use tokio::signal::ctrl_c;
use clap::{Parser, ArgAction};
use colored::*;

/// 命令行参数
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// 节点名称
    #[clap(short, long, default_value = "ZeroEdge Node")]
    name: String,
    
    /// 监听端口
    #[clap(short, long, default_value = "0")]
    port: u16,
    
    /// 日志级别
    #[clap(long, default_value = "info")]
    log_level: String,
    
    /// 启用详细日志
    #[clap(short, long, action = ArgAction::SetTrue)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 解析命令行参数
    let args = Args::parse();
    
    // 初始化日志
    let log_level = if args.verbose { "debug" } else { &args.log_level };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();
    
    info!("{}", format!("Starting ZeroEdge node {}...", args.name).green().bold());
    
    // 生成身份
    info!("Generating identity...");
    let identity = UserIdentity::new(args.name.clone())?;
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
    let local_addr = SocketAddr::from_str(&format!("0.0.0.0:{}", args.port))?;
    
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
    
    // 创建命令处理器
    info!("Initializing command interface...");
    let (mut command_processor, command_rx, result_tx) = CommandProcessor::new(
        dht,
        network,
        identity,
    );
    
    // 启动命令处理线程
    let command_handle = task::spawn(async move {
        command_handler(command_rx, result_tx).await;
    });
    
    // 启动命令处理器
    let processor_handle = task::spawn(async move {
        if let Err(e) = command_processor.start().await {
            error!("Command processor error: {}", e);
        }
    });
    
    // 等待Ctrl+C信号
    match ctrl_c().await {
        Ok(()) => {
            info!("Shutting down...");
        },
        Err(e) => {
            error!("Error waiting for Ctrl+C: {}", e);
        }
    }
    
    // 等待任务完成
    let _ = command_handle.await;
    let _ = processor_handle.await;
    
    info!("ZeroEdge node stopped.");
    Ok(())
}

/// 命令处理函数
async fn command_handler(
    mut command_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<zero_edge::cli::commands::CommandResult>,
) {
    use zero_edge::cli::commands::{Command, CommandContext, CommandResult};
    
    while let Some(cmd_str) = command_rx.recv().await {
        // 解析命令字符串
        // 注意：这里简化了解析逻辑，实际应该使用更健壮的方式
        if cmd_str.contains("Command::Help") {
            let _ = result_tx.send(Command::Help.execute(CommandContext {
                dht: Arc::new(PublicDht::new(PublicDhtConfig::default())),
                network: Arc::new(NetworkManager::new(NetworkConfig::default(), vec![]).await.unwrap()),
                identity: Arc::new(UserIdentity::new("Temp".to_string()).unwrap()),
                args: vec![],
            }).await).await;
        } else if cmd_str.contains("Command::Exit") {
            let _ = result_tx.send(CommandResult::Exit).await;
            break;
        } else {
            // 其他命令处理
            let _ = result_tx.send(CommandResult::Info(format!("Processing command: {}", cmd_str))).await;
        }
    }
}
