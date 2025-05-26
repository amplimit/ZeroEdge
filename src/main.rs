use zero_edge::dht::{NodeId, PublicDht, PublicDhtConfig};
use zero_edge::network::{NetworkManager, NetworkConfig};
use zero_edge::identity::UserIdentity;
use zero_edge::identity::device::DeviceType;
use zero_edge::nat::NatTraversal;
use zero_edge::cli::CommandProcessor;

use std::net::SocketAddr;
use std::str::FromStr;
use std::convert::TryFrom;
use std::time::Duration;
use std::sync::Arc;
use log::{info, warn, error, debug};
use env_logger::Env;
use tokio::sync::mpsc;
use tokio::task;
use tokio::signal::ctrl_c;
use clap::{Parser, ArgAction};
use colored::*;
use dirs;
use std::path::PathBuf;
use zero_edge::utils::config::Config;
use zero_edge::dht::NodeInfo;
use zero_edge::crypto::PublicKey;
use chrono;
use bincode;

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
    /// DHT 引导节点列表，格式: <nodeid_hex>@<ip>:<port>
    #[clap(short, long, action = ArgAction::Append)]
    bootstrap: Vec<String>,
    
    /// 启用详细日志
    #[clap(short, long, action = ArgAction::SetTrue)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 解析命令行参数
    let args = Args::parse();
    
    // 加载配置文件
    let config_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zeroedge")
        .join("config.json");
    let mut config = Config::load(&config_path)?;
    // 命令行指定的引导节点覆盖配置
    if !args.bootstrap.is_empty() {
        config.bootstrap_nodes = args.bootstrap.clone();
    }
    // 首次运行时保存默认配置
    if !config_path.exists() {
        config.save(&config_path)?;
    }
    config.ensure_data_dir()?;
    
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
    let network = Arc::new(NetworkManager::new(network_config, stun_servers).await?);
    
    // 启动网络
    info!("Starting network...");
    network.start().await?;
    // 引导 DHT
    if !config.bootstrap_nodes.is_empty() {
        let mut boot_nodes = Vec::new();
        for node_str in &config.bootstrap_nodes {
            if let Some((id_str, addr_str)) = node_str.split_once('@') {
                match (hex::decode(id_str), addr_str.parse::<SocketAddr>()) {
                    (Ok(id_bytes), Ok(addr)) => {
                        if let Ok(node_id) = NodeId::try_from(id_bytes.as_slice()) {
                            let node_info = NodeInfo::new(
                                node_id,
                                PublicKey::dummy(),
                                vec![addr],
                                1,
                                false,
                            );
                            boot_nodes.push(node_info);
                        } else {
                            warn!("Invalid bootstrap node id: {}", id_str);
                        }
                    }
                    _ => warn!("Invalid bootstrap node format: {}", node_str),
                }
            } else {
                warn!("Invalid bootstrap node format: {}", node_str);
            }
        }
        if !boot_nodes.is_empty() {
            info!("Bootstrapping DHT with {} nodes", boot_nodes.len());
            dht.bootstrap(&boot_nodes).await?;
        }
    }
    
    // 创建共享引用
    info!("Creating shared references...");
    let dht_arc = Arc::new(dht);
    let network_arc = Arc::clone(&network);
    let identity_arc = Arc::new(identity);
    
    // 创建命令处理器
    info!("Initializing command interface...");
    let (mut command_processor, command_rx, result_tx) = CommandProcessor::new(
        dht_arc.clone(),
        network_arc.clone(),
        identity_arc.clone(),
    );
    
    // 启动消息接收处理器
    let network_clone = Arc::clone(&network);
    let message_handle = task::spawn(async move {
        message_receiver_handler(network_clone).await;
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
    let _ = message_handle.await;
    let _ = processor_handle.await;
    
    info!("ZeroEdge node stopped.");
    Ok(())
}

/// 命令处理函数
async fn command_handler(
    mut command_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<zero_edge::cli::commands::CommandResult>,
    dht: Arc<PublicDht>,
    network: Arc<NetworkManager>,
    identity: Arc<UserIdentity>,
) {
    use zero_edge::cli::commands::{Command, CommandContext, CommandResult};
    
    // 命令映射
    let mut commands = std::collections::HashMap::new();
    commands.insert("Command::Help", Command::Help);
    commands.insert("Command::Exit", Command::Exit);
    commands.insert("Command::Send", Command::Send);
    commands.insert("Command::Contacts", Command::Contacts);
    commands.insert("Command::CreateGroup", Command::CreateGroup);
    commands.insert("Command::AddToGroup", Command::AddToGroup);
    commands.insert("Command::Find", Command::Find);
    commands.insert("Command::WhoAmI", Command::WhoAmI);
    commands.insert("Command::Status", Command::Status);
    commands.insert("Command::DhtRoutes", Command::DhtRoutes);
    
    while let Some(cmd_str) = command_rx.recv().await {
        info!("Received command: {}", cmd_str);
        
        // 解析命令字符串
        let cmd_type = if cmd_str.starts_with("Command::") {
            cmd_str.split_whitespace().next().unwrap_or("")
        } else {
            ""  // 未知命令类型
        };
        
        // 查找命令
        let command = match commands.get(cmd_type) {
            Some(cmd) => cmd,
            None => {
                // 如果找不到命令，返回信息
                if let Err(e) = result_tx.send(CommandResult::Info(format!("Processing command: {}", cmd_str))).await {
                    error!("Failed to send command result: {}", e);
                }
                continue;
            }
        };
        
        // 执行命令
        let context = CommandContext {
            dht: dht.clone(),
            network: network.clone(),
            identity: identity.clone(),
            args: vec![], // 这里简化处理，实际应从cmd_str解析参数
        };
        
        let result = command.execute(context).await;
        
        // 发送结果
        if let Err(e) = result_tx.send(result).await {
            error!("Failed to send command result: {}", e);
        }
        
        // 如果是退出命令，则退出循环
        if matches!(command, Command::Exit) {
            break;
        }
    }
}

/// 消息接收处理器
async fn message_receiver_handler(network: Arc<NetworkManager>) {
    info!("Message receiver handler started.");
    
    let mut interval = tokio::time::interval(Duration::from_millis(100)); // 每100ms检查一次
    
    loop {
        interval.tick().await;
        
        // 获取所有已连接的对等点
        let peers = network.get_connected_peers().await;
        
        // 检查每个对等点是否有新消息
        for peer in peers {
            match peer.receive().await {
                Ok(data) => {
                    // 尝试反序列化消息
                    match bincode::deserialize::<zero_edge::message::Message>(&data) {
                        Ok(message) => {
                            // 显示接收到的消息
                            display_received_message(&message, &peer).await;
                        },
                        Err(e) => {
                            // 可能是协议消息或其他数据，记录但不显示错误
                            debug!("Received non-message data from {}: {} bytes ({})", 
                                peer.get_info().id, data.len(), e);
                        }
                    }
                },
                Err(zero_edge::network::PeerError::Timeout) => {
                    // 超时是正常的，继续检查下一个对等点
                    continue;
                },
                Err(e) => {
                    // 其他错误，记录但继续
                    debug!("Error receiving from peer {}: {}", peer.get_info().id, e);
                }
            }
        }
    }
}

/// 显示接收到的消息
async fn display_received_message(message: &zero_edge::message::Message, peer: &zero_edge::network::Peer) {
    use colored::*;
    
    let timestamp = chrono::DateTime::from_timestamp(message.timestamp as i64, 0)
        .unwrap_or_else(chrono::Utc::now)
        .format("%H:%M:%S");
    
    // 获取消息内容
    let content = String::from_utf8_lossy(&message.content);
    
    // 显示消息
    println!("{} {} {}: {}", 
        format!("[{}]", timestamp).blue(),
        "📨".green(),
        peer.get_info().id.bright_cyan(),
        content.white()
    );
}
