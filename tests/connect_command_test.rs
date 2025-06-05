use zero_edge::{
    dht::{NodeId, PublicDht, PublicDhtConfig},
    crypto::KeyPair,
    cli::commands::{Command, CommandContext},
    network::{NetworkManager, NetworkConfig},
    identity::UserIdentity,
};
use std::time::Duration;
use std::sync::Arc;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

/// 测试/connect命令的功能
/// 验证可以手动添加节点到DHT路由表
#[tokio::test]
async fn test_connect_command() {
    // 创建本地身份
    let identity = UserIdentity::new("Test User".to_string()).expect("Failed to create identity");
    let local_id = NodeId::from_public_key(&identity.keypair.public).unwrap();
    
    // 创建DHT配置
    let dht_config = PublicDhtConfig {
        local_id: local_id.clone(),
        local_public_key: identity.keypair.public.clone(),
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400),
        node_ttl: Duration::from_secs(7200),
        refresh_interval: Duration::from_secs(3600),
        republish_interval: Duration::from_secs(21600),
        replication_factor: 5,
    };
    
    // 创建并启动DHT
    let dht = PublicDht::new(dht_config);
    dht.start().await.expect("Failed to start DHT");
    
    // 创建网络管理器（模拟）
    let network_config = NetworkConfig::default();
    let stun_servers = vec!["stun.l.google.com:19302".to_string()];
    let network = NetworkManager::new(network_config, stun_servers).await
        .expect("Failed to create network manager");
    
    // 创建命令上下文
    let context = CommandContext {
        dht: Arc::new(dht),
        network: Arc::new(network),
        identity: Arc::new(identity),
        args: vec![
            "39b65115dfaef3d92bc0d421d8ba8e1ee26acc847b8742b04b5730f4e1eec732@127.0.0.1:8080".to_string()
        ],
    };
    
    // 测试连接命令
    let connect_command = Command::Connect;
    let result = connect_command.execute(context.clone()).await;
    
    // 验证结果
    match result {
        zero_edge::cli::commands::CommandResult::Success(msg) => {
            println!("✅ Connect command succeeded: {}", msg);
            assert!(msg.contains("Connected to node") || msg.contains("Added node"));
        },
        zero_edge::cli::commands::CommandResult::Warning(msg) => {
            println!("⚠️  Connect command with warning: {}", msg);
            // 警告也算成功，因为节点可能无法验证连接但已添加到路由表
            assert!(msg.contains("Added node"));
        },
        other => {
            panic!("Expected success or warning, got: {:?}", other);
        }
    }
    
    // 验证节点是否已添加到DHT路由表
    let routing_table_size = context.dht.routing_table_size();
    assert!(routing_table_size > 0, "节点应该已添加到DHT路由表");
    
    // 验证可以从路由表中看到添加的节点
    let routing_table = context.dht.list_routing_table();
    let target_id = NodeId::from_str("39b65115dfaef3d92bc0d421d8ba8e1ee26acc847b8742b04b5730f4e1eec732")
        .expect("Invalid node ID");
    
    let mut found = false;
    for (id, _info) in routing_table.iter() {
        if *id == target_id {
            found = true;
            break;
        }
    }
    assert!(found, "目标节点应该出现在路由表中");
    
    println!("✅ /connect 命令测试通过！");
}

/// 测试/connect命令的错误处理
#[tokio::test]
async fn test_connect_command_error_cases() {
    // 创建基本上下文
    let identity = UserIdentity::new("Test User".to_string()).expect("Failed to create identity");
    let local_id = NodeId::from_public_key(&identity.keypair.public).unwrap();
    
    let dht_config = PublicDhtConfig {
        local_id: local_id.clone(),
        local_public_key: identity.keypair.public.clone(),
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400),
        node_ttl: Duration::from_secs(7200),
        refresh_interval: Duration::from_secs(3600),
        republish_interval: Duration::from_secs(21600),
        replication_factor: 5,
    };
    
    let dht = PublicDht::new(dht_config);
    dht.start().await.expect("Failed to start DHT");
    
    let network_config = NetworkConfig::default();
    let stun_servers = vec!["stun.l.google.com:19302".to_string()];
    let network = NetworkManager::new(network_config, stun_servers).await
        .expect("Failed to create network manager");
    
    // 测试1: 无参数
    let context_no_args = CommandContext {
        dht: Arc::new(dht.clone()),
        network: Arc::new(network.clone()),
        identity: Arc::new(identity.clone()),
        args: vec![],
    };
    
    let result = Command::Connect.execute(context_no_args).await;
    match result {
        zero_edge::cli::commands::CommandResult::Error(msg) => {
            assert!(msg.contains("Usage: /connect"));
        },
        _ => panic!("应该返回使用说明错误"),
    }
    
    // 测试2: 无效格式（缺少@）
    let context_bad_format = CommandContext {
        dht: Arc::new(dht.clone()),
        network: Arc::new(network.clone()),
        identity: Arc::new(identity.clone()),
        args: vec!["invalid_format".to_string()],
    };
    
    let result = Command::Connect.execute(context_bad_format).await;
    match result {
        zero_edge::cli::commands::CommandResult::Error(msg) => {
            assert!(msg.contains("Invalid format"));
        },
        _ => panic!("应该返回格式错误"),
    }
    
    // 测试3: 无效节点ID
    let context_bad_id = CommandContext {
        dht: Arc::new(dht.clone()),
        network: Arc::new(network.clone()),
        identity: Arc::new(identity.clone()),
        args: vec!["invalid_id@127.0.0.1:8080".to_string()],
    };
    
    let result = Command::Connect.execute(context_bad_id).await;
    match result {
        zero_edge::cli::commands::CommandResult::Error(msg) => {
            assert!(msg.contains("Invalid node ID format"));
        },
        _ => panic!("应该返回节点ID格式错误"),
    }
    
    // 测试4: 无效地址
    let context_bad_addr = CommandContext {
        dht: Arc::new(dht),
        network: Arc::new(network),
        identity: Arc::new(identity),
        args: vec!["39b65115dfaef3d92bc0d421d8ba8e1ee26acc847b8742b04b5730f4e1eec732@invalid_address".to_string()],
    };
    
    let result = Command::Connect.execute(context_bad_addr).await;
    match result {
        zero_edge::cli::commands::CommandResult::Error(msg) => {
            assert!(msg.contains("Invalid address"));
        },
        _ => panic!("应该返回地址格式错误"),
    }
    
    println!("✅ /connect 命令错误处理测试通过！");
}

// 辅助函数扩展NodeId
trait NodeIdExt {
    fn from_str(s: &str) -> Result<NodeId, String>;
}

impl NodeIdExt for NodeId {
    fn from_str(s: &str) -> Result<NodeId, String> {
        let bytes = hex::decode(s).map_err(|e| format!("Invalid NodeId hex: {}", e))?;
        NodeId::try_from(bytes.as_slice()).map_err(|e| e.to_string())
    }
}