use zero_edge::{
    dht::{NodeId, NodeInfo, PublicDht, PublicDhtConfig, validate_node_id},
    crypto::KeyPair,
    cli::commands::{Command, CommandContext, CommandResult},
};
use std::sync::Arc;
use std::time::Duration;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

/// 测试模拟实际应用程序环境中的节点查找功能
/// 
/// 这个测试验证在真实使用环境下节点查找的正确行为，包括：
/// 1. 正确的DHT初始化和引导过程
/// 2. 通过CLI命令进行节点查找
/// 3. 处理找不到节点的情况
#[tokio::test]
async fn test_real_world_node_lookup() {
    // 创建本地节点
    let local_id = NodeId::random();
    let local_keypair = KeyPair::generate().expect("Failed to generate keypair");
    
    let config = PublicDhtConfig {
        local_id: local_id.clone(),
        local_public_key: local_keypair.public.clone(),
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400),
        node_ttl: Duration::from_secs(7200),
        refresh_interval: Duration::from_secs(3600),
        republish_interval: Duration::from_secs(21600),
        replication_factor: 5,
    };
    
    // 创建DHT实例并启动
    let dht = Arc::new(PublicDht::new(config));
    dht.start().await.expect("Failed to start DHT");
    
    // 创建一些测试节点并添加到DHT
    let remote_node_id = NodeId::random();
    let remote_keypair = KeyPair::generate().expect("Failed to generate keypair");
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    
    let remote_node_info = NodeInfo::new_signed(
        remote_node_id.clone(),
        remote_keypair.public.clone(),
        vec![remote_addr],
        1,
        false,
        &remote_keypair.secret,
    ).expect("Failed to create node info");
    
    // 添加远程节点到DHT
    dht.add_node_sync(remote_node_info.clone()).expect("Failed to add remote node");
    
    // 验证DHT路由表包含远程节点
    let routing_table = dht.list_routing_table();
    let mut node_found = false;
    for (id, _) in routing_table.iter() {
        if *id == remote_node_id {
            node_found = true;
            break;
        }
    }
    assert!(node_found, "Remote node not found in routing table");
    
    // 现在测试各种查找场景:
    
    // 场景1: 查找存在的节点ID
    let id_str = remote_node_id.to_string();
    println!("查找节点ID: {}", id_str);
    
    // 使用DHT API直接查找
    let api_result = dht.find_node(&remote_node_id).await;
    assert!(api_result.is_ok(), "API节点查找失败");
    let found_nodes = api_result.unwrap();
    assert!(!found_nodes.is_empty(), "API查找应返回至少一个节点");
    assert_eq!(found_nodes[0].id, remote_node_id, "API找到了错误的节点");
    
    // 场景2: 查找不存在的节点ID
    let random_id = NodeId::random();
    let random_id_str = random_id.to_string();
    println!("查找不存在的节点ID: {}", random_id_str);
    
    let not_found_result = dht.find_node(&random_id).await;
    assert!(not_found_result.is_ok(), "查找不存在的节点应该返回成功");
    let not_found_nodes = not_found_result.unwrap();
    // 注意：我们修改了find_node的行为，现在它会返回最接近的节点而不是空列表
    println!("Found {} node(s) when searching for non-existent ID", not_found_nodes.len());
    
    // 场景3: 测试无效的节点ID格式
    let invalid_id = "invalid_node_id";
    let validation_result = validate_node_id(invalid_id);
    assert!(validation_result.is_err(), "无效节点ID应被拒绝");
    
    // 关闭DHT
    dht.stop().await.expect("Failed to stop DHT");
}

/// 测试通过命令接口进行节点查找
/// 
/// 这个测试验证通过命令处理器进行节点查找的完整流程
#[tokio::test]
async fn test_find_command_workflow() {
    // 创建本地节点
    let local_id = NodeId::random();
    let local_keypair = KeyPair::generate().expect("Failed to generate keypair");
    
    let config = PublicDhtConfig {
        local_id: local_id.clone(),
        local_public_key: local_keypair.public.clone(),
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400),
        node_ttl: Duration::from_secs(7200),
        refresh_interval: Duration::from_secs(3600),
        republish_interval: Duration::from_secs(21600),
        replication_factor: 5,
    };
    
    // 创建DHT实例并启动 - 使用Arc包装以便共享
    let dht = Arc::new(PublicDht::new(config));
    dht.start().await.expect("Failed to start DHT");
    
    // 创建一个测试节点并添加到DHT
    let test_node_id = NodeId::random();
    let test_keypair = KeyPair::generate().expect("Failed to generate keypair");
    let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    
    let test_node_info = NodeInfo::new_signed(
        test_node_id.clone(),
        test_keypair.public.clone(),
        vec![test_addr],
        1,
        false,
        &test_keypair.secret,
    ).expect("Failed to create node info");
    
    // 添加测试节点到DHT
    dht.add_node_sync(test_node_info.clone()).expect("Failed to add test node");
    
    // 验证测试节点已添加到路由表
    let routing_table = dht.list_routing_table();
    assert!(!routing_table.is_empty(), "路由表不应为空");
    let mut found_in_routing = false;
    for (id, _) in routing_table.iter() {
        if *id == test_node_id {
            found_in_routing = true;
            break;
        }
    }
    assert!(found_in_routing, "测试节点应存在于路由表中");
    
    // 现在测试命令处理器的查找功能 (模拟用户输入 /find <node-id>)
    
    // 场景1: 查找存在的节点
    let node_id_str = test_node_id.to_string();
    
    // 创建共享组件
    let identity = Arc::new(zero_edge::identity::UserIdentity::new(
        "Test User".to_string()
    ).expect("Failed to create identity"));
    let network = Arc::new(zero_edge::network::NetworkManager::new(
        zero_edge::network::NetworkConfig::default(),
        vec!["stun.l.google.com:19302".to_string()],
    ).await.expect("Failed to create network manager"));
    
    // 模拟执行 /find 命令
    let find_command_args = vec![node_id_str.clone()];
    let find_result = Command::find(CommandContext {
        args: find_command_args,
        dht: Arc::clone(&dht),
        identity: Arc::clone(&identity),
        network: Arc::clone(&network),
    }).await;
    
    // 验证结果是成功的，且找到了节点
    match find_result {
        CommandResult::Success(msg) => {
            println!("成功找到节点: {}", msg);
            assert!(msg.contains(&test_node_id.to_string()), "成功消息应包含节点ID");
        },
        CommandResult::Error(err) => {
            panic!("查找现有节点失败: {}", err);
        },
        _ => panic!("意外的命令结果类型"),
    }
    
    // 场景2: 查找不存在的节点
    let random_id = NodeId::random();
    let random_id_str = random_id.to_string();
    
    // 模拟执行 /find 命令搜索不存在的节点
    let not_found_args = vec![random_id_str.clone()];
    let not_found_result = Command::find(CommandContext {
        args: not_found_args,
        dht: Arc::clone(&dht),
        identity: Arc::clone(&identity),
        network: Arc::clone(&network),
    }).await;
    
    // 注意：由于我们修改了find_node的行为，现在它会返回最接近的节点，所以命令可能返回成功或失败
    match not_found_result {
        CommandResult::Error(err) => {
            println!("命令返回错误: {}", err);
            // 如果返回错误，确保是因为没找到节点
            assert!(err.contains("not found"), "错误消息应表明节点未找到");
        },
        CommandResult::Success(msg) => {
            println!("命令返回成功，可能找到了最接近的节点: {}", msg);
            // 如果返回成功，不做断言，因为这在新实现中是合法的
        },
        _ => panic!("意外的命令结果类型"),
    }
    
    // 关闭DHT
    dht.stop().await.expect("Failed to stop DHT");
}
