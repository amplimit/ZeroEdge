use zero_edge::{
    dht::{NodeId, NodeInfo, PublicDht, PublicDhtConfig},
    crypto::KeyPair,
};
use std::time::Duration;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

/// 测试修复后的DHT节点查找功能
/// 
/// 验证现在可以正确找到添加的节点
#[tokio::test]
async fn test_dht_fixed_node_lookup() {
    // 创建本地节点
    let local_keypair = KeyPair::generate().expect("Failed to generate keypair");
    let local_id = NodeId::from_public_key(&local_keypair.public).unwrap();
    
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
    
    // 创建并启动DHT实例
    let dht = PublicDht::new(config);
    dht.start().await.expect("Failed to start DHT");
    
    // 创建远程节点
    let remote_keypair = KeyPair::generate().expect("Failed to generate keypair");
    let remote_id = NodeId::from_public_key(&remote_keypair.public).unwrap();
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    
    let remote_node_info = NodeInfo::new_signed(
        remote_id.clone(),
        remote_keypair.public.clone(),
        vec![remote_addr],
        1,
        false,
        &remote_keypair.secret,
    ).expect("Failed to create remote node info");
    
    // 1. 确认DHT路由表初始为空
    let initial_size = dht.routing_table_size();
    assert_eq!(initial_size, 0, "初始路由表应为空");
    
    // 2. 添加节点到DHT
    let add_result = dht.add_node_sync(remote_node_info.clone());
    assert!(add_result.is_ok(), "添加节点应该成功");
    
    // 3. 确认节点已添加到路由表
    let updated_size = dht.routing_table_size();
    assert_eq!(updated_size, 1, "添加节点后路由表应包含1个节点");
    
    // 4. 验证可以通过路由表查看添加的节点
    let routing_table = dht.list_routing_table();
    assert!(!routing_table.is_empty(), "路由表不应为空");
    
    let mut found_in_table = false;
    for (id, info) in routing_table.iter() {
        if *id == remote_id {
            found_in_table = true;
            assert_eq!(info.id, remote_id, "节点ID应匹配");
            assert_eq!(info.addresses[0], remote_addr, "节点地址应匹配");
            break;
        }
    }
    assert!(found_in_table, "远程节点应出现在路由表中");
    
    // 5. 现在测试DHT的find_node API - 这是修复的核心功能
    println!("测试查找刚添加的节点，ID: {}", remote_id);
    let lookup_result = dht.find_node(&remote_id).await;
    
    // 验证查找结果
    assert!(lookup_result.is_ok(), "节点查找应该成功: {:?}", lookup_result);
    let found_nodes = lookup_result.unwrap();
    
    // 关键断言：验证find_node现在能找到刚添加的节点
    assert!(!found_nodes.is_empty(), "find_node应该返回至少一个节点");
    
    // 验证找到的是正确的节点
    assert_eq!(found_nodes[0].id, remote_id, "找到的节点ID应匹配");
    assert_eq!(found_nodes[0].addresses[0], remote_addr, "找到的节点地址应匹配");
    
    println!("✅ 成功找到节点！ID: {}, 地址: {}", found_nodes[0].id, found_nodes[0].addresses[0]);
    
    // 6. 测试查找不存在的节点
    let nonexistent_id = NodeId::random();
    println!("测试查找不存在的节点，ID: {}", nonexistent_id);
    let not_found_result = dht.find_node(&nonexistent_id).await;
    
    assert!(not_found_result.is_ok(), "查找不存在的节点应该返回成功结果");
    let not_found_nodes = not_found_result.unwrap();
    
    // 对于不存在的节点，应该返回空列表或最近的节点
    println!("查找不存在节点的结果：找到 {} 个节点", not_found_nodes.len());
    
    // 7. 停止DHT
    dht.stop().await.expect("Failed to stop DHT");
    
    println!("✅ DHT节点查找功能测试通过！问题已修复。");
}

/// 测试基本的PublicDht创建和操作
#[tokio::test]
async fn test_dht_basic_operations() {
    let keypair = KeyPair::generate().expect("Failed to generate keypair");
    let node_id = NodeId::from_public_key(&keypair.public).unwrap();
    
    let config = PublicDhtConfig {
        local_id: node_id,
        local_public_key: keypair.public,
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400),
        node_ttl: Duration::from_secs(7200),
        refresh_interval: Duration::from_secs(3600),
        republish_interval: Duration::from_secs(21600),
        replication_factor: 5,
    };
    
    let dht = PublicDht::new(config);
    
    // 测试启动
    let start_result = dht.start().await;
    assert!(start_result.is_ok(), "DHT应该能够成功启动");
    
    // 测试初始状态
    assert_eq!(dht.routing_table_size(), 0, "初始路由表应为空");
    
    // 测试停止
    let stop_result = dht.stop().await;
    assert!(stop_result.is_ok(), "DHT应该能够成功停止");
}