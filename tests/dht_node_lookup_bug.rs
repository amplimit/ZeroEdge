use zero_edge::dht::{NodeId, NodeInfo, PublicDht, PublicDhtConfig, validate_node_id};
use zero_edge::crypto::KeyPair;
use std::time::Duration;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

/// 重现并测试实际使用中发现的DHT节点查找问题
///
/// 此测试模拟用户报告的问题：节点被正确添加到DHT，但使用find_node查找时找不到
#[tokio::test]
async fn test_dht_node_lookup_in_real_usage() {
    // 创建本地节点配置
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
    
    // 创建并启动DHT实例
    let dht = PublicDht::new(config);
    dht.start().await.expect("Failed to start DHT");
    
    // 创建远程节点
    let remote_id = NodeId::random();
    let remote_keypair = KeyPair::generate().expect("Failed to generate keypair");
    let remote_info = NodeInfo::new_signed(
        remote_id.clone(),
        remote_keypair.public.clone(),
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001)],
        1,
        false,
        &remote_keypair.secret,
    ).expect("Failed to create remote node info");
    
    // 1. 首先确认DHT路由表为空
    let initial_table = dht.list_routing_table();
    assert!(initial_table.is_empty(), "初始路由表应为空");
    
    // 2. 手动将节点添加到DHT
    dht.add_node_sync(remote_info.clone()).expect("Failed to add remote node");
    
    // 3. 确认节点已添加到路由表
    let updated_table = dht.list_routing_table();
    assert!(!updated_table.is_empty(), "添加节点后路由表不应为空");
    
    // 验证节点是否在路由表中
    let mut found = false;
    for (id, info) in &updated_table {
        if *id == remote_id {
            found = true;
            println!("在路由表中找到节点: {:?}", info);
            break;
        }
    }
    assert!(found, "远程节点应出现在路由表中");
    
    // 4. 现在通过DHT的find_node API查找该节点
    println!("测试查找刚添加的节点，ID: {}", remote_id);
    let lookup_result = dht.find_node(&remote_id).await;
    
    // 验证查找结果
    assert!(lookup_result.is_ok(), "节点查找应该成功");
    let found_nodes = lookup_result.unwrap();
    
    // 这是关键断言 - 验证find_node能找到刚添加的节点
    assert!(!found_nodes.is_empty(), "find_node应该返回至少一个节点");
    
    // 验证找到的是正确的节点
    if !found_nodes.is_empty() {
        assert_eq!(found_nodes[0].id, remote_id, "找到的节点ID应匹配");
    }
    
    // 5. 测试查找不存在的节点
    let nonexistent_id = NodeId::random();
    println!("测试查找不存在的节点，ID: {}", nonexistent_id);
    let not_found_result = dht.find_node(&nonexistent_id).await;
    
    assert!(not_found_result.is_ok(), "查找不存在的节点应该返回成功结果");
    let not_found_nodes = not_found_result.unwrap();
    assert!(not_found_nodes.is_empty(), "查找不存在的节点应该返回空列表");
    
    // 6. 验证节点ID验证功能
    let valid_id_str = remote_id.to_string();
    let validation_result = validate_node_id(&valid_id_str);
    assert!(validation_result.is_ok(), "有效节点ID应该通过验证");
    
    let invalid_id = "invalid_id_format";
    let invalid_result = validate_node_id(invalid_id);
    assert!(invalid_result.is_err(), "无效节点ID应该被拒绝");
    
    // 7. 确保正确关闭DHT
    dht.stop().await.expect("Failed to stop DHT");
}

/// 测试DHT的精确匹配模式
///
/// 这个测试检查find_node实现是否正确地仅返回精确匹配的节点
#[tokio::test]
async fn test_dht_exact_match_mode() {
    // 创建本地节点配置
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
    
    // 创建并启动DHT实例
    let dht = PublicDht::new(config);
    dht.start().await.expect("Failed to start DHT");
    
    // 创建多个节点并添加到DHT
    let node_ids = (0..5).map(|_| NodeId::random()).collect::<Vec<_>>();
    let mut node_infos = Vec::new();
    
    for (i, id) in node_ids.iter().enumerate() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let port = 8001 + i as u16;
        let info = NodeInfo::new_signed(
            id.clone(),
            keypair.public.clone(),
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)],
            1,
            false,
            &keypair.secret,
        ).expect("Failed to create node info");
        
        dht.add_node_sync(info.clone()).expect("Failed to add node");
        node_infos.push(info);
    }
    
    // 确认所有节点都已添加到路由表
    let table = dht.list_routing_table();
    assert_eq!(table.len(), node_ids.len(), "路由表应包含所有添加的节点");
    
    // 测试每个节点ID的精确匹配
    for (i, id) in node_ids.iter().enumerate() {
        println!("测试节点 {}: {}", i, id);
        let result = dht.find_node(id).await.expect("节点查找失败");
        
        // 验证只返回了精确匹配的节点
        assert_eq!(result.len(), 1, "查找应该只返回1个精确匹配的节点");
        assert_eq!(result[0].id, *id, "返回的节点ID应该精确匹配");
    }
    
    // 测试不存在的节点ID
    let nonexistent_id = NodeId::random();
    let not_found_result = dht.find_node(&nonexistent_id).await.expect("查找操作失败");
    assert!(not_found_result.is_empty(), "查找不存在的节点应返回空列表");
    
    // 关闭DHT
    dht.stop().await.expect("Failed to stop DHT");
}
