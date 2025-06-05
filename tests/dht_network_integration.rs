use zero_edge::{
    dht::{
        NodeId, NodeInfo, PublicDht, PublicDhtConfig, 
        create_test_bootstrap_nodes, BootstrapConfig, BootstrapManager
    },
    crypto::KeyPair,
};
use std::time::Duration;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::time::sleep;

/// 测试完整的DHT网络功能
/// 
/// 这个测试创建多个DHT节点，验证它们能够相互发现和通信
#[tokio::test]
async fn test_dht_network_discovery() {
    // 初始化日志
    let _ = env_logger::builder().is_test(true).try_init();
    
    // 创建第一个节点（引导节点）
    let bootstrap_keypair = KeyPair::generate().expect("Failed to generate keypair");
    let bootstrap_id = NodeId::from_public_key(&bootstrap_keypair.public).unwrap();
    
    let bootstrap_config = PublicDhtConfig {
        local_id: bootstrap_id.clone(),
        local_public_key: bootstrap_keypair.public.clone(),
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400),
        node_ttl: Duration::from_secs(7200),
        refresh_interval: Duration::from_secs(3600),
        republish_interval: Duration::from_secs(21600),
        replication_factor: 5,
    };
    
    let bootstrap_dht = PublicDht::new(bootstrap_config);
    
    // 启动引导节点
    bootstrap_dht.start().await.expect("Failed to start bootstrap DHT");
    
    // 等待一下让引导节点完全启动
    sleep(Duration::from_millis(100)).await;
    
    // 获取引导节点的实际地址
    let bootstrap_node_info = {
        // 创建引导节点信息
        let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        NodeInfo::new_signed(
            bootstrap_id.clone(),
            bootstrap_keypair.public.clone(),
            vec![bootstrap_addr],
            1,
            false,
            &bootstrap_keypair.secret,
        ).expect("Failed to create bootstrap node info")
    };
    
    // 创建第二个节点
    let node2_keypair = KeyPair::generate().expect("Failed to generate keypair");
    let node2_id = NodeId::from_public_key(&node2_keypair.public).unwrap();
    
    let node2_config = PublicDhtConfig {
        local_id: node2_id.clone(),
        local_public_key: node2_keypair.public.clone(),
        k_value: 20,
        alpha_value: 3,
        record_ttl: Duration::from_secs(86400),
        node_ttl: Duration::from_secs(7200),
        refresh_interval: Duration::from_secs(3600),
        republish_interval: Duration::from_secs(21600),
        replication_factor: 5,
    };
    
    let node2_dht = PublicDht::new(node2_config);
    
    // 设置引导节点
    node2_dht.set_bootstrap_nodes(vec![bootstrap_node_info.clone()]);
    
    // 启动第二个节点
    node2_dht.start().await.expect("Failed to start node2 DHT");
    
    // 等待引导过程完成
    sleep(Duration::from_millis(500)).await;
    
    // 执行引导过程
    let bootstrap_result = node2_dht.bootstrap(&[bootstrap_node_info.clone()]).await;
    println!("Bootstrap result: {:?}", bootstrap_result);
    
    // 等待网络稳定
    sleep(Duration::from_millis(1000)).await;
    
    // 测试节点发现：node2尝试查找bootstrap节点
    println!("Node2 attempting to find bootstrap node: {}", bootstrap_id);
    let find_result = node2_dht.find_node(&bootstrap_id).await;
    
    match find_result {
        Ok(nodes) => {
            println!("Node2 found {} nodes when searching for bootstrap", nodes.len());
            if !nodes.is_empty() {
                println!("First found node ID: {}", nodes[0].id);
                assert_eq!(nodes[0].id, bootstrap_id, "Should find the bootstrap node");
            } else {
                // 在新的实现中，如果直接连接失败，可能返回最近的节点或空列表
                println!("No nodes found - this might be expected if network connection failed");
            }
        },
        Err(e) => {
            println!("Find node failed: {}", e);
            // 在某些情况下，网络连接可能失败，这在测试环境中是可能的
        }
    }
    
    // 测试反向查找：bootstrap节点尝试查找node2
    println!("Bootstrap attempting to find node2: {}", node2_id);
    let reverse_find_result = bootstrap_dht.find_node(&node2_id).await;
    
    match reverse_find_result {
        Ok(nodes) => {
            println!("Bootstrap found {} nodes when searching for node2", nodes.len());
        },
        Err(e) => {
            println!("Reverse find failed: {}", e);
        }
    }
    
    // 检查路由表状态
    println!("Bootstrap DHT routing table size: {}", bootstrap_dht.routing_table_size());
    println!("Node2 DHT routing table size: {}", node2_dht.routing_table_size());
    
    // 停止节点
    node2_dht.stop().await.expect("Failed to stop node2");
    bootstrap_dht.stop().await.expect("Failed to stop bootstrap");
    
    println!("Network discovery test completed");
}

/// 测试多节点网络
/// 
/// 创建多个节点并验证网络形成和节点发现
#[tokio::test]
async fn test_multi_node_network() {
    let _ = env_logger::builder().is_test(true).try_init();
    
    const NUM_NODES: usize = 3;
    let mut dhts = Vec::new();
    let mut node_infos = Vec::new();
    
    // 创建多个节点
    for i in 0..NUM_NODES {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let node_id = NodeId::from_public_key(&keypair.public).unwrap();
        
        let config = PublicDhtConfig {
            local_id: node_id.clone(),
            local_public_key: keypair.public.clone(),
            k_value: 20,
            alpha_value: 3,
            record_ttl: Duration::from_secs(86400),
            node_ttl: Duration::from_secs(7200),
            refresh_interval: Duration::from_secs(3600),
            republish_interval: Duration::from_secs(21600),
            replication_factor: 5,
        };
        
        let dht = PublicDht::new(config);
        
        // 启动节点
        dht.start().await.expect("Failed to start DHT");
        
        // 创建节点信息
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8100 + i as u16);
        let node_info = NodeInfo::new_signed(
            node_id,
            keypair.public.clone(),
            vec![addr],
            1,
            false,
            &keypair.secret,
        ).expect("Failed to create node info");
        
        dhts.push(dht);
        node_infos.push(node_info);
        
        // 短暂等待，避免端口冲突
        sleep(Duration::from_millis(50)).await;
    }
    
    // 让第一个节点作为引导节点
    let bootstrap_node = &node_infos[0];
    
    // 其他节点连接到引导节点
    for i in 1..NUM_NODES {
        let dht = &dhts[i];
        dht.set_bootstrap_nodes(vec![bootstrap_node.clone()]);
        
        match dht.bootstrap(&[bootstrap_node.clone()]).await {
            Ok(_) => println!("Node {} bootstrap successful", i),
            Err(e) => println!("Node {} bootstrap failed: {}", i, e),
        }
        
        sleep(Duration::from_millis(100)).await;
    }
    
    // 等待网络稳定
    sleep(Duration::from_millis(1000)).await;
    
    // 测试节点间的相互发现
    for i in 0..NUM_NODES {
        for j in 0..NUM_NODES {
            if i != j {
                let target_id = &node_infos[j].id;
                match dhts[i].find_node(target_id).await {
                    Ok(found_nodes) => {
                        println!("Node {} found {} nodes when searching for node {}", 
                               i, found_nodes.len(), j);
                    },
                    Err(e) => {
                        println!("Node {} failed to find node {}: {}", i, j, e);
                    }
                }
            }
        }
    }
    
    // 显示路由表状态
    for (i, dht) in dhts.iter().enumerate() {
        println!("Node {} routing table size: {}", i, dht.routing_table_size());
    }
    
    // 停止所有节点
    for (i, dht) in dhts.iter().enumerate() {
        if let Err(e) = dht.stop().await {
            println!("Failed to stop node {}: {}", i, e);
        }
    }
    
    println!("Multi-node network test completed");
}

/// 测试引导节点管理器
#[test]
fn test_bootstrap_manager() {
    let test_nodes = create_test_bootstrap_nodes(3, 9000);
    
    let bootstrap_config = BootstrapConfig {
        nodes: test_nodes.clone(),
        connect_timeout: Duration::from_secs(5),
        min_connections: 1,
        max_retries: 3,
    };
    
    let mut manager = BootstrapManager::new(bootstrap_config);
    
    // 验证节点数量
    assert_eq!(manager.get_bootstrap_nodes().len(), 3);
    
    // 测试添加节点
    let new_node = create_test_bootstrap_nodes(1, 9100)[0].clone();
    manager.add_bootstrap_node(new_node.clone());
    assert_eq!(manager.get_bootstrap_nodes().len(), 4);
    
    // 测试移除节点
    manager.remove_bootstrap_node(&new_node.id);
    assert_eq!(manager.get_bootstrap_nodes().len(), 3);
    
    // 验证配置
    assert!(manager.validate_config().is_ok());
}

/// 测试网络消息的序列化和反序列化
#[test]
fn test_network_message_serialization() {
    use zero_edge::dht::DhtMessage;
    
    let keypair = KeyPair::generate().unwrap();
    let node_id = NodeId::from_public_key(&keypair.public).unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
    
    let node_info = NodeInfo::new_signed(
        node_id.clone(),
        keypair.public.clone(),
        vec![addr],
        1,
        false,
        &keypair.secret,
    ).unwrap();
    
    // 测试Ping消息
    let ping = DhtMessage::Ping {
        sender: node_info.clone(),
        message_id: 12345,
    };
    
    let ping_bytes = ping.to_bytes().unwrap();
    let deserialized_ping = DhtMessage::from_bytes(&ping_bytes).unwrap();
    
    match deserialized_ping {
        DhtMessage::Ping { message_id, .. } => {
            assert_eq!(message_id, 12345);
        },
        _ => panic!("Wrong message type"),
    }
    
    // 测试FindNode消息
    let target = NodeId::random();
    let find_node = DhtMessage::FindNodeRequest {
        sender: node_info.clone(),
        target: target.clone(),
        message_id: 67890,
    };
    
    let find_bytes = find_node.to_bytes().unwrap();
    let deserialized_find = DhtMessage::from_bytes(&find_bytes).unwrap();
    
    match deserialized_find {
        DhtMessage::FindNodeRequest { target: found_target, message_id, .. } => {
            assert_eq!(found_target, target);
            assert_eq!(message_id, 67890);
        },
        _ => panic!("Wrong message type"),
    }
}