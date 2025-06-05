use zero_edge::{
    dht::{NodeId, NodeInfo, PublicDht, PublicDhtConfig},
    crypto::KeyPair,
};
use std::time::Duration;

/// 基本的DHT创建和启动测试
#[tokio::test]
async fn test_dht_basic_creation() {
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
    
    // 测试DHT启动
    let start_result = dht.start().await;
    assert!(start_result.is_ok(), "DHT should start successfully");
    
    // 测试DHT停止
    let stop_result = dht.stop().await;
    assert!(stop_result.is_ok(), "DHT should stop successfully");
}

/// 测试节点ID生成和验证
#[test]
fn test_node_id_operations() {
    // 测试从公钥生成NodeId
    let keypair = KeyPair::generate().unwrap();
    let node_id = NodeId::from_public_key(&keypair.public).unwrap();
    
    // 测试NodeId转换为字符串
    let id_string = node_id.to_string();
    assert_eq!(id_string.len(), 64); // 32字节 = 64个十六进制字符
    
    // 测试NodeId距离计算
    let other_id = NodeId::random();
    let distance = node_id.distance(&other_id);
    assert_eq!(distance.len(), 32); // 距离应该是32字节
    
    // 自己到自己的距离应该是0
    let self_distance = node_id.distance(&node_id);
    assert!(self_distance.iter().all(|&b| b == 0));
}

/// 测试基本的NodeInfo创建和验证
#[test]
fn test_node_info_creation() {
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    
    let keypair = KeyPair::generate().unwrap();
    let node_id = NodeId::from_public_key(&keypair.public).unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
    
    // 测试创建已签名的NodeInfo
    let node_info = NodeInfo::new_signed(
        node_id.clone(),
        keypair.public.clone(),
        vec![addr],
        1,
        false,
        &keypair.secret,
    );
    
    assert!(node_info.is_ok(), "NodeInfo creation should succeed");
    
    let node_info = node_info.unwrap();
    
    // 验证NodeInfo
    let verify_result = node_info.verify();
    assert!(verify_result.is_ok(), "NodeInfo verification should succeed");
    
    // 检查基本属性
    assert_eq!(node_info.id, node_id);
    assert_eq!(node_info.addresses[0], addr);
    assert_eq!(node_info.protocol_version, 1);
    assert!(!node_info.is_relay);
}