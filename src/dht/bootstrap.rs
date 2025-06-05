use crate::dht::{NodeId, NodeInfo};
use crate::crypto::KeyPair;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::time::Duration;

/// 引导节点配置
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// 引导节点列表
    pub nodes: Vec<NodeInfo>,
    
    /// 引导连接超时时间
    pub connect_timeout: Duration,
    
    /// 最小成功连接的引导节点数
    pub min_connections: usize,
    
    /// 最大重试次数
    pub max_retries: u32,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            nodes: get_default_bootstrap_nodes(),
            connect_timeout: Duration::from_secs(10),
            min_connections: 1,
            max_retries: 3,
        }
    }
}

/// 获取默认的引导节点列表
/// 
/// 在生产环境中，这些应该是已知的稳定节点
/// 目前使用本地测试节点
pub fn get_default_bootstrap_nodes() -> Vec<NodeInfo> {
    // 在实际应用中，这里应该包含一些已知的稳定引导节点
    // 现在我们返回空列表，让用户自己配置
    Vec::new()
}

/// 创建测试引导节点
/// 
/// 这个函数用于测试和开发环境
pub fn create_test_bootstrap_nodes(count: usize, start_port: u16) -> Vec<NodeInfo> {
    let mut nodes = Vec::new();
    
    for i in 0..count {
        // 生成随机密钥对
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        let node_id = NodeId::from_public_key(&keypair.public)
            .expect("Failed to create node ID");
        
        // 创建测试地址
        let port = start_port + i as u16;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        
        // 创建节点信息
        match NodeInfo::new_signed(
            node_id,
            keypair.public,
            vec![addr],
            1, // protocol version
            false, // is_relay
            &keypair.secret,
        ) {
            Ok(node_info) => nodes.push(node_info),
            Err(e) => {
                log::warn!("Failed to create test bootstrap node {}: {}", i, e);
            }
        }
    }
    
    nodes
}

/// 引导节点管理器
pub struct BootstrapManager {
    config: BootstrapConfig,
}

impl BootstrapManager {
    /// 创建新的引导节点管理器
    pub fn new(config: BootstrapConfig) -> Self {
        Self { config }
    }
    
    /// 获取引导节点列表
    pub fn get_bootstrap_nodes(&self) -> &[NodeInfo] {
        &self.config.nodes
    }
    
    /// 添加引导节点
    pub fn add_bootstrap_node(&mut self, node: NodeInfo) {
        self.config.nodes.push(node);
    }
    
    /// 移除引导节点
    pub fn remove_bootstrap_node(&mut self, node_id: &NodeId) {
        self.config.nodes.retain(|node| node.id != *node_id);
    }
    
    /// 验证引导节点配置
    pub fn validate_config(&self) -> Result<(), String> {
        if self.config.nodes.is_empty() {
            return Err("No bootstrap nodes configured".to_string());
        }
        
        for (i, node) in self.config.nodes.iter().enumerate() {
            if node.addresses.is_empty() {
                return Err(format!("Bootstrap node {} has no addresses", i));
            }
            
            // 验证节点信息签名
            if let Err(e) = node.verify() {
                return Err(format!("Bootstrap node {} has invalid signature: {}", i, e));
            }
        }
        
        Ok(())
    }
    
    /// 获取配置
    pub fn config(&self) -> &BootstrapConfig {
        &self.config
    }
}

/// 引导节点发现策略
#[derive(Debug, Clone)]
pub enum BootstrapStrategy {
    /// 使用配置文件中的静态节点列表
    Static(Vec<NodeInfo>),
    
    /// 使用DNS种子节点发现
    DnsSeeds(Vec<String>),
    
    /// 使用已知的种子服务器
    SeedServers(Vec<SocketAddr>),
    
    /// 组合多种策略
    Combined(Vec<BootstrapStrategy>),
}

impl BootstrapStrategy {
    /// 解析引导策略，获取节点列表
    pub fn resolve(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<NodeInfo>, Box<dyn std::error::Error>>> + '_>> {
        Box::pin(async move {
            match self {
                BootstrapStrategy::Static(nodes) => Ok(nodes.clone()),
                
                BootstrapStrategy::DnsSeeds(_seeds) => {
                    // DNS种子节点发现的实现
                    // 这里应该查询DNS TXT记录获取节点列表
                    log::warn!("DNS seed discovery not implemented yet");
                    Ok(Vec::new())
                },
                
                BootstrapStrategy::SeedServers(_servers) => {
                    // 种子服务器发现的实现
                    // 这里应该连接到种子服务器获取节点列表
                    log::warn!("Seed server discovery not implemented yet");
                    Ok(Vec::new())
                },
                
                BootstrapStrategy::Combined(strategies) => {
                    let mut all_nodes = Vec::new();
                    
                    for strategy in strategies {
                        match strategy.resolve().await {
                            Ok(mut nodes) => all_nodes.append(&mut nodes),
                            Err(e) => log::warn!("Failed to resolve bootstrap strategy: {}", e),
                        }
                    }
                    
                    // 去重
                    all_nodes.sort_by(|a, b| a.id.cmp(&b.id));
                    all_nodes.dedup_by(|a, b| a.id == b.id);
                    
                    Ok(all_nodes)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_config_default() {
        let config = BootstrapConfig::default();
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_create_test_bootstrap_nodes() {
        let nodes = create_test_bootstrap_nodes(3, 8000);
        assert_eq!(nodes.len(), 3);
        
        // 验证端口递增
        assert_eq!(nodes[0].addresses[0].port(), 8000);
        assert_eq!(nodes[1].addresses[0].port(), 8001);
        assert_eq!(nodes[2].addresses[0].port(), 8002);
        
        // 验证节点ID唯一
        assert_ne!(nodes[0].id, nodes[1].id);
        assert_ne!(nodes[1].id, nodes[2].id);
        assert_ne!(nodes[0].id, nodes[2].id);
    }

    #[test]
    fn test_bootstrap_manager() {
        let config = BootstrapConfig::default();
        let mut manager = BootstrapManager::new(config);
        
        // 添加测试节点
        let test_nodes = create_test_bootstrap_nodes(2, 9000);
        manager.add_bootstrap_node(test_nodes[0].clone());
        manager.add_bootstrap_node(test_nodes[1].clone());
        
        assert_eq!(manager.get_bootstrap_nodes().len(), 2);
        
        // 移除节点
        manager.remove_bootstrap_node(&test_nodes[0].id);
        assert_eq!(manager.get_bootstrap_nodes().len(), 1);
        assert_eq!(manager.get_bootstrap_nodes()[0].id, test_nodes[1].id);
    }

    #[tokio::test]
    async fn test_bootstrap_strategy_static() {
        let test_nodes = create_test_bootstrap_nodes(2, 9100);
        let strategy = BootstrapStrategy::Static(test_nodes.clone());
        
        let resolved = strategy.resolve().await.unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].id, test_nodes[0].id);
        assert_eq!(resolved[1].id, test_nodes[1].id);
    }

    #[tokio::test]
    async fn test_bootstrap_strategy_combined() {
        let test_nodes1 = create_test_bootstrap_nodes(2, 9200);
        let test_nodes2 = create_test_bootstrap_nodes(2, 9300);
        
        let strategy = BootstrapStrategy::Combined(vec![
            BootstrapStrategy::Static(test_nodes1),
            BootstrapStrategy::Static(test_nodes2),
        ]);
        
        let resolved = strategy.resolve().await.unwrap();
        assert_eq!(resolved.len(), 4);
    }
}