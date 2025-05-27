use crate::dht::{KademliaError, NodeId, NodeInfo, RoutingTable};
use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use log::{debug, info, warn, error};
// 移除未使用的导入
// use thiserror::Error;

/// 公共DHT的配置
#[derive(Clone, Debug)]
pub struct PublicDhtConfig {
    /// 本地节点ID
    pub local_id: NodeId,
    
    /// 本地公钥
    pub local_public_key: PublicKey,
    
    /// 每个bucket的大小 (k值)
    pub k_value: usize,
    
    /// 并行查询的节点数 (alpha值)
    pub alpha_value: usize,
    
    /// 记录的生存时间
    pub record_ttl: Duration,
    
    /// 节点记录的生存时间
    pub node_ttl: Duration,
    
    /// 刷新间隔
    pub refresh_interval: Duration,
    
    /// 再发布间隔
    pub republish_interval: Duration,
    
    /// 复制因子 (存储多少份)
    pub replication_factor: usize,
}

impl Default for PublicDhtConfig {
    fn default() -> Self {
        Self {
            local_id: NodeId([0; 32]), // 默认需要替换
            local_public_key: PublicKey::default(), // 默认需要替换
            k_value: 20,
            alpha_value: 3,
            record_ttl: Duration::from_secs(86400), // 24小时
            node_ttl: Duration::from_secs(7200),    // 2小时
            refresh_interval: Duration::from_secs(3600), // 1小时
            republish_interval: Duration::from_secs(21600), // 6小时
            replication_factor: 5,
        }
    }
}

/// DHT中存储的值
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtValue {
    /// 键
    pub key: Vec<u8>,
    
    /// 值
    pub value: Vec<u8>,
    
    /// 发布者的ID
    pub publisher: NodeId,
    
    /// 发布者的公钥
    pub publisher_key: PublicKey,
    
    /// 发布时间
    pub publish_time: SystemTime,
    
    /// 过期时间
    pub expires_at: SystemTime,
    
    /// 发布者的签名
    pub signature: Vec<u8>,
}

impl DhtValue {
    /// 创建新的DHT值
    pub fn new(
        key: Vec<u8>,
        value: Vec<u8>,
        publisher: NodeId,
        publisher_key: PublicKey,
        ttl: Duration,
    ) -> Self {
        let now = SystemTime::now();
        let expires_at = now + ttl;
        
        Self {
            key,
            value,
            publisher,
            publisher_key,
            publish_time: now,
            expires_at,
            signature: Vec::new(), // 需要调用sign方法
        }
    }
    
    /// 签名DHT值
    pub fn sign(&mut self, secret_key: &crate::crypto::SecretKey) -> Result<(), KademliaError> {
        // 创建副本，没有签名
        let mut value_copy = self.clone();
        value_copy.signature = Vec::new();
        
        // 序列化
        let bytes = bincode::serialize(&value_copy)
            .map_err(|e| KademliaError::OperationFailed(e.to_string()))?;
        
        // 签名
        self.signature = crate::crypto::sign(secret_key, &bytes)
            .map_err(|e| KademliaError::OperationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// 验证DHT值的签名
    pub fn verify(&self) -> Result<(), KademliaError> {
        // 创建副本，没有签名
        let mut value_copy = self.clone();
        value_copy.signature = Vec::new();
        
        // 序列化
        let bytes = bincode::serialize(&value_copy)
            .map_err(|e| KademliaError::OperationFailed(e.to_string()))?;
        
        // 验证签名
        crate::crypto::verify(&self.publisher_key, &bytes, &self.signature)
            .map_err(|e| KademliaError::OperationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// 检查DHT值是否过期
    pub fn is_expired(&self) -> bool {
        match SystemTime::now().duration_since(self.expires_at) {
            Ok(_) => true,  // 当前时间已经超过过期时间
            Err(_) => false, // 当前时间尚未到达过期时间
        }
    }
}

/// DHT操作类型
#[derive(Debug, Clone)]
enum DhtOperation {
    /// 查找节点
    FindNode { 
        target: NodeId, 
        result_tx: mpsc::Sender<Vec<NodeInfo>>,
    },
    /// 查找值
    FindValue { 
        key: Vec<u8>, 
        result_tx: mpsc::Sender<Option<DhtValue>>,
    },
    /// 存储值
    Store { 
        value: DhtValue, 
        result_tx: mpsc::Sender<Result<(), KademliaError>>,
    },
    /// 刷新路由表
    RefreshTable,
    /// 重新发布值
    RepublishValues,
}

/// 公共DHT的实现
pub struct PublicDht {
    /// 配置
    config: PublicDhtConfig,
    
    /// 路由表
    routing_table: Arc<RwLock<RoutingTable>>,
    
    /// 本地存储的值
    values: Arc<RwLock<HashMap<Vec<u8>, DhtValue>>>,
    
    /// 操作通道
    op_tx: mpsc::Sender<DhtOperation>,
    
    /// 运行中标志
    running: Arc<RwLock<bool>>,
}

impl PublicDht {
    /// 创建新的公共DHT
    pub fn new(config: PublicDhtConfig) -> Self {
        // 创建路由表
        let routing_table = Arc::new(RwLock::new(
            RoutingTable::new(config.local_id.clone(), config.node_ttl)
        ));
        
        // 创建值存储
        let values = Arc::new(RwLock::new(HashMap::new()));
        
        // 创建操作通道
        let (op_tx, op_rx) = mpsc::channel(100);
        
        // 标记为未运行
        let running = Arc::new(RwLock::new(false));
        
        // 创建DHT
        let dht = Self {
            config,
            routing_table,
            values,
            op_tx,
            running,
        };
        
        // 启动后台任务
        dht.spawn_background_task(op_rx);
        
        dht
    }
    
    /// 启动DHT
    pub async fn start(&self) -> Result<(), KademliaError> {
        // 标记为运行中
        {
            let mut running = self.running.write().unwrap();
            *running = true;
        }
        
        info!("Public DHT started");
        
        Ok(())
    }
    
    /// 停止DHT
    pub async fn stop(&self) -> Result<(), KademliaError> {
        // 标记为不再运行
        {
            let mut running = self.running.write().unwrap();
            *running = false;
        }
        
        info!("Public DHT stopped");
        
        Ok(())
    }
    
    /// 启动后台任务
    fn spawn_background_task(&self, mut op_rx: mpsc::Receiver<DhtOperation>) {
        let routing_table = self.routing_table.clone();
        let values = self.values.clone();
        let running = self.running.clone();
        let config = self.config.clone();
        
        // 创建一个新的channel以便后台任务可以向自己发送操作
        let (op_tx, mut task_op_rx) = mpsc::channel::<DhtOperation>(100);
        
        tokio::spawn(async move {
            info!("DHT background task started");
            
            // 创建刷新计时器
            let mut refresh_interval = tokio::time::interval(config.refresh_interval);
            let mut republish_interval = tokio::time::interval(config.republish_interval);
            
            loop {
                tokio::select! {
                    // 处理操作
                    Some(op) = op_rx.recv() => {
                        if !*running.read().unwrap() {
                            continue;
                        }
                        
                        match op {
                            DhtOperation::FindNode { target, result_tx } => {
                                // 查找节点逻辑 - 只返回精确匹配的节点
                                let result = {
                                    let table = routing_table.read().unwrap();
                                    
                                    // 检查是否有精确匹配
                                    if let Some(node) = table.get_node(&target) {
                                        // 找到精确匹配，返回该节点
                                        debug!("Found exact match for node ID: {}", target);
                                        vec![node.clone()]
                                    } else {
                                        // 没有精确匹配，返回空列表
                                        debug!("No exact match found for node ID: {}", target);
                                        Vec::new()
                                    }
                                };
                                
                                // 返回精确匹配的节点或空列表
                                let _ = result_tx.send(result).await;
                            },
                            DhtOperation::FindValue { key, result_tx } => {
                                // 查找值逻辑
                                let value = {
                                    let values_map = values.read().unwrap();
                                    values_map.get(&key).cloned()
                                };
                                
                                // 暂时只查找本地存储
                                let _ = result_tx.send(value).await;
                            },
                            DhtOperation::Store { value, result_tx } => {
                                // 存储值逻辑
                                let result = {
                                    // 验证值
                                    match value.verify() {
                                        Ok(_) => {
                                            // 存储到本地
                                            let mut values_map = values.write().unwrap();
                                            values_map.insert(value.key.clone(), value);
                                            Ok(())
                                        },
                                        Err(e) => Err(e),
                                    }
                                };
                                
                                // 返回结果
                                let _ = result_tx.send(result).await;
                            },
                            DhtOperation::RefreshTable => {
                                // 刷新路由表
                                let buckets_to_refresh = {
                                    let table = routing_table.read().unwrap();
                                    table.buckets_needing_refresh(config.refresh_interval)
                                };
                                
                                // 在实际实现中，这里会为每个需要刷新的bucket启动查找过程
                                if !buckets_to_refresh.is_empty() {
                                    debug!("Refreshing {} buckets", buckets_to_refresh.len());
                                }
                            },
                            DhtOperation::RepublishValues => {
                                // 重新发布值
                                let values_to_republish = {
                                    let values_map = values.read().unwrap();
                                    values_map.values().cloned().collect::<Vec<_>>()
                                };
                                
                                // 在实际实现中，这里会重新发布所有需要重新发布的值
                                if !values_to_republish.is_empty() {
                                    debug!("Republishing {} values", values_to_republish.len());
                                }
                            }
                        }
                    },
                    // 处理内部任务自己发送的操作
                    Some(op) = task_op_rx.recv() => {
                        if !*running.read().unwrap() {
                            continue;
                        }
                        
                        match op {
                            // 处理内部操作...
                            _ => {}
                        }
                    },
                    // 刷新计时器触发
                    _ = refresh_interval.tick() => {
                        if !*running.read().unwrap() {
                            continue;
                        }
                        
                        // 发送刷新表操作
                        let _ = op_tx.send(DhtOperation::RefreshTable).await;
                    },
                    // 重新发布计时器触发
                    _ = republish_interval.tick() => {
                        if !*running.read().unwrap() {
                            continue;
                        }
                        
                        // 发送重新发布操作
                        let _ = op_tx.send(DhtOperation::RepublishValues).await;
                    },
                    // 清理过期值和节点
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        if !*running.read().unwrap() {
                            continue;
                        }
                        
                        // 清理过期值
                        {
                            let mut values_map = values.write().unwrap();
                            values_map.retain(|_, v| !v.is_expired());
                        }
                        
                        // 清理过期节点
                        {
                            let mut table = routing_table.write().unwrap();
                            let removed = table.remove_expired();
                            if removed > 0 {
                                debug!("Removed {} expired nodes from routing table", removed);
                            }
                        }
                    }
                }
            }
        });
    }
    
    /// 查找节点
    /// 
    /// 根据给定的节点ID查找节点。如果找到精确匹配的节点，返回该节点。
    /// 如果没有找到精确匹配，返回空列表。
    pub async fn find_node(&self, target: &NodeId) -> Result<Vec<NodeInfo>, KademliaError> {
        // 注意: 不要让读锁跨越 await 点，所以需要在异步操作前完全获取数据并释放锁
        
        // 首先从路由表中查找精确匹配，并获取路由表信息用于日志记录
        let exact_match_node: Option<NodeInfo>;
        let table_size: usize;
        let nodes_preview: Vec<String>;
        
        {
            // 使用封闭的作用域来确保锁不会跨越 await 点
            let routing_table = self.routing_table.read().unwrap();
            table_size = routing_table.len();
            
            // 日志显示前5个节点预览
            nodes_preview = routing_table.get_all_nodes()
                .take(5)
                .map(|(id, _)| format!("{}...", &id.to_string()[..8]))
                .collect();
                
            // 检查精确匹配
            exact_match_node = routing_table.get_node(target).cloned();
        } // 路由表锁在这里释放
        
        info!("Finding node: {}, current routing table size: {}", target, table_size);
        
        if !nodes_preview.is_empty() {
            info!("Routing table preview: {}", nodes_preview.join(", "));
        }
        
        // 如果找到精确匹配，直接返回
        if let Some(node) = exact_match_node {
            info!("Found exact match for node ID: {} in local routing table", target);
            return Ok(vec![node]);
        }
        
        // 如果在本地路由表中没有找到，创建操作并发送
        let (tx, mut rx) = mpsc::channel(1);
        
        // 创建并发送查找节点操作
        let op = DhtOperation::FindNode {
            target: target.clone(),
            result_tx: tx,
        };
        
        debug!("Sending FindNode operation for node ID: {}", target);
        
        // 发送操作
        if let Err(e) = self.op_tx.send(op).await {
            error!("Failed to send FindNode operation: {}", e);
            return Err(KademliaError::OperationFailed(format!("Failed to send FindNode operation: {}", e)));
        }
        
        // 等待结果
        match rx.recv().await {
            Some(nodes) => {
                let count = nodes.len();
                if count > 0 {
                    info!("FindNode operation found {} node(s) for ID: {}", count, target);
                } else {
                    info!("FindNode operation found no nodes for ID: {}", target);
                }
                Ok(nodes)
            },
            None => {
                let error_msg = format!("Find node operation failed: no response received");
                error!("{}", error_msg);
                Err(KademliaError::OperationFailed(error_msg))
            }
        }
    }
    
    /// 查找最接近目标ID的节点（标准Kademlia查找）
    /// 
    /// 这个方法实现标准的Kademlia DHT查找逻辑，返回最接近目标ID的k个节点。
    /// 即使没有精确匹配，也会返回最接近的节点。
    pub async fn find_closest_nodes(&self, target: &NodeId, count: Option<usize>) -> Result<Vec<NodeInfo>, KademliaError> {
        let k_value = count.unwrap_or(self.config.k_value);
        
        // 直接从路由表中获取最接近的节点
        let closest_nodes = {
            let table = self.routing_table.read().unwrap();
            table.get_closest(target, k_value)
        };
        
        debug!("Found {} closest nodes for target ID: {}", closest_nodes.len(), target);
        Ok(closest_nodes)
    }
    
    /// 手动添加节点到路由表 (同步版本)
    /// 
    /// 主要用于测试和引导节点初始化
    pub fn add_node_sync(&self, node: NodeInfo) -> Result<(), KademliaError> {
        // 验证节点信息
        match node.verify() {
            Ok(_) => {
                // 先记录节点ID以便于日志输出
                let node_id = node.id.clone();
                
                // 添加到路由表
                let mut table = self.routing_table.write().unwrap();
                table.add_node(node);
                debug!("Added node: {} to routing table", node_id);
                Ok(())
            },
            Err(e) => Err(KademliaError::InvalidNodeInfo(e.to_string())),
        }
    }
    
    /// 查找值
    pub async fn find_value(&self, key: &[u8]) -> Result<Option<DhtValue>, KademliaError> {
        let (tx, mut rx) = mpsc::channel(1);
        
        // 发送查找值操作
        self.op_tx.send(DhtOperation::FindValue {
            key: key.to_vec(),
            result_tx: tx,
        }).await.map_err(|e| KademliaError::OperationFailed(e.to_string()))?;
        
        // 等待结果
        rx.recv().await.ok_or_else(|| KademliaError::OperationFailed("Find value operation failed".to_string()))
    }
    
    /// 存储值
    pub async fn store(&self, value: DhtValue) -> Result<(), KademliaError> {
        let (tx, mut rx) = mpsc::channel(1);
        
        // 发送存储操作
        self.op_tx.send(DhtOperation::Store {
            value,
            result_tx: tx,
        }).await.map_err(|e| KademliaError::OperationFailed(e.to_string()))?;
        
        // 等待结果
        rx.recv().await.ok_or_else(|| KademliaError::OperationFailed("Store operation failed".to_string()))?
    }
    
    /// 添加节点到路由表
    pub async fn add_node(&self, node: NodeInfo) -> Result<(), KademliaError> {
        let mut table = self.routing_table.write().unwrap();
        table.update_node(node)
    }
    
    /// 引导DHT
    pub async fn bootstrap(&self, bootstrap_nodes: &[NodeInfo]) -> Result<(), KademliaError> {
        info!("Bootstrapping DHT with {} nodes", bootstrap_nodes.len());
        
        // 添加引导节点到路由表
        for node in bootstrap_nodes {
            let mut table = self.routing_table.write().unwrap();
            if let Err(e) = table.update_node(node.clone()) {
                warn!("Failed to add bootstrap node: {}", e);
            }
        }
        
        // 查找自己的ID，以填充路由表
        self.find_node(&self.config.local_id).await?;
        
        info!("DHT bootstrap complete");
        
        Ok(())
    }

    /// 返回路由表中节点的数量
    pub fn routing_table_size(&self) -> usize {
        let table = self.routing_table.read().unwrap();
        table.len()
    }

    /// 返回路由表中的所有节点
    pub fn list_routing_table(&self) -> Vec<(NodeId, NodeInfo)> {
        let table = self.routing_table.read().unwrap();
        table.get_all_nodes().collect()
    }
}

// 为PublicKey实现Default，用于PublicDhtConfig的默认实现
impl Default for PublicKey {
    fn default() -> Self {
        // 在实际应用中，这不应该被使用
        // 这里只是为了让编译通过
        unimplemented!("PublicKey default implementation should not be used");
    }
}
