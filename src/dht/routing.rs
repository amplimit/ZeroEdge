use crate::dht::kademlia::{NodeId, NodeInfo, KademliaError};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

const BUCKET_SIZE: usize = 20; // k值，每个k-bucket中存放的最大节点数
const BUCKET_COUNT: usize = 256; // 桶的数量，对应NodeId的比特数

/// 路由表实现，基于Kademlia的k-bucket结构
pub struct RoutingTable {
    /// 本地节点ID
    local_id: NodeId,
    
    /// k-buckets，每个bucket存储距离在特定范围内的节点
    buckets: Vec<VecDeque<NodeInfo>>,
    
    /// 节点信息的哈希表，用于快速查找
    nodes: HashMap<NodeId, NodeInfo>,
    
    /// 上次刷新每个bucket的时间
    last_refresh: Vec<SystemTime>,
    
    /// 节点记录的生存时间
    node_ttl: Duration,
}

impl RoutingTable {
    /// 创建新的路由表
    pub fn new(local_id: NodeId, node_ttl: Duration) -> Self {
        let mut buckets = Vec::with_capacity(BUCKET_COUNT);
        let mut last_refresh = Vec::with_capacity(BUCKET_COUNT);
        
        for _ in 0..BUCKET_COUNT {
            buckets.push(VecDeque::with_capacity(BUCKET_SIZE));
            last_refresh.push(SystemTime::now());
        }
        
        Self {
            local_id,
            buckets,
            nodes: HashMap::new(),
            last_refresh,
            node_ttl,
        }
    }
    
    /// 计算应该放入哪个bucket
    fn bucket_index(&self, id: &NodeId) -> usize {
        let distance = self.local_id.distance(id);
        
        // 找到第一个非零字节
        for (i, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                // 找到这个字节中最高的非零位
                for j in (0..8).rev() {
                    if (byte & (1 << j)) != 0 {
                        return i * 8 + (7 - j);
                    }
                }
            }
        }
        
        // 如果所有字节都是0，这是本地节点自己
        255
    }
    
    /// 添加或更新节点
    pub fn update_node(&mut self, node: NodeInfo) -> Result<(), KademliaError> {
        // 验证节点信息签名
        node.verify()?;
        
        // 不添加本地节点
        if node.id == self.local_id {
            return Ok(());
        }
        
        let bucket_idx = self.bucket_index(&node.id);
        let bucket = &mut self.buckets[bucket_idx];
        
        // 检查节点是否已存在
        if let Some(pos) = bucket.iter().position(|n| n.id == node.id) {
            // 节点已存在，移到队列末尾（最近看到的）
            let existing = bucket.remove(pos).unwrap();
            
            // 如果新节点信息更新，则使用新信息
            if node.last_updated > existing.last_updated {
                bucket.push_back(node.clone());
                self.nodes.insert(node.id.clone(), node.clone());
            } else {
                bucket.push_back(existing);
            }
        } else {
            // 节点不存在
            if bucket.len() < BUCKET_SIZE {
                // Bucket未满，直接添加
                bucket.push_back(node.clone());
                self.nodes.insert(node.id.clone(), node.clone());
            } else {
                // Bucket已满，检查最久未见的节点是否仍活跃
                // 先clone oldest，避免借用冲突
                let oldest_id = bucket.front().map(|node| node.id.clone()).unwrap();
                let is_expired = bucket.front().map(|node| node.is_expired(self.node_ttl)).unwrap_or(false);
                
                if is_expired {
                    // 最久未见的节点已过期，移除它
                    bucket.pop_front();
                    self.nodes.remove(&oldest_id);
                    
                    // 添加新节点
                    bucket.push_back(node.clone());
                    self.nodes.insert(node.id.clone(), node.clone());
                }
                // 如果最旧的节点仍然活跃，暂时忽略新节点
                // 真实实现中，这里可能会ping最旧的节点来确认活跃状态
            }
        }
        
        Ok(())
    }
    
    /// 获取特定节点信息
    pub fn get_node(&self, id: &NodeId) -> Option<&NodeInfo> {
        self.nodes.get(id)
    }
    
    /// 获取离目标节点最近的k个节点
    pub fn get_closest(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        // 创建一个保存所有节点的向量，包括目标节点的距离
        let mut nodes_with_distance: Vec<(NodeInfo, [u8; 32])> = self.nodes.values()
            .map(|node| (node.clone(), node.id.distance(target)))
            .collect();
        
        // 按照到目标节点的距离排序
        nodes_with_distance.sort_by(|a, b| a.1.cmp(&b.1));
        
        // 返回最近的count个节点
        nodes_with_distance.into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }
    
    /// 返回需要刷新的bucket索引
    pub fn buckets_needing_refresh(&self, refresh_interval: Duration) -> Vec<usize> {
        let now = SystemTime::now();
        let mut result = Vec::new();
        
        for (i, last) in self.last_refresh.iter().enumerate() {
            if now.duration_since(*last).unwrap_or_default() > refresh_interval {
                result.push(i);
            }
        }
        
        result
    }
    
    /// 标记bucket已刷新
    pub fn mark_bucket_refreshed(&mut self, bucket_idx: usize) {
        if bucket_idx < self.last_refresh.len() {
            self.last_refresh[bucket_idx] = SystemTime::now();
        }
    }
    
    /// 清理过期节点
    pub fn remove_expired(&mut self) -> usize {
        let mut removed = 0;
        
        for bucket in &mut self.buckets {
            let before_len = bucket.len();
            bucket.retain(|node| !node.is_expired(self.node_ttl));
            removed += before_len - bucket.len();
        }
        
        // 更新哈希表
        self.nodes.retain(|_, node| !node.is_expired(self.node_ttl));
        
        removed
    }
    
    /// 获取路由表中的节点总数
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    
    /// 检查路由表是否为空
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    
    /// 获取指定bucket中的所有节点
    pub fn get_bucket_nodes(&self, bucket_idx: usize) -> Vec<NodeInfo> {
        if bucket_idx < self.buckets.len() {
            self.buckets[bucket_idx].iter().cloned().collect()
        } else {
            Vec::new()
        }
    }
    
    /// 获取路由表中的所有节点
    pub fn get_all_nodes(&self) -> impl Iterator<Item = (NodeId, NodeInfo)> + '_ {
        self.nodes.iter().map(|(id, node)| (id.clone(), node.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair; // 移除未使用的PublicKey导入
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    // 创建测试节点信息
    fn create_test_node(id_bytes: [u8; 32]) -> NodeInfo {
        let id = NodeId(id_bytes);
        let keypair = KeyPair::generate().unwrap();
        
        let mut node = NodeInfo::new(
            id,
            keypair.public.clone(),
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000)],
            1,
            false
        );
        
        // 签名节点信息
        node.sign(&keypair.secret).unwrap();
        
        node
    }
    
    #[test]
    fn test_bucket_index() {
        let local_id = NodeId([0; 32]);
        let table = RoutingTable::new(local_id, Duration::from_secs(3600));
        
        // 测试不同距离的节点
        let test_cases = [
            ([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
            ([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 6),
            ([128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0),
            ([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 15),
        ];
        
        for (id_bytes, expected_index) in test_cases {
            let id = NodeId(id_bytes);
            assert_eq!(table.bucket_index(&id), expected_index);
        }
    }
    
    #[test]
    fn test_update_and_get_node() {
        let local_id = NodeId([0; 32]);
        let mut table = RoutingTable::new(local_id, Duration::from_secs(3600));
        
        // 创建测试节点
        let mut test_id = [0; 32];
        test_id[0] = 1;
        let node = create_test_node(test_id);
        
        // 添加节点
        table.update_node(node.clone()).unwrap();
        
        // 查找节点
        let retrieved = table.get_node(&node.id).unwrap();
        assert_eq!(retrieved.id, node.id);
    }
    
    #[test]
    fn test_get_closest() {
        let local_id = NodeId([0; 32]);
        let mut table = RoutingTable::new(local_id, Duration::from_secs(3600));
        
        // 创建多个测试节点
        for i in 1..10 {
            let mut test_id = [0; 32];
            test_id[0] = i;
            let node = create_test_node(test_id);
            table.update_node(node).unwrap();
        }
        
        // 创建目标节点ID
        let mut target_id = [0; 32];
        target_id[0] = 2;
        let target = NodeId(target_id);
        
        // 获取最近的3个节点
        let closest = table.get_closest(&target, 3);
        
        // 验证第一个是ID[2]，最近的节点
        assert_eq!(closest[0].id.0[0], 2);
        
        // 应该有3个结果
        assert_eq!(closest.len(), 3);
    }
}
