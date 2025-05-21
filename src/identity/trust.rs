use crate::identity::UserId;
use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustError {
    #[error("Trust operation failed: {0}")]
    OperationFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid trust level: {0}")]
    InvalidTrustLevel(String),
}

/// 信任级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// 未知，不信任
    Unknown = 0,
    
    /// 间接信任，通过信任链
    Indirect = 1,
    
    /// 手动添加但未验证
    Unverified = 2,
    
    /// 已验证
    Verified = 3,
    
    /// 完全信任
    FullyTrusted = 4,
}

impl TrustLevel {
    /// 检查是否达到最低信任级别
    pub fn meets_minimum(&self, minimum: TrustLevel) -> bool {
        *self as u8 >= minimum as u8
    }
    
    /// 从原始值创建信任级别
    pub fn from_u8(value: u8) -> Result<Self, TrustError> {
        match value {
            0 => Ok(TrustLevel::Unknown),
            1 => Ok(TrustLevel::Indirect),
            2 => Ok(TrustLevel::Unverified),
            3 => Ok(TrustLevel::Verified),
            4 => Ok(TrustLevel::FullyTrusted),
            _ => Err(TrustError::InvalidTrustLevel(format!("Invalid trust level: {}", value))),
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Unknown => write!(f, "Unknown"),
            TrustLevel::Indirect => write!(f, "Indirect"),
            TrustLevel::Unverified => write!(f, "Unverified"),
            TrustLevel::Verified => write!(f, "Verified"),
            TrustLevel::FullyTrusted => write!(f, "Fully Trusted"),
        }
    }
}

/// 验证方法
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// 手动指纹验证
    ManualFingerprint,
    
    /// 通过共享密钥
    SharedSecret,
    
    /// 通过信任链（朋友的朋友）
    TrustChain,
    
    /// 通过可信第三方
    TrustedThirdParty,
    
    /// 通过QR码
    QRCode,
    
    /// 通过NFC
    NFC,
}

impl fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationMethod::ManualFingerprint => write!(f, "Manual Fingerprint"),
            VerificationMethod::SharedSecret => write!(f, "Shared Secret"),
            VerificationMethod::TrustChain => write!(f, "Trust Chain"),
            VerificationMethod::TrustedThirdParty => write!(f, "Trusted Third Party"),
            VerificationMethod::QRCode => write!(f, "QR Code"),
            VerificationMethod::NFC => write!(f, "NFC"),
        }
    }
}

/// 信任记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecord {
    /// 用户ID
    pub user_id: UserId,
    
    /// 已知的公钥
    pub public_key: PublicKey,
    
    /// 信任级别
    pub trust_level: TrustLevel,
    
    /// 验证方法
    pub verification_method: Option<VerificationMethod>,
    
    /// 首次添加时间
    pub added_at: SystemTime,
    
    /// 最后更新时间
    pub last_updated: SystemTime,
    
    /// 验证时间
    pub verified_at: Option<SystemTime>,
    
    /// 上次交互时间
    pub last_interaction: Option<SystemTime>,
    
    /// 信任路径（对于间接信任）
    pub trust_path: Option<Vec<UserId>>,
    
    /// 附加信息
    pub additional_info: HashMap<String, String>,
}

impl TrustRecord {
    /// 创建新的信任记录
    pub fn new(user_id: UserId, public_key: PublicKey, trust_level: TrustLevel) -> Self {
        let now = SystemTime::now();
        
        // 仅当信任级别至少为已验证时才设置验证时间
        let verified_at = if trust_level.meets_minimum(TrustLevel::Verified) {
            Some(now)
        } else {
            None
        };
        
        Self {
            user_id,
            public_key,
            trust_level,
            verification_method: None,
            added_at: now,
            last_updated: now,
            verified_at,
            last_interaction: None,
            trust_path: None,
            additional_info: HashMap::new(),
        }
    }
    
    /// 更新信任级别
    pub fn update_trust_level(&mut self, level: TrustLevel, method: Option<VerificationMethod>) -> &mut Self {
        self.trust_level = level;
        self.verification_method = method;
        self.last_updated = SystemTime::now();
        
        // 如果升级到已验证或以上
        if level.meets_minimum(TrustLevel::Verified) && self.verified_at.is_none() {
            self.verified_at = Some(SystemTime::now());
        }
        
        self
    }
    
    /// 记录交互
    pub fn record_interaction(&mut self) -> &mut Self {
        self.last_interaction = Some(SystemTime::now());
        self
    }
    
    /// 设置信任路径
    pub fn set_trust_path(&mut self, path: Vec<UserId>) -> &mut Self {
        self.trust_path = Some(path);
        self.last_updated = SystemTime::now();
        self
    }
    
    /// 添加附加信息
    pub fn add_info(&mut self, key: &str, value: &str) -> &mut Self {
        self.additional_info.insert(key.to_string(), value.to_string());
        self.last_updated = SystemTime::now();
        self
    }
    
    /// 检查记录是否已验证
    pub fn is_verified(&self) -> bool {
        self.trust_level.meets_minimum(TrustLevel::Verified)
    }
    
    /// 计算信任强度（0.0-1.0）
    pub fn calculate_trust_strength(&self) -> f32 {
        let base_strength = match self.trust_level {
            TrustLevel::Unknown => 0.0,
            TrustLevel::Indirect => 0.3,
            TrustLevel::Unverified => 0.5,
            TrustLevel::Verified => 0.8,
            TrustLevel::FullyTrusted => 1.0,
        };
        
        // 调整因素：验证方法
        let method_factor = match &self.verification_method {
            Some(VerificationMethod::ManualFingerprint) => 1.1, // 强验证方法
            Some(VerificationMethod::QRCode) => 1.1,
            Some(VerificationMethod::NFC) => 1.1,
            Some(VerificationMethod::SharedSecret) => 1.0,
            Some(VerificationMethod::TrustedThirdParty) => 0.9,
            Some(VerificationMethod::TrustChain) => 0.8, // 间接验证
            None => 0.7, // 没有验证方法
        };
        
        // 调整因素：信任路径长度
        let path_factor = match &self.trust_path {
            Some(path) => {
                if path.is_empty() {
                    1.0
                } else {
                    // 信任链越长，信任度越低
                    1.0 - (0.1 * path.len() as f32).min(0.9)
                }
            }
            None => 1.0,
        };
        
        // 调整因素：最后交互时间（随时间减弱）
        let interaction_factor = match &self.last_interaction {
            Some(time) => {
                match SystemTime::now().duration_since(*time) {
                    Ok(duration) => {
                        // 超过90天的交互逐渐降低信任强度
                        let days = duration.as_secs() / (60 * 60 * 24);
                        if days < 90 {
                            1.0
                        } else {
                            let decay = ((days - 90) as f32 / 365.0).min(0.5);
                            1.0 - decay
                        }
                    }
                    Err(_) => 1.0, // 时钟回调，不降低信任
                }
            }
            None => 0.9, // 没有交互记录
        };
        
        // 综合计算信任强度
        let strength = base_strength * method_factor * path_factor * interaction_factor;
        
        // 限制范围在0.0-1.0之间
        strength.max(0.0).min(1.0)
    }
}

/// 信任存储
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustStore {
    /// 信任记录映射
    records: HashMap<UserId, TrustRecord>,
}

impl TrustStore {
    /// 创建新的信任存储
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }
    
    /// 添加或更新信任记录
    pub fn add_or_update(&mut self, record: TrustRecord) {
        self.records.insert(record.user_id.clone(), record);
    }
    
    /// 获取信任记录
    pub fn get(&self, user_id: &UserId) -> Option<&TrustRecord> {
        self.records.get(user_id)
    }
    
    /// 获取可变信任记录
    pub fn get_mut(&mut self, user_id: &UserId) -> Option<&mut TrustRecord> {
        self.records.get_mut(user_id)
    }
    
    /// 移除信任记录
    pub fn remove(&mut self, user_id: &UserId) -> Option<TrustRecord> {
        self.records.remove(user_id)
    }
    
    /// 获取所有信任记录
    pub fn get_all(&self) -> impl Iterator<Item = &TrustRecord> {
        self.records.values()
    }
    
    /// 获取所有已验证的记录
    pub fn get_verified(&self) -> impl Iterator<Item = &TrustRecord> {
        self.records.values().filter(|r| r.is_verified())
    }
    
    /// 搜索达到指定信任级别的记录
    pub fn search_by_trust_level(&self, minimum_level: TrustLevel) -> Vec<&TrustRecord> {
        self.records.values()
            .filter(|r| r.trust_level.meets_minimum(minimum_level))
            .collect()
    }
    
    /// 搜索最近交互的记录
    pub fn search_recent_interactions(&self, limit: usize) -> Vec<&TrustRecord> {
        let mut result: Vec<&TrustRecord> = self.records.values()
            .filter(|r| r.last_interaction.is_some())
            .collect();
        
        // 按最后交互时间排序
        result.sort_by(|a, b| {
            b.last_interaction.unwrap().cmp(&a.last_interaction.unwrap())
        });
        
        // 返回前limit个结果
        result.truncate(limit);
        result
    }
    
    /// 计算信任路径
    pub fn find_trust_path(&self, target: &UserId, max_depth: usize) -> Option<Vec<UserId>> {
        // 如果目标已经直接信任，返回空路径
        if self.records.contains_key(target) {
            return Some(Vec::new());
        }
        
        // 使用广度优先搜索查找信任路径
        let mut queue = std::collections::VecDeque::new();
        let mut visited = std::collections::HashSet::new();
        let mut parent = std::collections::HashMap::new();
        
        // 从所有已验证的直接信任开始
        for record in self.get_verified() {
            queue.push_back(record.user_id.clone());
            visited.insert(record.user_id.clone());
        }
        
        while let Some(current) = queue.pop_front() {
            // 如果达到最大深度，跳过
            let current_path_len = self.get_path_length(&parent, &current);
            if current_path_len >= max_depth {
                continue;
            }
            
            // 检查目标
            if &current == target {
                // 构建路径
                return Some(self.reconstruct_path(&parent, target));
            }
            
            // 获取当前节点的信任记录，如果没有，继续
            let Some(record) = self.get(&current) else {
                continue;
            };
            
            // 如果当前记录不可信，跳过
            if !record.is_verified() {
                continue;
            }
            
            // 如果当前记录有信任的用户，考虑它们
            if let Some(trusted_path) = &record.trust_path {
                for next in trusted_path {
                    if !visited.contains(next) {
                        queue.push_back(next.clone());
                        visited.insert(next.clone());
                        parent.insert(next.clone(), current.clone());
                    }
                }
            }
        }
        
        // 没有找到路径
        None
    }
    
    // 辅助方法：获取路径长度
    fn get_path_length(&self, parent: &HashMap<UserId, UserId>, node: &UserId) -> usize {
        let mut length = 0;
        let mut current = node;
        
        while let Some(p) = parent.get(current) {
            length += 1;
            current = p;
        }
        
        length
    }
    
    // 辅助方法：重建路径
    fn reconstruct_path(&self, parent: &HashMap<UserId, UserId>, target: &UserId) -> Vec<UserId> {
        let mut path = Vec::new();
        let mut current = target;
        
        // 从目标节点开始，向后追溯到起点
        while let Some(p) = parent.get(current) {
            path.push(current.clone());
            current = p;
        }
        
        // 反转路径，使其从起点到终点
        path.reverse();
        path
    }
}

/// 验证状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// 验证成功
    Success,
    
    /// 验证失败
    Failure,
    
    /// 验证等待中
    Pending,
    
    /// 验证超时
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    
    #[test]
    fn test_trust_record() {
        // 生成密钥对
        let keypair = KeyPair::generate().unwrap();
        
        // 创建用户ID
        let user_id = UserId([1u8; 32]);
        
        // 创建信任记录
        let mut record = TrustRecord::new(
            user_id,
            keypair.public.clone(),
            TrustLevel::Unverified,
        );
        
        // 测试更新信任级别
        record.update_trust_level(TrustLevel::Verified, Some(VerificationMethod::ManualFingerprint));
        
        assert_eq!(record.trust_level, TrustLevel::Verified);
        assert_eq!(record.verification_method, Some(VerificationMethod::ManualFingerprint));
        assert!(record.verified_at.is_some());
        
        // 测试记录交互
        record.record_interaction();
        
        assert!(record.last_interaction.is_some());
        
        // 测试添加附加信息
        record.add_info("nickname", "Alice");
        
        assert_eq!(record.additional_info.get("nickname"), Some(&"Alice".to_string()));
        
        // 测试计算信任强度
        let strength = record.calculate_trust_strength();
        
        assert!(strength > 0.0);
        assert!(strength <= 1.0);
    }
    
    #[test]
    fn test_trust_store() {
        // 创建信任存储
        let mut store = TrustStore::new();
        
        // 创建三个用户
        let alice_id = UserId([1u8; 32]);
        let bob_id = UserId([2u8; 32]);
        let charlie_id = UserId([3u8; 32]);
        
        // 生成密钥对
        let alice_keypair = KeyPair::generate().unwrap();
        let bob_keypair = KeyPair::generate().unwrap();
        let charlie_keypair = KeyPair::generate().unwrap();
        
        // 创建信任记录
        let mut alice_record = TrustRecord::new(
            alice_id.clone(),
            alice_keypair.public.clone(),
            TrustLevel::Verified,
        );
        alice_record.update_trust_level(TrustLevel::Verified, Some(VerificationMethod::ManualFingerprint));
        
        let mut bob_record = TrustRecord::new(
            bob_id.clone(),
            bob_keypair.public.clone(),
            TrustLevel::Unverified,
        );
        
        let mut charlie_record = TrustRecord::new(
            charlie_id.clone(),
            charlie_keypair.public.clone(),
            TrustLevel::Indirect,
        );
        charlie_record.set_trust_path(vec![bob_id.clone()]);
        
        // 添加记录到存储
        store.add_or_update(alice_record);
        store.add_or_update(bob_record);
        store.add_or_update(charlie_record);
        
        // 测试获取记录
        assert!(store.get(&alice_id).is_some());
        assert!(store.get(&bob_id).is_some());
        assert!(store.get(&charlie_id).is_some());
        
        // 测试搜索
        let verified = store.search_by_trust_level(TrustLevel::Verified);
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].user_id, alice_id);
        
        // 测试移除
        store.remove(&bob_id);
        assert!(store.get(&bob_id).is_none());
        
        // 测试记录数量
        assert_eq!(store.get_all().count(), 2);
    }
}
