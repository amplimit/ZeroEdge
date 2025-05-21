use crate::identity::{UserId, UserProfile};
use crate::crypto::{PublicKey, KeyPair};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use rand::Rng;

#[derive(Error, Debug)]
pub enum GroupMessageError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Group operation failed: {0}")]
    OperationFailed(String),
    
    #[error("Member not found: {0}")]
    MemberNotFound(String),
}

/// 群组标识符
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// 成员角色
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MemberRole {
    /// 普通成员
    Member = 0,
    
    /// 管理员
    Admin = 1,
    
    /// 所有者
    Owner = 2,
}

impl MemberRole {
    /// 检查是否有管理权限
    pub fn can_manage(&self) -> bool {
        matches!(self, MemberRole::Admin | MemberRole::Owner)
    }
    
    /// 检查是否是所有者
    pub fn is_owner(&self) -> bool {
        matches!(self, MemberRole::Owner)
    }
}

/// 群组成员信息
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    /// 用户ID
    pub user_id: UserId,
    
    /// 角色
    pub role: MemberRole,
    
    /// 显示名称
    pub display_name: Option<String>,
    
    /// 加入时间
    pub joined_at: u64,
    
    /// 邀请人
    pub invited_by: Option<UserId>,
    
    /// 用户公钥
    pub public_key: PublicKey,
}

impl GroupMember {
    /// 创建新的群组成员
    pub fn new(
        user_id: UserId,
        role: MemberRole,
        public_key: PublicKey,
        invited_by: Option<UserId>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            user_id,
            role,
            display_name: None,
            joined_at: now,
            invited_by,
            public_key,
        }
    }
    
    /// 设置显示名称
    pub fn with_display_name(mut self, name: String) -> Self {
        self.display_name = Some(name);
        self
    }
}

/// 群组信息
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInfo {
    /// 群组ID
    pub id: GroupId,
    
    /// 群组名称
    pub name: String,
    
    /// 群组描述
    pub description: Option<String>,
    
    /// 创建时间
    pub created_at: u64,
    
    /// 更新时间
    pub updated_at: u64,
    
    /// 群组图标哈希
    pub avatar_hash: Option<String>,
    
    /// 是否为公开群组
    pub is_public: bool,
    
    /// 成员限制
    pub member_limit: usize,
    
    /// 当前成员数量
    pub member_count: usize,
}

impl GroupInfo {
    /// 创建新的群组信息
    pub fn new(name: String, is_public: bool) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut id_bytes = [0u8; 32];
        rand::thread_rng().try_fill(&mut id_bytes).expect("Failed to generate random ID bytes");
        
        Self {
            id: GroupId(id_bytes),
            name,
            description: None,
            created_at: now,
            updated_at: now,
            avatar_hash: None,
            is_public,
            member_limit: 100, // 默认成员限制
            member_count: 0,
        }
    }
    
    /// 设置群组描述
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
    
    /// 设置群组图标
    pub fn with_avatar(mut self, avatar_hash: String) -> Self {
        self.avatar_hash = Some(avatar_hash);
        self
    }
    
    /// 设置成员限制
    pub fn with_member_limit(mut self, limit: usize) -> Self {
        self.member_limit = limit;
        self
    }
}

/// 群组成员管理
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMembership {
    /// 群组信息
    pub info: GroupInfo,
    
    /// 成员列表
    pub members: HashMap<UserId, GroupMember>,
    
    /// 群组公钥对
    #[serde(skip)]
    pub group_keypair: Option<KeyPair>,
}

impl GroupMembership {
    /// 创建新的群组
    pub fn new(
        name: String,
        creator: UserId,
        creator_profile: &UserProfile,
        creator_keypair: &KeyPair,
        is_public: bool,
    ) -> Result<Self, GroupMessageError> {
        // 创建群组信息
        let mut info = GroupInfo::new(name, is_public);
        
        // 创建群组密钥对
        let group_keypair = KeyPair::generate()
            .map_err(|e| GroupMessageError::OperationFailed(e.to_string()))?;
        
        // 创建创建者成员信息
        let creator_member = GroupMember::new(
            creator.clone(),
            MemberRole::Owner,
            creator_keypair.public.clone(),
            None,
        ).with_display_name(creator_profile.display_name.clone());
        
        // 创建成员列表
        let mut members = HashMap::new();
        members.insert(creator, creator_member);
        
        // 更新成员数量
        info.member_count = members.len();
        
        Ok(Self {
            info,
            members,
            group_keypair: Some(group_keypair),
        })
    }
    
    /// 添加成员
    pub fn add_member(
        &mut self,
        member_id: UserId,
        member_profile: &UserProfile,
        member_public_key: PublicKey,
        added_by: UserId,
        role: MemberRole,
    ) -> Result<(), GroupMessageError> {
        // 检查添加者权限
        if let Some(adder) = self.members.get(&added_by) {
            if !adder.role.can_manage() {
                return Err(GroupMessageError::PermissionDenied(
                    "Only admins and owners can add members".to_string()
                ));
            }
        } else {
            return Err(GroupMessageError::MemberNotFound(
                format!("Adding user {} not found", added_by)
            ));
        }
        
        // 检查成员是否已存在
        if self.members.contains_key(&member_id) {
            return Err(GroupMessageError::OperationFailed(
                format!("Member {} already exists", member_id)
            ));
        }
        
        // 检查成员限制
        if self.members.len() >= self.info.member_limit {
            return Err(GroupMessageError::OperationFailed(
                "Group has reached member limit".to_string()
            ));
        }
        
        // 创建新成员
        let new_member = GroupMember::new(
            member_id.clone(),
            role,
            member_public_key,
            Some(added_by),
        ).with_display_name(member_profile.display_name.clone());
        
        // 添加到成员列表
        self.members.insert(member_id, new_member);
        
        // 更新群组信息
        self.info.member_count = self.members.len();
        self.info.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(())
    }
    
    /// 移除成员
    pub fn remove_member(
        &mut self,
        member_id: &UserId,
        removed_by: &UserId,
    ) -> Result<(), GroupMessageError> {
        // 检查移除者权限
        if let Some(remover) = self.members.get(removed_by) {
            // 检查是否为自己离开
            if member_id == removed_by {
                // 任何人都可以自己离开
            } else if !remover.role.can_manage() {
                // 非管理员不能移除他人
                return Err(GroupMessageError::PermissionDenied(
                    "Only admins and owners can remove members".to_string()
                ));
            } else {
                // 管理员不能移除所有者
                if let Some(member) = self.members.get(member_id) {
                    if member.role.is_owner() && !remover.role.is_owner() {
                        return Err(GroupMessageError::PermissionDenied(
                            "Admins cannot remove owners".to_string()
                        ));
                    }
                }
            }
        } else {
            return Err(GroupMessageError::MemberNotFound(
                format!("Removing user {} not found", removed_by)
            ));
        }
        
        // 移除成员
        if self.members.remove(member_id).is_none() {
            return Err(GroupMessageError::MemberNotFound(
                format!("Member {} not found", member_id)
            ));
        }
        
        // 更新群组信息
        self.info.member_count = self.members.len();
        self.info.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(())
    }
    
    /// 更新成员角色
    pub fn update_member_role(
        &mut self,
        member_id: &UserId,
        new_role: MemberRole,
        updated_by: &UserId,
    ) -> Result<(), GroupMessageError> {
        // 检查更新者权限
        if let Some(updater) = self.members.get(updated_by) {
            if !updater.role.is_owner() {
                return Err(GroupMessageError::PermissionDenied(
                    "Only owners can change member roles".to_string()
                ));
            }
        } else {
            return Err(GroupMessageError::MemberNotFound(
                format!("Updating user {} not found", updated_by)
            ));
        }
        
        // 更新成员角色
        if let Some(member) = self.members.get_mut(member_id) {
            member.role = new_role;
        } else {
            return Err(GroupMessageError::MemberNotFound(
                format!("Member {} not found", member_id)
            ));
        }
        
        // 更新群组信息
        self.info.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(())
    }
    
    /// 获取成员
    pub fn get_member(&self, member_id: &UserId) -> Option<&GroupMember> {
        self.members.get(member_id)
    }
    
    /// 获取成员角色
    pub fn get_member_role(&self, member_id: &UserId) -> Option<MemberRole> {
        self.members.get(member_id).map(|m| m.role)
    }
    
    /// 检查是否为成员
    pub fn is_member(&self, user_id: &UserId) -> bool {
        self.members.contains_key(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    
    #[test]
    fn test_group_creation() {
        // 创建创建者密钥对
        let creator_keypair = KeyPair::generate().unwrap();
        
        // 创建用户ID
        let creator_id = UserId([1; 32]);
        
        // 创建用户配置文件
        let creator_profile = UserProfile {
            display_name: "Creator".to_string(),
            status: None,
            avatar_hash: None,
            last_updated: SystemTime::now(),
            version: 1,
            signature: Vec::new(),
        };
        
        // 创建群组
        let group = GroupMembership::new(
            "Test Group".to_string(),
            creator_id.clone(),
            &creator_profile,
            &creator_keypair,
            false,
        ).unwrap();
        
        // 验证群组信息
        assert_eq!(group.info.name, "Test Group");
        assert_eq!(group.info.member_count, 1);
        assert!(!group.info.is_public);
        
        // 验证创建者是否为所有者
        assert!(group.is_member(&creator_id));
        assert_eq!(group.get_member_role(&creator_id), Some(MemberRole::Owner));
    }
    
    #[test]
    fn test_group_member_management() {
        // 创建创建者密钥对
        let creator_keypair = KeyPair::generate().unwrap();
        let member_keypair = KeyPair::generate().unwrap();
        
        // 创建用户ID
        let creator_id = UserId([1; 32]);
        let member_id = UserId([2; 32]);
        
        // 创建用户配置文件
        let creator_profile = UserProfile {
            display_name: "Creator".to_string(),
            status: None,
            avatar_hash: None,
            last_updated: SystemTime::now(),
            version: 1,
            signature: Vec::new(),
        };
        
        let member_profile = UserProfile {
            display_name: "Member".to_string(),
            status: None,
            avatar_hash: None,
            last_updated: SystemTime::now(),
            version: 1,
            signature: Vec::new(),
        };
        
        // 创建群组
        let mut group = GroupMembership::new(
            "Test Group".to_string(),
            creator_id.clone(),
            &creator_profile,
            &creator_keypair,
            false,
        ).unwrap();
        
        // 添加成员
        group.add_member(
            member_id.clone(),
            &member_profile,
            member_keypair.public.clone(),
            creator_id.clone(),
            MemberRole::Member,
        ).unwrap();
        
        // 验证成员是否添加成功
        assert!(group.is_member(&member_id));
        assert_eq!(group.get_member_role(&member_id), Some(MemberRole::Member));
        assert_eq!(group.info.member_count, 2);
        
        // 更新成员角色
        group.update_member_role(
            &member_id,
            MemberRole::Admin,
            &creator_id,
        ).unwrap();
        
        // 验证角色是否更新成功
        assert_eq!(group.get_member_role(&member_id), Some(MemberRole::Admin));
        
        // 移除成员
        group.remove_member(&member_id, &creator_id).unwrap();
        
        // 验证成员是否移除成功
        assert!(!group.is_member(&member_id));
        assert_eq!(group.info.member_count, 1);
    }
}
