use crate::identity::{UserId, UserProfile};
use crate::crypto::{PublicKey, KeyPair};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::str::FromStr; // Added for FromStr
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

#[derive(Debug, PartialEq, Eq)]
pub struct ParseGroupIdError(String);

impl FromStr for GroupId {
    type Err = ParseGroupIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut S = s;
        if s.starts_with("0x") {
            S = &s[2..];
        }
        
        if S.len() != 64 {
            return Err(ParseGroupIdError(format!(
                "Invalid length for GroupId: expected 64 hex chars, got {}",
                S.len()
            )));
        }
        match hex::decode(S) {
            Ok(bytes) => {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Ok(GroupId(arr))
                } else {
                    // This case should ideally not be reached if hex::decode works as expected
                    // and S.len() == 64, as 64 hex chars decode to 32 bytes.
                    Err(ParseGroupIdError(format!(
                        "Decoded byte length is not 32: got {}",
                        bytes.len()
                    )))
                }
            }
            Err(e) => Err(ParseGroupIdError(format!("Invalid hex string: {}", e))),
        }
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

    /// 添加成员 (简化版)
    pub fn add_member_simplified(
        &mut self,
        member_id: UserId,
        member_public_key: PublicKey,
        member_display_name: Option<String>,
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
                format!("Adding user {} not found in group", added_by)
            ));
        }
        
        // 检查成员是否已存在
        if self.members.contains_key(&member_id) {
            return Err(GroupMessageError::OperationFailed(
                format!("Member {} already exists in group", member_id)
            ));
        }
        
        // 检查成员限制
        if self.members.len() >= self.info.member_limit {
            return Err(GroupMessageError::OperationFailed(
                "Group has reached member limit".to_string()
            ));
        }
        
        // 创建新成员
        let mut new_member = GroupMember::new(
            member_id.clone(),
            role,
            member_public_key,
            Some(added_by),
        );

        if let Some(name) = member_display_name {
            new_member = new_member.with_display_name(name);
        }
        
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
    use std::str::FromStr; // For GroupId::from_str testing

    #[test]
    fn test_group_id_from_str() {
        let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let valid_bytes = hex::decode(valid_hex).unwrap();
        let mut expected_arr = [0u8; 32];
        expected_arr.copy_from_slice(&valid_bytes);

        // Test valid 64-char hex string
        assert_eq!(GroupId::from_str(valid_hex), Ok(GroupId(expected_arr.clone())));

        // Test valid 66-char hex string with "0x" prefix
        let valid_hex_prefix = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(GroupId::from_str(valid_hex_prefix), Ok(GroupId(expected_arr.clone())));

        // Test invalid hex characters
        let invalid_hex_char = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"; // 'g' is invalid
        assert!(GroupId::from_str(invalid_hex_char).is_err());
        match GroupId::from_str(invalid_hex_char) {
            Err(ParseGroupIdError(msg)) => assert!(msg.contains("Invalid hex string")),
            _ => panic!("Expected ParseGroupIdError for invalid hex char"),
        }


        // Test too short hex string
        let short_hex = "0123456789abcdef";
        assert!(GroupId::from_str(short_hex).is_err());
         match GroupId::from_str(short_hex) {
            Err(ParseGroupIdError(msg)) => assert!(msg.contains("Invalid length")),
            _ => panic!("Expected ParseGroupIdError for short hex"),
        }


        // Test too long hex string
        let long_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00";
        assert!(GroupId::from_str(long_hex).is_err());
        match GroupId::from_str(long_hex) {
            Err(ParseGroupIdError(msg)) => assert!(msg.contains("Invalid length")),
            _ => panic!("Expected ParseGroupIdError for long hex"),
        }
        
        // Test with "0x" prefix and invalid length
        let short_hex_prefix = "0x0123456789abcdef";
        assert!(GroupId::from_str(short_hex_prefix).is_err());
        match GroupId::from_str(short_hex_prefix) {
            Err(ParseGroupIdError(msg)) => assert!(msg.contains("Invalid length")),
            _ => panic!("Expected ParseGroupIdError for short hex with prefix"),
        }
    }

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

    #[test]
    fn test_group_add_member_simplified() {
        // Setup creator
        let creator_keypair = KeyPair::generate().unwrap();
        let creator_id = UserId::from_public_key(&creator_keypair.public).unwrap();
        let creator_profile = UserProfile::new("Creator".to_string());

        // Create group
        let mut group = GroupMembership::new(
            "Simplified Test Group".to_string(),
            creator_id.clone(),
            &creator_profile,
            &creator_keypair,
            false,
        ).unwrap();
        assert_eq!(group.info.member_count, 1);

        // Setup new member 1
        let member1_keypair = KeyPair::generate().unwrap();
        let member1_id = UserId::from_public_key(&member1_keypair.public).unwrap();
        let member1_display_name = "Member One".to_string();

        // Test: Successfully add new member by owner with display name
        let result = group.add_member_simplified(
            member1_id.clone(),
            member1_keypair.public.clone(),
            Some(member1_display_name.clone()),
            creator_id.clone(),
            MemberRole::Member,
        );
        assert!(result.is_ok());
        assert_eq!(group.info.member_count, 2);
        assert!(group.is_member(&member1_id));
        let member1_info = group.get_member(&member1_id).unwrap();
        assert_eq!(member1_info.role, MemberRole::Member);
        assert_eq!(member1_info.display_name, Some(member1_display_name));
        assert_eq!(member1_info.invited_by, Some(creator_id.clone()));

        // Setup new member 2
        let member2_keypair = KeyPair::generate().unwrap();
        let member2_id = UserId::from_public_key(&member2_keypair.public).unwrap();

        // Test: Successfully add another member by owner without display name
        let result_no_display_name = group.add_member_simplified(
            member2_id.clone(),
            member2_keypair.public.clone(),
            None, // No display name
            creator_id.clone(),
            MemberRole::Admin, // Add as admin for next test
        );
        assert!(result_no_display_name.is_ok());
        assert_eq!(group.info.member_count, 3);
        assert!(group.is_member(&member2_id));
        let member2_info = group.get_member(&member2_id).unwrap();
        assert_eq!(member2_info.role, MemberRole::Admin);
        assert_eq!(member2_info.display_name, None);

        // Setup new member 3
        let member3_keypair = KeyPair::generate().unwrap();
        let member3_id = UserId::from_public_key(&member3_keypair.public).unwrap();
        
        // Test: Permission Denied - Try to add by member1 (who is MemberRole::Member)
        let result_permission_denied = group.add_member_simplified(
            member3_id.clone(),
            member3_keypair.public.clone(),
            None,
            member1_id.clone(), // Added by member1
            MemberRole::Member,
        );
        assert!(matches!(result_permission_denied, Err(GroupMessageError::PermissionDenied(_))));
        assert_eq!(group.info.member_count, 3); // Count should not change

        // Test: Permission OK - Try to add by member2 (who is MemberRole::Admin)
         let result_permission_ok_admin = group.add_member_simplified(
            member3_id.clone(),
            member3_keypair.public.clone(),
            None,
            member2_id.clone(), // Added by member2 (Admin)
            MemberRole::Member,
        );
        assert!(result_permission_ok_admin.is_ok());
        assert_eq!(group.info.member_count, 4); 


        // Test: Member Exists - Try to add member1 again
        let result_member_exists = group.add_member_simplified(
            member1_id.clone(),
            member1_keypair.public.clone(),
            Some("Attempt Re-add".to_string()),
            creator_id.clone(),
            MemberRole::Member,
        );
        assert!(matches!(result_member_exists, Err(GroupMessageError::OperationFailed(_))));
        if let Err(GroupMessageError::OperationFailed(msg)) = result_member_exists {
            assert!(msg.contains("already exists in group"));
        }
        assert_eq!(group.info.member_count, 4); // Count should not change

        // Test: Group Full
        group.info.member_limit = group.members.len(); // Set limit to current size (4)
        let member4_keypair = KeyPair::generate().unwrap();
        let member4_id = UserId::from_public_key(&member4_keypair.public).unwrap();
        let result_group_full = group.add_member_simplified(
            member4_id.clone(),
            member4_keypair.public.clone(),
            None,
            creator_id.clone(),
            MemberRole::Member,
        );
        assert!(matches!(result_group_full, Err(GroupMessageError::OperationFailed(_))));
         if let Err(GroupMessageError::OperationFailed(msg)) = result_group_full {
            assert!(msg.contains("Group has reached member limit"));
        }
        assert_eq!(group.info.member_count, 4); // Count should not change
    }
}
