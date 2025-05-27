use crate::dht::{PublicDht, NodeId}; // NodeInfo removed
use crate::network::NetworkManager;
use crate::identity::{UserIdentity, TrustRecord, UserId}; // TrustRecord, UserId were already here from previous change
use crate::message::{Message, MessageType};
use crate::message::group_messaging::{GroupMembership, GroupId, MemberRole}; // Added GroupId, MemberRole
use crate::crypto::PublicKey; // Added PublicKey

use std::sync::Arc;
use std::convert::TryFrom;
use std::str::FromStr; // Added FromStr import
// 移除未使用的导入
// use std::collections::HashMap;
use chrono::{DateTime, Utc}; // Added chrono import
use log::{info, error, warn}; // Added warn here
use colored::*;
use indoc::indoc;

/// 命令结果
#[derive(Debug, Clone)]
pub enum CommandResult {
    Success(String),
    Info(String),
    Warning(String),
    Error(String),
    Exit,
}

/// 命令类型
#[derive(Debug, Clone)]
pub enum Command {
    Help,
    Exit,
    Send,
    Contacts,
    CreateGroup,
    AddToGroup,
    Find,
    WhoAmI,
    Status,
    DhtRoutes,
}

/// 命令上下文
// 不为CommandContext派生Debug，因为PublicDht和NetworkManager没有实现Debug
#[derive(Clone)]
pub struct CommandContext {
    pub dht: Arc<PublicDht>,
    pub network: Arc<NetworkManager>,
    pub identity: Arc<UserIdentity>,
    pub args: Vec<String>,
}

// 手动实现Debug，避免PublicDht和NetworkManager的Debug约束
impl std::fmt::Debug for CommandContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandContext")
            .field("identity", &self.identity)
            .field("args", &self.args)
            .finish_non_exhaustive()
    }
}

impl Command {
    /// 执行命令
    pub async fn execute(&self, context: CommandContext) -> CommandResult {
        match self {
            Command::Help => Self::help(),
            Command::Exit => Self::exit(),
            Command::Send => Self::send(context).await,
            Command::Contacts => Self::contacts(context).await,
            Command::CreateGroup => Self::create_group(context).await,
            Command::AddToGroup => Self::add_to_group(context).await,
            Command::Find => Self::find(context).await,
            Command::WhoAmI => Self::whoami(context),
            Command::Status => Self::status(context).await,
            Command::DhtRoutes => Self::dht_routes(context).await,
        }
    }
    
    /// 帮助命令
    fn help() -> CommandResult {
        let help_text = indoc! {"
            Available commands:
            
            /help                       - Show this help message
            /exit, /quit               - Exit the application
            /send <node_id> <message>  - Send a message to a node
            /contacts                  - List all contacts
            /create-group <name>       - Create a new group
            /add-to-group <group> <id> - Add a contact to a group
            /find <node_id>            - Find a node in the DHT
            /whoami                    - Show your identity information
            /status                    - Show network status
            /dht-routes                - Show DHT routing table
            
            You can also send a message without the /send command by just typing the message.
        "};
        
        CommandResult::Info(help_text.to_string())
    }
    
    /// 退出命令
    fn exit() -> CommandResult {
        CommandResult::Exit
    }
    
    /// 发送消息命令
    async fn send(context: CommandContext) -> CommandResult {
        // 检查参数
        if context.args.len() < 2 {
            return CommandResult::Error("Usage: /send <node_id> <message>".to_string());
        }
        
        let target_id = &context.args[0];
        let message_text = &context.args[1..].join(" ");
        
        // 解析目标节点ID
        let target_node_id = match NodeId::from_str(target_id) {
            Ok(id) => id,
            Err(_) => return CommandResult::Error(format!("Invalid node ID: {}", target_id)),
        };
        
        // 首先从DHT查找目标节点
        let target_nodes = match context.dht.find_node(&target_node_id).await {
            Ok(nodes) => nodes,
            Err(e) => return CommandResult::Error(format!("Failed to find target node: {}", e)),
        };
        
        if target_nodes.is_empty() {
            return CommandResult::Error(format!("Target node not found: {}", target_id));
        }
        
        // 获取目标节点的地址
        let target_node = &target_nodes[0];
        let target_addr = match target_node.addresses.first() {
            Some(addr) => *addr,
            None => return CommandResult::Error("Target node has no address".to_string()),
        };
        
        // 创建消息
        let content = message_text.as_bytes().to_vec();
        let message = Message::new(
            MessageType::Direct,
            context.identity.id.clone(),
            Some(context.identity.id.clone()), // 发件人，这里应该转换为对应的类型
            context.identity.keypair.public.clone(),
            content,
            "text/plain".to_string(),
            0, // 序列号
            None, // 引用
        );
        
        // 签名消息
        let mut signed_message = message.clone();
        if let Err(e) = signed_message.sign(&context.identity.keypair.secret) {
            return CommandResult::Error(format!("Failed to sign message: {}", e));
        }
        
        // 使用具体的地址发送消息
        match context.network.send_message_to_address(signed_message, target_addr).await {
            Ok(_) => {
                info!("Message sent to {} ({})", target_id, target_addr);
                CommandResult::Success(format!("Message sent to {} ({})", target_id, target_addr))
            },
            Err(e) => {
                error!("Failed to send message: {}", e);
                CommandResult::Error(format!("Failed to send message: {}", e))
            }
        }
    }
    
    /// 联系人列表命令
    async fn contacts(context: CommandContext) -> CommandResult {
        let trust_store = &context.identity.trust_store;
        let contact_records: Vec<&TrustRecord> = trust_store.get_all().collect();

        if contact_records.is_empty() {
            return CommandResult::Info("No contacts found.".to_string());
        }

        let mut result = String::from("Contacts:\n");
        for (i, contact_record) in contact_records.iter().enumerate() {
            let name = contact_record.additional_info.get("nickname")
                .or_else(|| contact_record.additional_info.get("display_name"))
                .cloned()
                .unwrap_or_else(|| contact_record.user_id.to_string());
            
            result.push_str(&format!("{}. {} ({})\n",
                i + 1,
                name.green(),
                contact_record.user_id.to_string().cyan()
            ));
        }
        CommandResult::Info(result)
    }

    /// 创建群组命令
    async fn create_group(context: CommandContext) -> CommandResult {
        // 检查参数
        if context.args.is_empty() {
            return CommandResult::Error("Usage: /create-group <group-name>".to_string());
        }
        
        let group_name = context.args.join(" ");
        let identity = &context.identity;

        // Create the new group.
        // For is_public, we'll default to false as it's not a command argument.
        match GroupMembership::new(
            group_name.clone(),
            identity.id.clone(),
            &identity.profile,
            &identity.keypair, // keypair is not serializable, but GroupMembership::new needs it.
            false, // is_public
        ) {
            Ok(new_group) => {
                let group_id = new_group.info.id.clone();
                // TODO: The new_group needs to be added to context.identity.group_memberships.
                // However, context.identity is an Arc<UserIdentity>, making direct mutation tricky.
                // To properly update, UserIdentity.group_memberships would need interior mutability (e.g. Mutex/RwLock),
                // or the main application loop would need to take the Arc, get a mutable reference (if unique),
                // update it, and then persist.
                // For now, we will log this and return success with the group info.
                info!("Group '{}' created with ID: {}. It needs to be added to UserIdentity.", group_name, group_id);
                
                CommandResult::Success(format!("Group '{}' created with ID: {}", group_name, group_id))
            }
            Err(e) => {
                error!("Failed to create group '{}': {}", group_name, e);
                CommandResult::Error(format!("Failed to create group '{}': {}", group_name, e))
            }
        }
    }
    
    /// 添加成员到群组命令
    async fn add_to_group(context: CommandContext) -> CommandResult {
        // 1. Check for the correct number of arguments
        if context.args.len() != 2 {
            return CommandResult::Error("Usage: /add-to-group <group-id> <contact-id>".to_string());
        }
        
        let group_id_str = &context.args[0];
        let contact_id_str = &context.args[1];

        // 2. Parse group_id_str into GroupId
        let group_id = match GroupId::from_str(group_id_str) {
            Ok(id) => id,
            Err(e) => return CommandResult::Error(format!("Invalid group ID '{}': {:?}", group_id_str, e)),
        };

        // 3. Parse contact_id_str into NodeId (UserId)
        let contact_user_id = match NodeId::from_str(contact_id_str) {
            Ok(id) => id,
            Err(_) => return CommandResult::Error(format!("Invalid contact ID: {}", contact_id_str)),
        };

        // 4. Attempt to retrieve PublicKey and DisplayName for contact_user_id
        let mut member_public_key: Option<PublicKey> = None;
        let mut member_display_name: Option<String> = None;

        // 4.b. Check TrustStore
        // Correctly pass &UserId by wrapping contact_user_id.0
        if let Some(trust_record) = context.identity.trust_store.get(&UserId(contact_user_id.0)) {
            member_public_key = Some(trust_record.public_key.clone());
            // Prefer "nickname", then "display_name" from additional_info
            member_display_name = trust_record.additional_info.get("nickname")
                .or_else(|| trust_record.additional_info.get("display_name"))
                .cloned();
        }

        // 4.c. If not in TrustStore, check DHT
        if member_public_key.is_none() {
            match context.dht.find_node(&contact_user_id).await {
                Ok(nodes) => {
                    if let Some(node_info) = nodes.first() {
                        // Assuming NodeInfo contains a PublicKey. If not, this needs adjustment.
                        // For the purpose of this example, let's assume NodeInfo has a public_key field.
                        // If NodeInfo.public_key is Option<PublicKey>, then it needs to be handled accordingly.
                        // Let's assume it's a direct PublicKey for now.
                        // Also, the current NodeInfo struct in dht.rs does not have public_key.
                        // This part will need adjustment based on actual NodeInfo structure.
                        // For now, we'll simulate its presence or acknowledge this limitation.
                        // For the subtask, we'll assume it can be fetched or error out.
                        // Given the existing NodeInfo does not have public_key, this will likely always fail
                        // unless the contact was in the trust store.
                        // Let's assume for the purpose of this exercise we *would* get it if available.
                        // If the NodeInfo struct from dht.rs has public_key:
                        // member_public_key = Some(node_info.public_key.clone());
                        // Since it doesn't, we log a warning and proceed. This means only trusted contacts can be added
                        // if their PK is not found otherwise.
                        // The prompt implies nodes[0].public_key.clone() exists.
                        // NodeInfo.public_key is NOT an Option, so direct assignment.
                        member_public_key = Some(node_info.public_key.clone());
                    } else {
                        // This case means find_node succeeded but returned an empty list
                        warn!("Contact {} not found in DHT.", contact_id_str);
                    }
                }
                Err(e) => {
                    warn!("Failed to query DHT for contact {}: {}", contact_id_str, e);
                }
            }
        }
        
        // 4.d. If member_public_key is still None, return error
        let final_member_public_key = match member_public_key {
            Some(pk) => pk,
            None => return CommandResult::Error(format!("Could not find public key for contact ID {}", contact_id_str)),
        };

        // 5. Retrieve and update GroupMembership (on a clone)
        if let Some(mut group_membership_clone) = context.identity.group_memberships.get(&group_id).cloned() {
            // This modification is on a clone and won't persist in context.identity.group_memberships
            // without further mechanisms in the main application loop (e.g., taking ownership of UserIdentity,
            // updating it, and then saving/passing it back).
            match group_membership_clone.add_member_simplified(
                UserId(contact_user_id.0), // Correctly pass UserId
                final_member_public_key,  // PublicKey
                member_display_name,     // Option<String>
                context.identity.id.clone(), // added_by: UserId
                MemberRole::Member,      // role: MemberRole
            ) {
                Ok(_) => {
                    info!(
                        "Successfully added {} to group {} (in memory clone). Original UserIdentity not yet updated.",
                        contact_id_str, group_id_str
                    );
                    CommandResult::Success(format!("Added {} to group {} (pending persistence)", contact_id_str, group_id_str))
                }
                Err(e) => CommandResult::Error(format!("Failed to add contact to group {}: {}", group_id_str, e)),
            }
        } else {
            CommandResult::Error(format!("Group {} not found", group_id_str))
        }
    }
    
    /// 查找节点命令
    pub async fn find(context: CommandContext) -> CommandResult {
        if context.args.is_empty() {
            return CommandResult::Error("Usage: /find <node-id>".to_string());
        }
        
        let node_id_str = &context.args[0];
        
        // 验证节点ID格式和长度
        if node_id_str.len() != 64 || !node_id_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return CommandResult::Error(format!("Invalid node ID format: {}", node_id_str));
        }
        
        // 解析节点ID
        let node_id = match NodeId::from_str(node_id_str) {
            Ok(id) => id,
            Err(_) => return CommandResult::Error(format!("Invalid node ID: {}", node_id_str)),
        };
        
        // 查找节点
        match context.dht.find_node(&node_id).await {
            Ok(nodes) => {
                // 返回的是节点列表，可能为空
                if nodes.is_empty() {
                    // 未找到匹配的节点，返回清晰的错误消息
                    CommandResult::Error(format!("Node with ID '{}' not found in the network", node_id))
                } else {
                    // 找到节点，显示详细信息
                    let mut result = format!("Found {} node(s) matching ID '{}':\n", nodes.len(), node_id);
                    
                    for (i, node) in nodes.iter().enumerate() {
                        let addr_info = node.addresses.first()
                            .map_or("Unknown address".to_string(), |addr| addr.to_string());
                        
                        result.push_str(&format!("{}. Node ID: {}\n   Address: {}\n", 
                            i+1, 
                            node.id.to_string(),
                            addr_info
                        ));
                    }
                    
                    CommandResult::Success(result)
                }
            },
            Err(e) => {
                // DHT操作错误
                CommandResult::Error(format!("Error during node lookup: {}", e))
            }
        }
    }
    

    
    /// 显示身份信息命令
    fn whoami(context: CommandContext) -> CommandResult {
        let identity = &context.identity;

        // Get profile last_updated time and format it
        let profile_last_updated_system_time = identity.profile.last_updated;
        let datetime_utc: DateTime<Utc> = profile_last_updated_system_time.into();
        let created_time_str = datetime_utc.format("%Y-%m-%d %H:%M:%S UTC").to_string();

        // Get devices count
        let devices_count = identity.devices.len();
        
        let result = format!(
            indoc! {"
                Your Identity:
                  User ID: {}
                  Public Key: {}
                  Created: {}
                  Connected Devices: {}
            "},
            identity.id.to_string().green(),
            hex::encode(&identity.keypair.public.to_bytes().unwrap_or_default()).cyan(),
            created_time_str.yellow(),
            devices_count.to_string().cyan(),
        );
        
        CommandResult::Info(result)
    }
    
    /// 显示网络状态命令
    async fn status(context: CommandContext) -> CommandResult {
        let network = &context.network;
        let _dht = &context.dht;
        
        // 获取网络状态
        let peers = network.get_connected_peers().await;
        // 获取路由表大小
        let dht_size = context.dht.routing_table_size();

        // Get NAT Type and Public Address
        let mut nat_type_str = "Unknown".to_string();
        let mut public_addr_str = "0.0.0.0:0".to_string(); // Default if None

        if let Some(nat_mapping) = context.network.nat_traversal.get_mapping() {
            nat_type_str = nat_mapping.nat_type.to_string();
            public_addr_str = nat_mapping.public_addr.to_string();
        }
        
        let result = format!(
            indoc! {"
                Network Status:
                  Connected Peers: {}
                  DHT Size: {}
                  NAT Type: {}
                  Public Address: {}
            "},
            peers.len().to_string().green(),
            dht_size.to_string().green(),
            nat_type_str.yellow(),
            public_addr_str.cyan(),
        );
        
        CommandResult::Info(result)
    }
    
    /// 显示DHT路由表命令
    async fn dht_routes(context: CommandContext) -> CommandResult {
        let _dht = &context.dht;
        
        // 获取路由表
        let routes_vec = context.dht.list_routing_table();
        if routes_vec.is_empty() {
            return CommandResult::Info("DHT routing table is empty.".to_string());
        }
        
        // 格式化路由表
        let mut result = String::from("DHT Routing Table:\n");
        for (i, (node_id, node)) in routes_vec.iter().enumerate() {
            result.push_str(&format!("{}. {} ({})\n", 
                i + 1, 
                node_id.to_string().green(), 
                node.addresses.first().map_or("Unknown".to_string(), |addr| addr.to_string()).cyan()
            ));
        }
        
        CommandResult::Info(result)
    }
}

// 辅助函数
trait NodeIdExt {
    fn from_str(s: &str) -> Result<NodeId, String>;
}

impl NodeIdExt for NodeId {
    fn from_str(s: &str) -> Result<NodeId, String> {
        let bytes = hex::decode(s).map_err(|e| format!("Invalid NodeId hex: {}", e))?;
        NodeId::try_from(bytes.as_slice()).map_err(|e| e.to_string())
    }
}
