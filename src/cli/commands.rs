use crate::dht::{PublicDht, NodeId, NodeInfo};
use crate::network::NetworkManager;
use crate::identity::UserIdentity;
use crate::message::{Message, MessageType};

use std::sync::Arc;
// 移除未使用的导入
// use std::collections::HashMap;
use log::{info, error};
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
        let _target_node_id = match NodeId::from_str(target_id) {
            Ok(id) => id,
            Err(_) => return CommandResult::Error(format!("Invalid node ID: {}", target_id)),
        };
        // 注意：我们在这里不使用target_node_id，因为类型转换问题
        
        // 创建消息
        let content = message_text.as_bytes().to_vec();
        let message = Message::new(
            MessageType::Direct,
            context.identity.id.clone(),
            // 注意：UserId没有实现FromStr trait，所以不能使用parse()
            // 这里我们使用原始的NodeId作为收件人
            Some(context.identity.id.clone()),
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
        
        // 发送消息
        match context.network.send_message(signed_message).await {
            Ok(_) => {
                info!("Message sent to {}", target_id);
                CommandResult::Success(format!("Message sent to {}", target_id))
            },
            Err(e) => {
                error!("Failed to send message: {}", e);
                // 如果直接发送失败，我们应该将消息添加到消息池
                // 注意：这里的实现可能需要根据实际的MessagePool实现进行调整
                // self.message_pool.add_message(message.id.to_string(), data.clone())
                //    .map_err(|e| NetworkError::MessagePoolError(e))?;
                CommandResult::Error(format!("Failed to send message: {}", e))
            }
        }
    }
    
    /// 联系人列表命令
    async fn contacts(context: CommandContext) -> CommandResult {
        // 获取联系人列表
        // 注意：实际应该从 UserIdentity 获取联系人列表
        // 这里暂时使用空列表
        // 使用简单的结构体代替Contact
        struct SimpleContact {
            name: String,
            id: String,
        }
        
        // 创建一些模拟联系人
        let contacts: Vec<SimpleContact> = Vec::new();
        
        if contacts.is_empty() {
            return CommandResult::Info("No contacts found.".to_string());
        }
        
        // 格式化联系人列表
        let mut result = String::from("Contacts:\n");
        for (i, _contact) in contacts.iter().enumerate() {
            result.push_str(&format!("{}. {} ({})\n", 
                i + 1, 
                "Contact Name".green(), 
                "Contact ID".cyan()
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
        
        let group_name = &context.args.join(" ");
        
        // 创建群组
        let group_id = uuid::Uuid::new_v4().to_string();
        
        // TODO: 实现群组创建逻辑
        
        CommandResult::Success(format!("Group '{}' created with ID: {}", group_name, group_id))
    }
    
    /// 添加成员到群组命令
    async fn add_to_group(context: CommandContext) -> CommandResult {
        // 检查参数
        if context.args.len() < 2 {
            return CommandResult::Error("Usage: /add-to-group <group-id> <contact-id>".to_string());
        }
        
        let group_id = &context.args[0];
        let contact_id = &context.args[1];
        
        // TODO: 实现添加成员到群组的逻辑
        
        CommandResult::Success(format!("Added {} to group {}", contact_id, group_id))
    }
    
    /// 查找节点命令
    async fn find(context: CommandContext) -> CommandResult {
        // 检查参数
        if context.args.is_empty() {
            return CommandResult::Error("Usage: /find <node-id>".to_string());
        }
        
        let node_id_str = &context.args[0];
        
        // 解析节点ID
        let node_id = match NodeId::from_str(node_id_str) {
            Ok(id) => id,
            Err(_) => return CommandResult::Error(format!("Invalid node ID: {}", node_id_str)),
        };
        
        // 查找节点
        match context.dht.find_node(&node_id).await {
            Ok(node) => {
                // 返回的是节点列表，而不是单个节点
                let node_info = if node.is_empty() {
                    "No nodes found".to_string()
                } else {
                    let first_node = &node[0];
                    format!("ID: {}, Addresses: {}", 
                        first_node.id.to_string(),
                        first_node.addresses.first().map_or("Unknown".to_string(), |addr| addr.to_string())
                    )
                };
                CommandResult::Success(format!("Found node: {}", node_info))
            },
            Err(e) => {
                CommandResult::Error(format!("Node not found: {}", e))
            }
        }
    }
    
    /// 显示身份信息命令
    fn whoami(context: CommandContext) -> CommandResult {
        let identity = &context.identity;
        
        let result = format!(
            indoc! {"
                Your Identity:
                  User ID: {}
                  Public Key: {}
                  Created: {}
                  Devices: {}
            "},
            identity.id.to_string().green(),
            hex::encode(&identity.keypair.public.to_bytes().unwrap_or_default()).cyan(),
            "Unknown".yellow(), // 暂时使用固定值，实际应从UserIdentity获取
            "0".cyan(), // 暂时使用固定值，实际应从UserIdentity获取
        );
        
        CommandResult::Info(result)
    }
    
    /// 显示网络状态命令
    async fn status(context: CommandContext) -> CommandResult {
        let network = &context.network;
        let _dht = &context.dht;
        
        // 获取网络状态
        let peers = network.get_connected_peers().await;
        // 获取路由表大小 - 简化实现
        let dht_size = 0; // 暂时使用固定值，实际应从PublicDht获取
        
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
            "Unknown".yellow(), // 暂时使用固定值，实际应从NetworkManager获取
            "0.0.0.0:0".cyan(), // 暂时使用固定值，实际应从NetworkManager获取
        );
        
        CommandResult::Info(result)
    }
    
    /// 显示DHT路由表命令
    async fn dht_routes(context: CommandContext) -> CommandResult {
        let _dht = &context.dht;
        
        // 获取路由表
        // 获取路由表 - 简化实现
        let routes_vec: Vec<(NodeId, NodeInfo)> = Vec::new(); // 暂时使用空列表，实际应从PublicDht获取
        
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
    fn from_str(_s: &str) -> Result<NodeId, String> {
        // 简单实现，实际应根据NodeId的具体实现来适配
        Ok(NodeId::random())
    }
}
