use crate::dht::NodeId;

/// 验证节点ID的格式和有效性
/// 
/// # 参数
/// * `node_id_str` - 要验证的节点ID字符串
///
/// # 返回值
/// * `Ok(NodeId)` - 如果验证成功，返回解析后的NodeId
/// * `Err(String)` - 如果验证失败，返回错误信息
///
/// # 验证步骤
/// - 检查长度是否为64个字符（32字节的十六进制表示）
/// - 确保所有字符都是有效的十六进制字符
/// - 尝试解析为NodeId类型
pub fn validate_node_id(node_id_str: &str) -> Result<NodeId, String> {
    // 验证节点ID格式和长度
    if node_id_str.len() != 64 || !node_id_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid node ID format: {}", node_id_str));
    }
    
    // 解析节点ID
    let bytes = match hex::decode(node_id_str) {
        Ok(b) => b,
        Err(e) => return Err(format!("Invalid NodeId hex: {}", e)),
    };
    
    NodeId::try_from(bytes.as_slice()).map_err(|e| e.to_string())
}
