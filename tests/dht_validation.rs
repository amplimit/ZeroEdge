use zero_edge::{
    dht::{NodeId, validate_node_id},
};

/// 测试节点ID验证函数
/// 
/// 这个测试验证节点ID验证逻辑能够正确处理:
/// - 有效的NodeID
/// - 格式错误的NodeID（长度不正确或包含非十六进制字符）
#[test]
fn test_node_id_validation() {
    // 测试1: 有效的节点ID（64个十六进制字符）
    let valid_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let result = validate_node_id(valid_id);
    assert!(result.is_ok(), "Valid node ID rejected: {}", valid_id);

    // 测试2: 无效的节点ID - 长度不足
    let short_id = "0123456789abcdef";
    let result = validate_node_id(short_id);
    assert!(result.is_err(), "Short node ID should be rejected");
    assert!(result.unwrap_err().contains("Invalid node ID format"), 
        "Error message should indicate format issue");

    // 测试3: 无效的节点ID - 长度过长
    let long_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00";
    let result = validate_node_id(long_id);
    assert!(result.is_err(), "Long node ID should be rejected");
    assert!(result.unwrap_err().contains("Invalid node ID format"), 
        "Error message should indicate format issue");

    // 测试4: 无效的节点ID - 包含非十六进制字符
    let invalid_chars_id = "0123456789abcdef0123456789abcdef0123456789abcdefggggggggggggg";
    let result = validate_node_id(invalid_chars_id);
    assert!(result.is_err(), "Node ID with invalid chars should be rejected");
    assert!(result.unwrap_err().contains("Invalid node ID format"), 
        "Error message should indicate format issue");
}

/// 测试随机NodeId的格式
/// 
/// 这个测试确保通过 NodeId::random() 生成的ID符合预期格式
#[test]
fn test_random_node_id_format() {
    // 生成随机节点ID
    let random_id = NodeId::random();
    
    // 转换为字符串格式并验证
    let id_str = random_id.to_string();
    
    // 验证长度为64（32字节，每字节2个十六进制字符）
    assert_eq!(id_str.len(), 64, "Random NodeId string should be 64 characters");
    
    // 验证只包含十六进制字符
    assert!(id_str.chars().all(|c| c.is_ascii_hexdigit()), 
        "Random NodeId should only contain hex digits");
    
    // 验证通过validate_node_id函数
    let validation_result = validate_node_id(&id_str);
    assert!(validation_result.is_ok(), 
        "Random NodeId should pass validation: {}", id_str);
}
