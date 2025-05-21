# ZeroEdge协议规范

本文档详细描述了ZeroEdge去中心化聊天协议的技术规范，为实现提供指导。

## 1. 核心概念

### 1.1 身份与密钥

- **密钥对**: 每个用户拥有多组密钥对
  - **身份密钥对**: 长期保存，用于身份验证
  - **会话密钥对**: 短期使用，用于消息加密
  - **预共享密钥**: 用于异步初始化加密通道

- **用户标识符(UserId)**: 
  - 由身份公钥派生的32字节SHA-256哈希值
  - 格式: `hash(identity_public_key)`

- **设备标识符(DeviceId)**:
  - 用户特定设备的唯一标识
  - 格式: `hash(device_public_key + random_salt)`

### 1.2 节点发现与路由

- **节点ID**:
  - 由公钥派生的Kademlia兼容ID
  - 格式: `hash(public_key)`

- **DHT记录结构**:
  ```
  {
    "id": "节点ID",
    "publicKey": "公钥(Base64编码)",
    "addresses": ["IP:端口", ...],
    "lastSeen": 时间戳,
    "version": 协议版本号,
    "flags": 节点标志,
    "signature": "记录签名(Base64编码)"
  }
  ```

- **双层DHT**:
  - **公共DHT**: 所有节点可访问，存储节点位置
  - **私有DHT**: 只对好友可见，存储加密数据

## 2. 网络协议

### 2.1 连接建立

1. **位置查询**:
   - 从DHT查询目标节点最新位置
   - 尝试已知历史地址

2. **NAT穿透过程**:
   - STUN服务器确定公网映射
   - 互发UDP包建立穿透
   - 双向身份验证

3. **中继连接**(当NAT穿透失败):
   - 查找共同联系人作为中继
   - 建立Node A ⟷ Node C ⟷ Node B连接
   - 传输端到端加密数据

### 2.2 传输协议

- **消息格式**:
  ```
  {
    "header": {
      "id": "消息UUID",
      "type": 消息类型,
      "sender": "发送者ID",
      "recipient": "接收者ID",
      "timestamp": 时间戳,
      "sequence": 序列号
    },
    "payload": "加密载荷(Base64编码)",
    "signature": "消息签名(Base64编码)"
  }
  ```

- **消息确认**:
  ```
  {
    "type": "ACK",
    "messageId": "原消息UUID",
    "status": 状态码,
    "timestamp": 时间戳,
    "signature": "确认签名(Base64编码)"
  }
  ```

### 2.3 离线消息处理

1. **消息分片**:
   - 使用Reed-Solomon(10,16)编码
   - 原消息分为10个原始片段和6个冗余片段
   - 只需10个任意片段即可恢复完整消息

2. **片段分布**:
   - 每个片段加密且签名
   - 分布存储在不同信任节点

3. **片段检索**:
   - 上线后请求片段
   - 接收足够数量后重建原消息
   - 向存储节点发送删除确认

### 2.4 多设备同步

1. **设备注册**:
   - 主设备生成授权令牌
   - 新设备扫描QR码获取令牌
   - 新设备生成派生密钥对
   - 主设备签名确认新设备

2. **状态同步**:
   - 使用CRDTs解决冲突
   - 增量同步优化带宽

## 3. 加密协议

### 3.1 端到端加密

1. **初始密钥协商**:
   - 基于改进的X3DH协议
   ```
   SK = KDF(DH(IKa, SPKb) || DH(EKa, IKb) || DH(EKa, SPKb))
   ```
   其中:
   - IK: 身份密钥
   - SPK: 签名预密钥
   - EK: 临时密钥
   - DH: Diffie-Hellman函数
   - KDF: 密钥派生函数

2. **消息加密**:
   - 使用双棘轮算法
   - 每条消息使用唯一密钥
   - 消息密钥随发送和接收更新

### 3.2 群组加密

1. **树形密钥分发**:
   - 使用逻辑密钥层次(LKH)
   - 新成员加入时分配新叶子节点
   - 成员离开时更新受影响路径上的密钥

2. **群组消息加密**:
   ```
   GroupMessage = Encrypt(MessageKey, Content)
   MessageKey = KDF(GroupKey || Counter)
   ```

### 3.3 信任验证

- **带外验证**:
  - 显示密钥指纹以人工比对
  - 生成短验证码进行口头确认
  - NFC/二维码直接传输验证数据

- **社交信任链**:
  - 信任传递: A信任B且B信任C，则A对C具有一定信任
  - 信任级别基于路径长度和强度

## 4. 数据结构

### 4.1 身份和配置文件

```rust
struct UserProfile {
    user_id: UserId,
    display_name: String,
    status: Option<String>,
    avatar_hash: Option<String>,
    devices: Vec<DeviceInfo>,
    last_updated: Timestamp,
    version: u64,
    signature: Signature,
}

struct DeviceInfo {
    device_id: DeviceId,
    owner_id: UserId,
    name: String,
    public_key: PublicKey,
    last_active: Timestamp,
    capabilities: DeviceCapabilities,
    signature: Signature,
}
```

### 4.2 消息

```rust
struct Message {
    id: Uuid,
    message_type: MessageType,
    sender_id: UserId,
    content: Vec<u8>,
    content_type: String,
    timestamp: Timestamp,
    sequence: u64,
    references: Option<Uuid>,
    signature: Signature,
}

struct DirectMessage {
    message: Message,
    recipient_id: UserId,
    encryption_info: EncryptionInfo,
}

struct GroupMessage {
    message: Message,
    group_id: GroupId,
    group_sequence: u64,
    encryption_info: EncryptionInfo,
}
```

### 4.3 群组

```rust
struct GroupInfo {
    id: GroupId,
    name: String,
    creator_id: UserId,
    created_at: Timestamp,
    members: Vec<GroupMember>,
    settings: GroupSettings,
    version: u64,
    signature: Signature,
}

struct GroupMember {
    user_id: UserId,
    role: MemberRole,
    joined_at: Timestamp,
    invited_by: UserId,
    status: MemberStatus,
}
```

## 5. 协议流程

### 5.1 用户注册流程

1. 生成身份密钥对
2. 创建用户配置文件
3. 签名配置文件
4. 连接到网络
5. 在DHT中注册位置信息

### 5.2 添加联系人流程

1. 通过QR码或分享链接交换身份信息
2. 验证身份通过比对密钥指纹
3. 互相添加到联系人列表
4. 执行初始密钥交换
5. 在私有DHT中注册联系信息

### 5.3 消息发送流程

1. 查询DHT获取接收者位置
2. 尝试建立直接连接
3. 构建并加密消息
4. 发送消息，等待确认
5. 如无法直接连接，使用中继或离线存储

### 5.4 群组创建与管理流程

1. 创建者生成群组ID和初始密钥
2. 定义群组设置和权限
3. 邀请初始成员
4. 分发群组信息和密钥
5. 群组状态变更采用CRDT合并

## 6. 激励机制

### 6.1 贡献计量

- **存储贡献**: 离线消息存储量和时间
- **中继贡献**: 转发的消息量
- **可用性贡献**: 节点在线时间

### 6.2 贡献证明

- 使用签名的贡献收据记录服务
- 定期在DHT中更新贡献摘要

### 6.3 资源分配

- 基于贡献分数分配网络优先级
- 高贡献用户获得更多存储配额和更优质中继

## 7. 安全与隐私考虑

### 7.1 元数据保护

- 限制可观察到的通信模式
- 混淆真实流量特征

### 7.2 前向安全和后向安全

- 定期轮换密钥
- 使用双棘轮实现真正的前向安全

### 7.3 抗女巫攻击

- 轻量级工作量证明
- 社交图谱验证

## 8. 实现注意事项

### 8.1 NAT穿透优化

- 智能超时策略
- 并行尝试多种穿透方法
- 缓存成功的穿透策略

### 8.2 移动设备优化

- 智能电源管理
- 低功耗运行模式
- 后台连接维护

### 8.3 带宽管理

- 优先传输重要消息
- 自适应压缩算法
- 增量同步减少数据传输

### 8.4 存储管理

- 自动过期和清理策略
- 基于优先级的存储分配
- 本地数据库分区优化

---

本规范持续更新中，随着协议发展将添加更多细节。
