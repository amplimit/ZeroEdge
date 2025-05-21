# ZeroEdge项目架构

本文档描述了ZeroEdge项目的代码架构和模块职责，帮助开发者理解整体设计。

## 项目结构

```
ZeroEdge/
├── src/                 # 源代码
│   ├── crypto/          # 密码学模块
│   ├── dht/             # 分布式哈希表实现
│   ├── identity/        # 身份管理
│   ├── message/         # 消息处理
│   ├── nat/             # NAT穿透
│   ├── network/         # 网络连接
│   ├── storage/         # 数据存储
│   └── utils/           # 工具函数
├── docs/                # 文档
│   ├── protocol_spec.md # 协议规范
│   └── ...
├── tests/               # 测试
│   ├── integration/     # 集成测试
│   └── ...
├── benches/             # 性能测试
├── examples/            # 示例应用
├── Cargo.toml           # Rust包配置
└── README.md            # 项目概述
```

## 核心模块

### 1. 密码学模块 (`src/crypto/`)

**职责**: 实现所有加密、解密、签名和验证操作。

**主要组件**:
- `keys.rs`: 密钥生成与管理
- `encryption.rs`: 消息加密与解密
- `signing.rs`: 签名与验证
- `double_ratchet.rs`: 双棘轮算法实现

**关键接口**:
```rust
// 生成密钥对
pub fn generate_keypair() -> Result<KeyPair, CryptoError>;

// 消息加密
pub fn encrypt(recipient_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

// 消息解密
pub fn decrypt(secret_key: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

// 创建签名
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, CryptoError>;

// 验证签名
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
```

### 2. 分布式哈希表 (`src/dht/`)

**职责**: 提供节点发现和分布式数据存储功能。

**主要组件**:
- `kademlia.rs`: Kademlia DHT算法实现
- `routing.rs`: 路由表管理
- `storage.rs`: DHT值存储
- `public_dht.rs`: 公共DHT实现
- `private_dht.rs`: 私有好友DHT实现

**关键接口**:
```rust
// 初始化DHT
pub fn initialize(config: DhtConfig) -> Result<DhtInstance, DhtError>;

// 查找节点
pub async fn find_node(node_id: &NodeId) -> Result<Option<NodeInfo>, DhtError>;

// 存储值
pub async fn store(key: &[u8], value: &[u8], ttl: Duration) -> Result<(), DhtError>;

// 获取值
pub async fn get(key: &[u8]) -> Result<Option<Vec<u8>>, DhtError>;
```

### 3. 身份管理 (`src/identity/`)

**职责**: 管理用户身份、身份验证和信任关系。

**主要组件**:
- `user.rs`: 用户身份
- `device.rs`: 设备管理
- `verification.rs`: 身份验证方法
- `trust.rs`: 信任关系存储

**关键接口**:
```rust
// 创建新用户身份
pub fn create_identity(name: &str) -> Result<UserIdentity, IdentityError>;

// 添加设备
pub fn add_device(identity: &mut UserIdentity, device_name: &str) -> Result<DeviceInfo, IdentityError>;

// 验证用户身份
pub fn verify_identity(user_id: &UserId, method: VerificationMethod) -> Result<VerificationStatus, IdentityError>;

// 建立信任关系
pub fn trust_user(identity: &mut UserIdentity, other_id: &UserId, level: TrustLevel) -> Result<(), IdentityError>;
```

### 4. 消息处理 (`src/message/`)

**职责**: 处理消息的创建、加密、存储和递送。

**主要组件**:
- `message_types.rs`: 各类消息定义
- `encryption.rs`: 消息加密层
- `offline_storage.rs`: 离线消息存储
- `delivery.rs`: 消息递送状态处理
- `group_messaging.rs`: 群组消息

**关键接口**:
```rust
// 创建直接消息
pub fn create_direct_message(sender: &UserIdentity, recipient_id: &UserId, content: &[u8], content_type: &str) -> Result<DirectMessage, MessageError>;

// 发送消息
pub async fn send_message(message: &Message) -> Result<DeliveryStatus, MessageError>;

// 存储离线消息
pub async fn store_offline(message: &EncryptedMessage) -> Result<(), OfflineStorageError>;

// 获取离线消息
pub async fn fetch_offline_messages(user_id: &UserId) -> Result<Vec<OfflineMessage>, OfflineStorageError>;
```

### 5. NAT穿透 (`src/nat/`)

**职责**: 提供P2P连接建立功能，处理各种NAT环境。

**主要组件**:
- `stun.rs`: STUN协议实现
- `hole_punching.rs`: UDP打洞
- `ice.rs`: ICE框架实现
- `relay.rs`: 中继服务

**关键接口**:
```rust
// 获取公网地址映射
pub async fn discover_mapping() -> Result<NatMapping, NatError>;

// 尝试直接连接
pub async fn establish_direct_connection(target: &NodeInfo) -> Result<Connection, NatError>;

// 中继连接
pub async fn establish_relayed_connection(target: &NodeInfo, relays: &[NodeInfo]) -> Result<Connection, NatError>;
```

### 6. 网络连接 (`src/network/`)

**职责**: 管理网络连接、消息传输和连接池。

**主要组件**:
- `connection.rs`: 连接管理
- `transport.rs`: 传输协议
- `peer.rs`: 对等节点表示
- `pool.rs`: 连接池

**关键接口**:
```rust
// 初始化网络
pub fn initialize(config: NetworkConfig) -> Result<NetworkInstance, NetworkError>;

// 连接对等节点
pub async fn connect(peer_id: &PeerId) -> Result<Connection, NetworkError>;

// 发送数据
pub async fn send(connection: &Connection, data: &[u8]) -> Result<(), NetworkError>;

// 接收数据
pub async fn receive(connection: &Connection) -> Result<Vec<u8>, NetworkError>;
```

### 7. 数据存储 (`src/storage/`)

**职责**: 管理本地持久化存储。

**主要组件**:
- `database.rs`: 本地数据库抽象
- `message_store.rs`: 消息存储
- `identity_store.rs`: 身份存储
- `config_store.rs`: 配置存储

**关键接口**:
```rust
// 初始化存储
pub fn initialize(path: &Path) -> Result<StorageInstance, StorageError>;

// 存储消息
pub async fn store_message(message: &Message) -> Result<(), StorageError>;

// 获取消息
pub async fn get_messages(query: MessageQuery) -> Result<Vec<Message>, StorageError>;

// 存储用户数据
pub async fn store_user_data(user_id: &UserId, key: &str, value: &[u8]) -> Result<(), StorageError>;
```

### 8. 实用工具 (`src/utils/`)

**职责**: 提供各种帮助函数和工具。

**主要组件**:
- `logging.rs`: 日志工具
- `serialization.rs`: 序列化辅助
- `scheduler.rs`: 任务调度
- `config.rs`: 配置管理

## 模块间交互

1. **用户注册流程**:
   ```
   identity::create_identity()
   ↓
   crypto::generate_keypair()
   ↓
   storage::store_identity()
   ↓
   dht::announce_node()
   ```

2. **消息发送流程**:
   ```
   message::create_direct_message()
   ↓
   crypto::encrypt()
   ↓
   dht::find_node() 找到接收者
   ↓
   nat::establish_connection() 建立连接
   ↓
   network::send() 发送消息
   ↓
   storage::store_message() 本地保存
   ```

3. **离线消息处理**:
   ```
   message::store_offline() 存储离线消息
   ↓
   message::split_message() 分片消息
   ↓
   crypto::encrypt_fragments() 加密分片
   ↓
   network::distribute_fragments() 分发到存储节点
   ```

4. **联系人添加流程**:
   ```
   identity::verify_identity() 验证身份
   ↓
   identity::trust_user() 添加信任
   ↓
   crypto::initial_key_exchange() 初始密钥交换
   ↓
   storage::store_contact() 存储联系人
   ```

## 扩展点

1. **加密算法替换**:
   加密模块设计为可插拔，可以无缝替换为不同的加密算法。

2. **存储后端**:
   存储接口抽象，可以使用不同的后端实现（SQLite、LevelDB等）。

3. **网络传输协议**:
   传输层可扩展，支持不同的底层协议（UDP、WebRTC等）。

4. **UI集成**:
   核心库设计为无UI依赖，可以与任何UI框架集成。

## 性能考量

1. **异步设计**:
   所有网络和IO操作都使用异步设计，避免阻塞。

2. **资源控制**:
   - 连接池限制最大并发连接
   - 存储配额防止过度使用
   - 带宽限制避免网络饱和

3. **优先级队列**:
   消息处理使用优先级队列，确保重要消息优先处理。

4. **增量同步**:
   数据同步采用增量方式减少传输量。

## 安全模型

1. **信任假设**:
   - 只信任经过验证的用户
   - 不信任网络基础设施
   - 不信任存储节点

2. **威胁模型**:
   - 被动监听：通过端到端加密防护
   - 主动中间人：通过密钥验证防护
   - 女巫攻击：通过社交验证减轻
   - 服务拒绝：通过分布式设计减轻

3. **数据保护**:
   - 所有存储数据加密
   - 敏感数据内存保护
   - 安全擦除机制

## 开发路线图

1. **Phase 1**: 核心通信协议
   - 基本P2P连接
   - 简单消息传递
   - 基本加密

2. **Phase 2**: 完整消息系统
   - 离线消息
   - 多设备同步
   - 群组消息

3. **Phase 3**: 可靠性与扩展
   - NAT穿透优化
   - 资源管理
   - 存储扩展

4. **Phase 4**: UI与用户体验
   - 命令行客户端
   - 图形界面客户端
   - 移动平台适配
