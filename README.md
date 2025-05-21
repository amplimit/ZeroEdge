# ZeroEdge: 完全去中心化的P2P聊天系统

ZeroEdge是一个纯点对点(P2P)、完全去中心化的通信系统，设计目标是提供安全、私密的聊天功能，而无需依赖任何中央服务器或中间商。

## 特性

- **完全去中心化**: 没有中央服务器，所有通信直接在节点之间进行
- **端到端加密**: 所有消息均经过强加密，只有预期接收者可以解密
- **离线消息**: 使用分布式存储确保即使接收方不在线也能收到消息
- **NAT穿透**: 使用先进的NAT穿透技术确保设备能够直接通信
- **多设备支持**: 可以在多个设备上使用同一身份
- **群组聊天**: 支持加密的群组通信
- **抗审查**: 设计抵抗网络审查，确保自由通信

## 目录结构

```
ZeroEdge/
├── src/                 # 源代码
│   ├── crypto/          # 密码学模块
│   ├── dht/             # 分布式哈希表
│   ├── identity/        # 用户身份管理
│   ├── message/         # 消息处理
│   ├── nat/             # NAT穿透
│   ├── network/         # 网络通信
│   ├── storage/         # 数据存储
│   └── utils/           # 工具函数
├── docs/                # 文档
└── tests/               # 测试
```

## 构建与运行

### 前提条件

- Rust 1.66.0或更高版本
- Cargo包管理器
- 建议：Ubuntu 22.04 LTS或Windows 10/11

### 构建

1. 克隆仓库:
```bash
git clone https://github.com/amplimit/ZeroEdge.git
cd ZeroEdge
```

2. 构建项目:
```bash
cargo build --release
```

### 运行

执行以下命令启动ZeroEdge客户端:

```bash
cargo run --release
```

默认配置文件将在首次运行时创建，位于`~/.config/zeroedge/config.json`（Linux/macOS）或`%APPDATA%\ZeroEdge\config.json`（Windows）。

## 使用方法

ZeroEdge当前为命令行应用程序。以下是基本操作:

1. **创建身份**:
   首次运行时，系统会提示创建新身份。输入显示名称并按下回车。

2. **添加联系人**:
   通过共享身份和手动验证添加联系人:
   ```
   /add <identity-code>
   ```
   然后进行验证:
   ```
   /verify <contact-id> <verification-code>
   ```

3. **发送消息**:
   ```
   /msg <contact-id> 您的消息内容
   ```

4. **创建群组**:
   ```
   /create-group <group-name>
   ```

5. **添加成员到群组**:
   ```
   /add-to-group <group-id> <contact-id>
   ```

6. **列出联系人**:
   ```
   /contacts
   ```

7. **显示帮助**:
   ```
   /help
   ```

## 工作原理

ZeroEdge使用分布式哈希表(DHT)进行节点发现，结合进阶的NAT穿透技术实现点对点通信。关键技术包括:

1. **Kademlia DHT**: 用于高效节点查找
2. **双层DHT**: 公共DHT用于基本发现，私有DHT用于朋友间加密数据交换
3. **Signal协议**: 提供前向安全性的消息加密
4. **Reed-Solomon编码**: 实现容错的离线消息存储
5. **多种NAT穿透技术**: 包括UDP打洞、STUN和智能中继系统

## 开发

### 代码规范

- 使用Rust 2021 Edition
- 遵循Rust API指南
- 所有公共API必须有文档注释
- 测试覆盖率至少80%

### 添加新功能

1. 创建功能分支:
   ```
   git checkout -b feature/your-feature-name
   ```

2. 实现功能和测试

3. 运行测试:
   ```
   cargo test
   ```

4. 提交更改:
   ```
   git commit -am "Add your feature description"
   ```

5. 推送分支:
   ```
   git push origin feature/your-feature-name
   ```

6. 创建Pull Request

## 运行指南

### 初次运行

1. 编译并运行ZeroEdge:
   ```bash
   cargo run --release
   ```

2. 创建你的第一个身份:
   ```
   输入显示名称: [你的名字]
   ```

3. 程序将生成你的身份并展示身份ID，记下这个ID以分享给你的联系人

### 设置NAT穿透

ZeroEdge自动尝试NAT穿透，但某些网络环境可能需要额外配置:

1. 检查NAT类型:
   ```
   /check-nat
   ```

2. 如果NAT类型是"Symmetric"，可能需要更多中继节点:
   ```
   /set-relays auto
   ```

### 故障排除

1. **无法连接到DHT网络**:
   - 检查网络连接
   - 尝试使用不同的引导节点:
     ```
     /set-bootstrap custom
     ```

2. **消息发送失败**:
   - 检查联系人是否在线
   - 验证有NAT穿透的连接:
     ```
     /check-connection <contact-id>
     ```

3. **日志查看**:
   启用详细日志记录:
   ```
   /set-log-level debug
   ```

## 贡献

欢迎贡献代码、报告问题或提出建议。请查看[贡献指南](CONTRIBUTING.md)了解更多信息。

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件。

## 联系方式

- 项目主页: https://github.com/amplimit/ZeroEdge
- 问题报告: https://github.com/amplimit/ZeroEdge/issues
