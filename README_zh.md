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
- **增强的命令行界面**: 强大的命令行界面，支持命令历史记录、自动补全和语法高亮

## 目录结构

```
ZeroEdge/
├── src/                 # 源代码
│   ├── cli/             # 命令行界面
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

ZeroEdge采用了增强的命令行界面，使用`clap`和`rustyline`库，提供命令历史记录、命令自动补全和语法高亮功能。以下是所有可用命令:

1. **获取帮助**:

   ```bash
   /help
   ```

   显示所有可用命令及其描述的列表。

2. **查看身份信息**:

   ```bash
   /whoami
   ```

   显示您的用户ID、公钥、创建时间和已连接的设备。

3. **发送消息**:

   ```bash
   /send <node_id> <消息内容>
   ```

   向特定节点发送消息，通过节点ID指定。注意，接收者必须能在DHT网络中被发现。

4. **列出联系人**:

   ```bash
   /contacts
   ```

   显示您的联系人列表。如果您还没有添加任何联系人，将显示“未找到联系人”。

5. **创建群组**:

   ```bash
   /create-group <群组名称>
   ```

   创建一个指定名称的新聊天群组。

6. **添加成员到群组**:

   ```bash
   /add-to-group <群组ID> <节点ID>
   ```

   将联系人添加到现有群聊中。

7. **查找节点**:

   ```bash
   /find <节点ID>
   ```

   在DHT网络中搜索指定 ID的节点。这是与其他节点建立通信的必要步骤。

8. **检查网络状态**:

   ```bash
   /status
   ```

   显示您当前的网络状态，包括已连接的节点、DHT大小、NAT类型和公共地址。

9. **查看DHT路由表**:

   ```bash
   /dht-routes
   ```

   显示DHT路由表信息，展示网络中已知的节点。

10. **退出应用程序**:

    ```bash
    /exit
    ```
    ```bash
    /quit
    ```

    两个命令都可以关闭应用程序。

**注意**:
- 您可以带或不带斜杠前缀输入命令（例如，`/whoami`和`whoami`都可以正常工作）。
- 要建立实例之间的通信，两个节点需要通过DHT网络相互发现。
- 在同一台机器上运行多个实例时，使用不同的端口：`zero_edge.exe -p <端口号>`
- 在尝试发送消息前，请使用`/status`检查网络连接。

## 工作原理

ZeroEdge使用分布式哈希表(DHT)进行节点发现，结合进阶的NAT穿透技术实现点对点通信。关键技术包括:

1. **Kademlia DHT**: 用于高效节点查找
2. **双层DHT**: 公共DHT用于基本发现，私有DHT用于朋友间加密数据交换
3. **Signal协议**: 提供前向安全性的消息加密
4. **Reed-Solomon编码**: 实现容错的离线消息存储
5. **多种NAT穿透技术**: 包括UDP打洞、STUN和智能中继系统
6. **命令行框架**: 利用`clap`进行命令解析和`rustyline`提供交互式shell功能

## 开发

### 代码规范

- 使用Rust 2021 Edition
- 遵循Rust API指南
- 所有公共API必须有文档注释
- 测试覆盖率至少80%

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

   ```bash
   /status
   ```

2. 如果NAT类型是"Symmetric"，可能需要更多中继节点（注意：中继功能目前正在开发中）

### 故障排除

1. **无法连接到DHT网络**:
   - 检查网络连接
   - 尝试使用不同的引导节点

2. **消息发送失败**:
   - 检查联系人是否在线
   - 验证NAT穿透连接:

     ```bash
     /status
     ```

3. **日志查看**:
   启用详细日志记录:

   ```bash
   cargo run --release -- --verbose
   ```

## 跨平台兼容性

ZeroEdge设计为可在多个平台上运行，但存在一些已知问题：

- **Linux编译**：虽然项目在Windows上可以成功编译，但在Linux环境（如GitHub Actions）中可能存在编译问题。这些问题与路径分隔符差异、平台特定代码和文件权限有关。
- **CI/CD流水线**：GitHub Actions配置已更新，支持多平台测试（Ubuntu、Windows、macOS）、代码格式检查和Clippy静态分析。

如果您遇到平台特定问题，请在问题跟踪器上报告。

## 贡献

欢迎贡献代码、报告问题或提出建议。请查看[贡献指南](CONTRIBUTING.md)了解更多信息。

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件。

## 联系方式

- 项目主页: https://github.com/amplimit/ZeroEdge
- 问题报告: https://github.com/amplimit/ZeroEdge/issues
