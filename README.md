# ZeroEdge: A Fully Decentralized P2P Chat System

ZeroEdge is a pure peer-to-peer (P2P), fully decentralized communication system designed to provide secure, private chat functionality without relying on any central servers or intermediaries.

## Features

- **Fully Decentralized**: No central servers, all communication happens directly between nodes
- **End-to-End Encryption**: All messages are strongly encrypted, only the intended recipient can decrypt them
- **Offline Messaging**: Uses distributed storage to ensure messages are received even when the recipient is offline
- **NAT Traversal**: Uses advanced NAT traversal techniques to ensure devices can communicate directly
- **Multi-Device Support**: Use the same identity across multiple devices
- **Group Chat**: Support for encrypted group communications
- **Censorship Resistant**: Designed to resist network censorship, ensuring free communication
- **Enhanced CLI**: Powerful command-line interface with command history, auto-completion, and syntax highlighting

## Directory Structure

```
ZeroEdge/
├── src/                 # Source code
│   ├── cli/             # Command-line interface
│   ├── crypto/          # Cryptography module
│   ├── dht/             # Distributed hash table
│   ├── identity/        # User identity management
│   ├── message/         # Message processing
│   ├── nat/             # NAT traversal
│   ├── network/         # Network communication
│   ├── storage/         # Data storage
│   └── utils/           # Utility functions
├── docs/                # Documentation
└── tests/               # Tests
```

## Building and Running

### Prerequisites

- Rust 1.66.0 or higher
- Cargo package manager
- Recommended: Ubuntu 22.04 LTS or Windows 10/11

### Building

1. Clone the repository:
```bash
git clone https://github.com/amplimit/ZeroEdge.git
cd ZeroEdge
```

2. Build the project:
```bash
cargo build --release
```

### Running

Execute the following command to start the ZeroEdge client:

```bash
cargo run --release
```

The default configuration file will be created on first run, located at `~/.config/zeroedge/config.json` (Linux/macOS) or `%APPDATA%\ZeroEdge\config.json` (Windows).

## Usage

ZeroEdge features an enhanced command-line interface using the `clap` and `rustyline` libraries, providing command history, auto-completion for commands, and syntax highlighting. Here are all available commands:

1. **Getting Help**:
   ```
   /help
   ```
   Shows a list of all available commands and their descriptions.

2. **Viewing Your Identity**:
   ```
   /whoami
   ```
   Shows your User ID, Public Key, creation time, and connected devices.

3. **Sending Messages**:
   ```
   /send <node_id> <message>
   ```
   Send a message to a specific node identified by its ID. Note that the recipient must be discoverable in the DHT network.

4. **Listing Contacts**:
   ```
   /contacts
   ```
   Displays your contact list. If you haven't added any contacts yet, it will show "No contacts found".

5. **Creating a Group**:
   ```
   /create-group <group-name>
   ```
   Creates a new chat group with the specified name.

6. **Adding Members to a Group**:
   ```
   /add-to-group <group-id> <node-id>
   ```
   Adds a contact to an existing group chat.

7. **Finding a Node**:
   ```
   /find <node-id>
   ```
   Searches for a node with the specified ID in the DHT network. This is essential for establishing communication with other nodes.

8. **Checking Network Status**:
   ```
   /status
   ```
   Shows your current network status, including connected peers, DHT size, NAT type, and public address.

9. **Viewing DHT Routing Table**:
   ```
   /dht-routes
   ```
   Displays the DHT routing table information, showing known peers in the network.

10. **Exiting the Application**:
    ```
    /exit
    ```
    ```
    /quit
    ```
    Both commands close the application.

**Note**: 
- You can enter commands with or without the leading slash (e.g., both `/whoami` and `whoami` will work).
- To establish communication between instances, both nodes need to discover each other through the DHT network.
- When running multiple instances on the same machine, use different ports: `zero_edge.exe -p <port_number>`
- Check network connectivity with `/status` before attempting to send messages.

## How It Works

ZeroEdge uses a distributed hash table (DHT) for node discovery, combined with advanced NAT traversal techniques to enable peer-to-peer communication. Key technologies include:

1. **Kademlia DHT**: For efficient node lookup
2. **Dual-layer DHT**: Public DHT for basic discovery, private DHT for encrypted data exchange between friends
3. **Signal Protocol**: For forward-secure message encryption
4. **Reed-Solomon Encoding**: For fault-tolerant offline message storage
5. **Multiple NAT Traversal Techniques**: Including UDP hole punching, STUN, and smart relay systems
6. **Command Line Framework**: Utilizing `clap` for command parsing and `rustyline` for interactive shell features

## Development

### Code Standards

- Uses Rust 2021 Edition
- Follows the Rust API Guidelines
- All public APIs must have documentation comments
- Test coverage of at least 80%

## Running Guide

### First Run

1. Compile and run ZeroEdge:
   ```bash
   cargo run --release
   ```

2. Create your first identity:
   ```
   Enter display name: [Your Name]
   ```

3. The program will generate your identity and display the identity ID. Note this ID to share with your contacts.

### Setting Up NAT Traversal

ZeroEdge automatically attempts NAT traversal, but some network environments may require additional configuration:

1. Check NAT type:
   ```
   /status
   ```

2. If NAT type is "Symmetric", you may need more relay nodes (note: relay functionality is currently under development)

### Troubleshooting

1. **Cannot Connect to DHT Network**:
   - Check your network connection
   - Try using different bootstrap nodes

2. **Message Sending Fails**:
   - Check if the contact is online
   - Verify NAT traversal connection:
     ```
     /status
     ```

3. **Viewing Logs**:
   Enable verbose logging:
   ```
   cargo run --release -- --verbose
   ```

## Cross-Platform Compatibility

ZeroEdge is designed to work on multiple platforms, but there are some known issues:

- **Linux Compilation**: While the project compiles successfully on Windows, there may be issues when compiling on Linux environments (such as GitHub Actions). These issues are related to path separators, platform-specific code, and file permissions.
- **CI/CD Pipeline**: The GitHub Actions configuration has been updated to support multi-platform testing (Ubuntu, Windows, macOS), code formatting checks, and Clippy static analysis.
- **Group Management Persistence**: Commands like `/create-group` and `/add-to-group` execute their immediate logic. However, the persistence of group creations and member changes is subject to ongoing development in the user identity state management. These changes may not be fully saved across sessions or immediately reflected in all contexts in the current version.

If you encounter platform-specific issues, please report them on the issue tracker.

## Contributing

Contributions in the form of code, bug reports, or suggestions are welcome. Please check the [contribution guidelines](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- Project Homepage: https://github.com/amplimit/ZeroEdge
- Issue Reporting: https://github.com/amplimit/ZeroEdge/issues
