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

ZeroEdge is currently a command-line application. Here are the basic operations:

1. **Creating an Identity**:
   On first run, the system will prompt you to create a new identity. Enter a display name and press Enter.

2. **Viewing Your Identity**:
   ```
   /whoami
   ```

3. **Sending Messages**:
   ```
   /send <node_id> <message>
   ```

4. **Listing Contacts**:
   ```
   /contacts
   ```

5. **Creating a Group**:
   ```
   /create-group <group-name>
   ```

6. **Adding Members to a Group**:
   ```
   /add-to-group <group-id> <node-id>
   ```

7. **Finding a Node**:
   ```
   /find <node-id>
   ```

8. **Checking Network Status**:
   ```
   /status
   ```

9. **Viewing DHT Routing Table**:
   ```
   /dht-routes
   ```

10. **Displaying Help**:
    ```
    /help
    ```

11. **Exiting the Application**:
    ```
    /exit
    ```

## How It Works

ZeroEdge uses a distributed hash table (DHT) for node discovery, combined with advanced NAT traversal techniques to enable peer-to-peer communication. Key technologies include:

1. **Kademlia DHT**: For efficient node lookup
2. **Dual-layer DHT**: Public DHT for basic discovery, private DHT for encrypted data exchange between friends
3. **Signal Protocol**: For forward-secure message encryption
4. **Reed-Solomon Encoding**: For fault-tolerant offline message storage
5. **Multiple NAT Traversal Techniques**: Including UDP hole punching, STUN, and smart relay systems

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

If you encounter platform-specific issues, please report them on the issue tracker.

## Contributing

Contributions in the form of code, bug reports, or suggestions are welcome. Please check the [contribution guidelines](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- Project Homepage: https://github.com/amplimit/ZeroEdge
- Issue Reporting: https://github.com/amplimit/ZeroEdge/issues
