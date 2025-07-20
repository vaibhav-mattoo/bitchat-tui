# bitchat-tui - Secure, Anonymous, Peer-to-Peer Bluetooth Chat

[![Last Commit](https://img.shields.io/github/last-commit/vaibhav-mattoo/bitchat-tui)](https://github.com/vaibhav-mattoo/bitchat-tui/commits)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/bitchat-tui)](https://crates.io/crates/bitchat-tui)
[![AUR version](https://img.shields.io/aur/version/bitchat-tui?logo=arch-linux)](https://aur.archlinux.org/packages/bitchat-tui)
[![Homebrew Tap](https://img.shields.io/badge/homebrew-tap-brightgreen?logo=homebrew)](https://github.com/vaibhav-mattoo/homebrew-bitchat-tui)

A secure, anonymous, and peer-to-peer chat application that runs over Bluetooth Low Energy (BLE). Communicate completely off-grid with end-to-end encryption, public channels, and direct messaging, all from your terminal.

## 🎨 Showcase


### Universal Install Script

The easiest way to install `bitchat-tui` on any supported system:

```
curl -sSfL https://raw.githubusercontent.com/vaibhav-mattoo/bitchat-tui/main/install.sh | sh
```

This script will automatically detect your system and install the appropriate binary.

> [!NOTE]
> Remember to add `~/.local/bin` to your `$PATH` if prompted by the install script, by adding `export PATH="$HOME/.local/bin:$PATH"` at the end of your shell config file (~/.bashrc, ~/.zshrc, etc).

### From Cargo

```
cargo install bitchat-tui
```


### From Homebrew (macOS & Linux)

```
brew tap vaibhav-mattoo/bitchat-tui
brew install bitchat-tui
```


### From AUR (Arch Linux)

Using `yay` or `paru`:

```
yay -S bitchat-tui
# or
paru -S bitchat-tui
```


### From Source

```
git clone https://github.com/vaibhav-mattoo/bitchat-tui.git
cd bitchat-tui
cargo install --path .
```


## 📋 Table of Contents

<!-- disabledMarkdownTOC autolink="false" markdown_preview="github" -->

- [Showcase](#-showcase)
- [Installation](#-installation)
    - [Universal Install Script](#universal-install-script)
    - [From Cargo](#from-cargo)
    - [From Homebrew (macOS & Linux)](#from-homebrew-macos--linux)
    - [From AUR (Arch Linux)](#from-aur-arch-linux)
    - [From Source](#from-source)
- [Quick Start](#-quick-start)
- [Features](#-features)
- [TUI Navigation](#-tui-navigation)
    - [Key Bindings](#key-bindings)
- [In-App Commands](#-in-app-commands)
    - [Basic Commands](#basic-commands)
    - [Channel Management](#channel-management)
    - [User Interaction](#user-interaction)
- [Cryptography & Security](#-cryptography--security)
    - [Key Exchange](#key-exchange)
    - [Encryption](#encryption)
    - [Authentication](#authentication)
    - [Channel Passwords](#channel-passwords)
- [Use Cases](#-use-cases)
- [Uninstallation](#-uninstallation)
- [License](#-license)

<!-- /MarkdownTOC -->

## 🚀 Quick Start

Launch the application directly from your terminal:

```
bitchat-tui
```

The app will immediately start scanning for other BitChat users. Once a peer is found, it will connect automatically and you'll be placed in the `#public` chat room.

Type messages in the input box and press `Enter` to send. Use `/help` to see a list of all available commands.

## ✨ Features

- **Secure & Anonymous**: All communication is end-to-end encrypted. No phone number, email, or account is required. Your identity is ephemeral and tied only to your session keys.
- **Peer-to-Peer Mesh**: Communicates directly with other devices running the app over Bluetooth Low Energy. No internet connection or central server is needed.
- **Public & Private Channels**: Chat with everyone in the public room, or create/join private, password-protected channels for group conversations.
- **Direct Messaging (DMs)**: Engage in secure, one-to-one conversations with any user on the network.
- **User & Channel Lists**: The sidebar provides an at-a-glance view of online users and the channels you've joined.
- **Message Fragmentation**: Large messages are automatically split into smaller chunks and reassembled by the receiving client, ensuring reliable delivery.
- **Cross-Platform**: A single binary that runs on Linux, macOS, and Windows.

## 🎮 TUI Navigation

The Terminal User Interface is designed for intuitive keyboard-only operation.

### Key Bindings

- **`Tab`**: Switch focus between the **Sidebar**, **Main Panel**, and **Input Box**.
- **`↑` / `↓`**: Navigate lists in the sidebar or scroll through messages in the main panel.
- **`Enter`**:
    - In **Sidebar**: Select a channel/user to chat with, or expand/collapse a section.
    - In **Input Box**: Send your message or command.
- **`Ctrl+C`**: Exit the application.
- **`PgUp` / `PgDn`**: Page up/down through the chat history in the main panel.
- **`Home` / `End`**: Jump to the start/end of the chat history.
- **`r`** (on error screen): Attempt to reconnect.

## 💻 In-App Commands

Type these commands into the input box to manage your chat experience.

### Basic Commands
- **`/help`**: Displays a list of all available commands.
- **`/name <new_name>`**: Changes your nickname for the current session.
- **`/exit`**: Quits the application.

### Channel Management
- **`/j #<channel> [password]`**: Joins a channel. If the channel is password-protected, provide the password.
- **`/leave`**: Leaves the current channel and returns you to `#public`.
- **`/pass <password>`**: Sets a password for a channel you created.
- **`/channels`**: Lists all channels you have discovered or joined.

### User Interaction
- **`/dm <user>`**: Starts a private Direct Message with a specific user.
- **`/online`**: Lists all users currently visible on the network.
- **`/block <user>`**: Blocks all messages from a specific user.
- **`/unblock <user>`**: Unblocks a previously blocked user.
- **`/clear`**: Clears all messages from the current conversation view.

## 🔐 Cryptography & Security

BitChat is built with security and privacy as a first principle. All communication is protected by a modern cryptographic stack.

### Key Exchange
- **X25519**: Ephemeral keys are generated for each session. The X25519 algorithm is used for an Elliptic Curve Diffie-Hellman (ECDH) key exchange to establish a secure, shared secret with each peer.

### Encryption
- **AES-256-GCM**: All messages (public, channel, and DM) are encrypted using AES in Galois/Counter Mode with a 256-bit key derived from the shared secret. This provides both confidentiality and integrity.

### Authentication
- **Ed25519**: Each peer generates an ephemeral Ed25519 key pair to sign communications, ensuring that messages are authentic and originate from the claimed sender.

### Channel Passwords
- **PBKDF2-SHA256**: When you set a password for a channel, a symmetric key is derived from it using PBKDF2 with 100,000 rounds of HMAC-SHA256, making it computationally difficult to brute-force.

## 🎯 Use Cases

BitChat is perfect for any situation where you need to communicate without relying on internet infrastructure.
- **Public Events**: Create a local chat network at concerts, festivals, or protests.
- **Remote Areas**: Stay in touch with your group while hiking, camping, or in areas with no cell service.
- **Classrooms or Offices**: Set up a quick, local communication channel for a specific room or building.
- **Privacy-Focused Communication**: Chat with others without leaving a digital footprint on a centralized server.

## 🗑️ Uninstallation

To uninstall `bitchat-tui` and remove its configuration files, you can run the universal uninstall script:

```
curl -sSfL https://raw.githubusercontent.com/vaibhav-mattoo/bitchat-tui/main/uninstall.sh | sh
```

Or download and run the script manually:

```
curl -sSfL https://raw.githubusercontent.com/vaibhav-mattoo/bitchat-tui/main/uninstall.sh -o uninstall.sh
chmod +x uninstall.sh
./uninstall.sh
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
