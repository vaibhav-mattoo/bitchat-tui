# bitchat-tui - Terminal UI Client for BitChat

[![Last Commit](https://img.shields.io/github/last-commit/vaibhav-mattoo/bitchat-tui)](https://github.com/vaibhav-mattoo/bitchat-tui/commits)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/bitchat-tui)](https://crates.io/crates/bitchat-tui)
[![AUR version](https://img.shields.io/aur/version/bitchat-tui?logo=arch-linux)](https://aur.archlinux.org/packages/bitchat-tui)
[![Homebrew Tap](https://img.shields.io/badge/homebrew-tap-brightgreen?logo=homebrew)](https://github.com/vaibhav-mattoo/homebrew-bitchat-tui)

<a title="This tool is Tool of The Week on Terminal Trove, The $HOME of all things in the terminal" href="https://terminaltrove.com/bitchat-tui/"><img src="https://cdn.terminaltrove.com/media/badges/tool_of_the_week/png/terminal_trove_tool_of_the_week_gold_transparent.png" alt="Terminal Trove Tool of The Week" /></a>

A modern Terminal User Interface (TUI) client for BitChat, a secure, anonymous, and peer-to-peer chat protocol that runs over Bluetooth Low Energy (BLE). Communicate completely off-grid with end-to-end encryption, public channels, and direct messaging, all from your terminal.

## 🎨 Showcase

Watch bitchat-tui in action! See how easy it is to use secure, anonymous Bluetooth messaging with our intuitive terminal interface.



https://github.com/user-attachments/assets/9b5ad6f4-2d90-41d4-8344-ba7c8108b2a2



### Universal Install Script

The easiest way to install `bitchat-tui` on Linux, macOS, or Windows:

```
curl -sSfL https://raw.githubusercontent.com/vaibhav-mattoo/bitchat-tui/main/install.sh | sh
```

This script will automatically detect your system and install the appropriate binary for your platform.

> [!NOTE]
> Remember to add `~/.local/bin` to your `$PATH` if prompted by the install script, by adding `export PATH="$HOME/.local/bin:$PATH"` at the end of your shell config file (~/.bashrc, ~/.zshrc, etc).

### From Cargo

```
cargo install bitchat-tui
```
> [!NOTE]
> If you are on Windows and get `linker link.exe not found` or `the msvc targets depend on the msvc linker but link.exe was not found` then you need to download Microsoft Visual C++ Build Tools. Go to https://visualstudio.microsoft.com/visual-cpp-build-tools/ download the installer for your version, during installation check the box "Desktop development with C++" and reboot after the install completes.

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

> [!NOTE]
> Building from source requires Rust to be installed on your system. This method works on Linux, macOS, and Windows.


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
    - [General Commands](#general-commands)
    - [Navigation Commands](#navigation-commands)
    - [Messaging Commands](#messaging-commands)
    - [Channel Management](#channel-management)
    - [Discovery Commands](#discovery-commands)
    - [Privacy & Security](#privacy--security)
- [TUI Navigation & Interface](#-tui-navigation--interface)
    - [Navigation & Chat Switching](#navigation--chat-switching)
    - [Notification System](#notification-system)
- [Cryptography & Security](#-cryptography--security)
    - [Key Exchange](#key-exchange)
    - [Encryption](#encryption)
    - [Authentication](#authentication)
    - [Channel Passwords](#channel-passwords)
- [Use Cases](#-use-cases)
- [Contributing](#-contributing)
- [Uninstallation](#-uninstallation)
- [License](#-license)

<!-- /MarkdownTOC -->

## 🚀 Quick Start

Launch the BitChat TUI client directly from your terminal:

```
bitchat-tui
```

The app will immediately start scanning for other BitChat users. Once a peer is found, it will connect automatically and you'll be placed in the `#public` chat room.

> [!IMPORTANT]
> If you see "Found bitchat service! Connecting..." but the device doesn't respond in time, you can retry the connection by pressing `r` on the error screen, or exit with `Ctrl+C` and run the app again.

Type messages in the input box and press `Enter` to send. Use `/help` to see a list of all available commands.

## ✨ Features

- **Modern TUI Interface**: Clean, responsive terminal interface built with Ratatui for an intuitive user experience
- **BitChat Protocol Support**: Full implementation of the BitChat messaging protocol with all features
- **Secure & Anonymous**: All communication is end-to-end encrypted. No phone number, email, or account is required. Your identity is ephemeral and tied only to your session keys.
- **Peer-to-Peer Mesh**: Communicates directly with other BitChat clients over Bluetooth Low Energy. No internet connection or central server is needed.
- **Public & Private Channels**: Chat with everyone in the public room, or create/join private, password-protected channels for group conversations.
- **Direct Messaging (DMs)**: Engage in secure, one-to-one conversations with any user on the network.
- **Smart Navigation**: Easy switching between public chat, channels, and DMs using the intuitive sidebar interface.
- **Notification System**: Visual indicators for unread messages, connection status, and active conversations.
- **User & Channel Lists**: The sidebar provides an at-a-glance view of online users and the channels you've joined.
- **Message Fragmentation**: Large messages are automatically split into smaller chunks and reassembled by the receiving client, ensuring reliable delivery.
- **Cross-Platform**: A single binary that runs on Linux, macOS, and Windows with native Bluetooth support on all platforms.

## 🎮 TUI Navigation

The Terminal User Interface (TUI) is designed for intuitive keyboard-only operation and provides a modern, responsive interface for the BitChat protocol.

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

### General Commands
- **`/help`**: Displays a list of all available commands.
- **`/name <name>`**: Changes your nickname for the current session.
- **`/status`**: Shows connection information and current status.
- **`/clear`**: Clears all messages from the current conversation view.
- **`/exit`**: Quits the application.

### Navigation Commands
- **`/public`**: Returns to the public chat room.

### Messaging Commands
- **`/dm <name> [message]`**: Starts a private Direct Message with a user. Optionally sends an initial message.
- **`/reply`**: Quick reply to the last person who sent you a private message.

### Channel Management
- **`/j #<channel> [password]`**: Joins a channel. If the channel is password-protected, provide the password.
- **`/leave`**: Leaves the current channel and returns you to `#public`.
- **`/pass <password>`**: Sets a password for a channel you created (owner only).
- **`/transfer @<user>`**: Transfers channel ownership to another user (owner only).
- **`/channels`**: Lists all channels you have discovered or joined.

### Discovery Commands
- **`/online`** or **`/w`**: Lists all users currently visible on the network.

### Privacy & Security
- **`/block @<user>`**: Blocks all messages from a specific user.
- **`/block`**: Lists all currently blocked users.
- **`/unblock @<user>`**: Unblocks a previously blocked user.

## 🎮 TUI Navigation & Interface

### Navigation & Chat Switching

#### Switching Between Conversations
- **Public Chat**: Select "Public" in the sidebar to return to the main public chat room.
- **Channels**: Select any channel name in the "Channels" section of the sidebar to switch to that channel.
- **Direct Messages**: Select a user's name in the "People" section to start or continue a DM conversation.

#### Sidebar Sections
- **Public**: The main public chat room where all users can see your messages.
- **Channels**: List of channels you've joined. Click to switch to a channel.
- **People**: List of online users. Click to start a private DM conversation.
- **Blocked**: Users you've blocked (if any).

### Notification System

The TUI provides several visual indicators to keep you informed:

#### Unread Message Indicators
- **Channel Badges**: Channels with unread messages show a count in the sidebar.
- **User Badges**: Users with unread DMs show a count next to their name.
- **Section Counters**: Each sidebar section shows total unread messages.

#### Status Indicators
- **Connection Status**: Shows "Connected" or "Connecting" in the status bar.
- **Current Chat**: Displays the active conversation name in the status bar.
- **Message Status**: Visual feedback when messages are sent successfully.

#### Visual Feedback
- **Color Coding**: Different colors for different message types (public, channel, DM).
- **Highlighting**: Selected items in the sidebar are highlighted.
- **Scroll Position**: Visual indicator shows your position in the message history.

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

BitChat is perfect for any situation where you need to communicate without relying on internet infrastructure. This TUI client makes it easy to use BitChat from any terminal environment.
- **Public Events**: Create a local chat network at concerts, festivals, or protests.
- **Remote Areas**: Stay in touch with your group while hiking, camping, or in areas with no cell service.
- **Classrooms or Offices**: Set up a quick, local communication channel for a specific room or building.
- **Privacy-Focused Communication**: Chat with others without leaving a digital footprint on a centralized server.
- **Terminal-Only Environments**: Perfect for servers, embedded systems, or minimalist computing setups.

## 🤝 Contributing

We welcome contributions from the community! Help us improve bitchat-tui by:

- **Bug Fixes**: Report and fix issues to make the app more stable
- **New Features**: Add functionality to enhance the user experience
- **Security Enhancements**: Improve the cryptographic implementation and security model
- **Documentation**: Help improve guides and documentation

To get started, fork the repository, create a feature branch, and submit a pull request. 

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
