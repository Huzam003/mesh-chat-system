# 🌐 CYBERSPACE TEXTS v2.0
### Decentralized Mesh Messenger with E2EE Security

![Mesh_chat Logo](https://via.placeholder.com/1000x300?text=CYBERSPACE+TEXTS+v2.0)

**CYBERSPACE TEXTS** is a professional-grade peer-to-peer (P2P) communication platform designed for secure, decentralized messaging and file transfers. Built for **Computer Networks** (3rd Semester) and **Cybersecurity** enthusiasts, it operates without central servers, creating a self-healing mesh network via Wi-Fi and Bluetooth.

---

## ✨ Key Features

### 🛡️ Cybersecurity Excellence
*   **End-to-End Encryption (E2EE)**: RSA-2048 (OAEP) encryption for all messages and files.
*   **Cryptographic Identity**: Unique node identities powered by RSA key pairs generated on first boot.
*   **Secure Handshake**: Automated public key exchange upon link establishment.
*   **Anti-Spoofing**: Packet source verification to prevent identity impersonation.

### 📡 Advanced Mesh Networking
*   **Multi-hop Routing**: Messages can traverse through multiple nodes (relays) to reach a target out of direct range.
*   **Gossip Protocol fallback**: Automated flooding logic for efficient network discovery.
*   **Dual Link Support**: Simultaneous communication over Wi-Fi (TCP/UDP) and Bluetooth (RFCOMM).
*   **Loop Protection**: Packet Sequence IDs and TTL (Time To Live) to maintain network stability.

### 🎨 Premium User Experience
*   **Glassmorphism HUD**: Sleek, modern interface using custom-tailored dark mode aesthetics.
*   **Interactive Terminal**: Built-in system console for real-time network feedback and developer commands.
*   **Desktop Notifications**: Integrated Windows OS notifications for background awareness.
*   **Pulse HUD**: Dynamic status indicators for connection health.

---

## 🛠️ Technical Architecture

### OSI Layer Implementation
| Layer | Protocol / Feature |
| :--- | :--- |
| **Application** | JSON-based Secure Protocol, File Encoding (Base64) |
| **Presentation** | RSA Encryption (OAEP), AES-GCM ready |
| **Transport** | TCP (Reliable Chat), UDP (Beacon Discovery) |
| **Network** | Mesh Routing Table, TTL Management |
| **Data Link** | MAC Address tracking, BT RFCOMM |

---

## 🚀 Getting Started

### Prerequisites
*   Python 3.10+
*   Windows OS (for Bluetooth and notification integration)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/[USER]/Mesh_chat.git
   cd Mesh_chat
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python mesh_Chat.py
   ```

### Console Commands
In the terminal input, you can use these commands:
*   `/status` - Display your unique ID and current peer count.
*   `/clear` - Purge the chat feed history.
*   `/ping [ID]` - (In development) Test connectivity speed to a specific node.

---

## 🏗️ Project Structure
*   `mesh_Chat.py` - Core application logic and GUI.
*   `config.py` - Centralized design system and network constants.
*   `flux_identity.json` - **(Ignored)** Persistent RSA identity keys.
*   `flux_nodes.db` - **(Ignored)** Database of known hardware nodes.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Developed By
**[USER]**  
*3rd Semester Cybersecurity Student | Computer Networks Project*

---
> [!NOTE]
> This project was developed as an educational exploration of decentralized protocols and cryptographic security.
