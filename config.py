# Configuration for Mesh_chat Cyber-Enhanced Upgrade

# --- APP INFO ---
APP_NAME = "CYBERSPACE TEXTS v2.0"
VERSION = "2.0.0-CYBER"

# --- NETWORK CONFIG ---
WIFI_TCP_PORT = 7000
WIFI_UDP_PORT = 7001
BT_CHANNEL = 4
BEACON_INTERVAL = 3  # Seconds
KEEP_ALIVE_INTERVAL = 10
ROUTING_TTL = 5  # Max hops

# --- SECURITY CONFIG ---
RSA_KEY_SIZE = 2048
IDENTITY_FILE = "flux_identity.json"
NODES_DB = "flux_nodes.db"

# --- AESTHETICS (NEON NIGHT PALETTE) ---
C_BG_VOID    = "#050505"
C_PANEL      = "#0a0a0a"
C_GLASS      = "#0f0f0f"
C_CYAN       = "#00f3ff"  # Wi-Fi / System
C_PINK       = "#ff0055"  # Bluetooth / Danger
C_PURPLE     = "#bd00ff"  # File Transfer
C_INDIGO     = "#4d00ff"  # Routing / Relays
C_TEXT       = "#ffffff"
C_TEXT_DIM   = "#888888"

# --- LOGGING ---
LOG_FILE = "mesh_chat.log"
