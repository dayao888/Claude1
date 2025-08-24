#!/bin/bash

# SBall 科学上网代理一键安装脚本
# 项目名称: sball科学上网代理
# 许可证: MIT License
# 支持平台: Linux (Ubuntu--amd64)

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SING_BOX_VERSION="1.12.2"
SING_BOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sing-box"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
LOG_FILE="/var/log/sing-box.log"

# 服务器信息
SERVER_IP=""
DOMAIN=""
USE_DOMAIN=false
USE_CUSTOM_PORTS=false

# 协议配置
PROTOCOLS=("vless-reality" "hysteria2" "tuic" "shadowtls" "shadowsocks" "trojan" "vmess-ws" "vless-ws-tls" "h2-reality" "grpc-reality" "anytls")

# 端口和配置映射
declare -A PROTOCOL_PORTS
declare -A PROTOCOL_CONFIGS

# 显示横幅
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
   _____ ____        _ _ 
  / ____| __ )      | | |
 | (___  |  _ \ __ _| | |
  \___ \ | |_) / _` | | |
  ____) ||  __/ (_| | | |
 |_____/ |_|   \__,_|_|_|
                         
SBall 科学上网代理 v1.0
支持 11 种主流协议的一键部署解决方案
EOF
    echo -e "${NC}"
    echo -e "${GREEN}项目地址: https://github.com/dayao888/Claude1/blob/main/sball.sh${NC}"
    echo -e "${YELLOW}支持协议: VLESS-Reality, Hysteria2, TUIC, ShadowTLS, Shadowsocks, Trojan, VMess-WS, VLESS-WS-TLS, H2-Reality, gRPC-Reality, AnyTLS${NC}"
    echo
}

# 日志函数
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# 检查系统环境
check_system() {
    if [[ ! -f /etc/os-release ]]; then
        error "无法识别的操作系统"
        exit 1
    fi
    
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        warn "建议使用 Ubuntu 系统，当前系统: $ID"
    fi
    
    if [[ $(uname -m) != "x86_64" ]]; then
        error "仅支持 x86_64 架构"
        exit 1
    fi
    
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 权限运行此脚本"
        exit 1
    fi
}

# 获取服务器IP
get_server_ip() {
    SERVER_IP=$(curl -s4 ifconfig.me) || SERVER_IP=$(curl -s4 icanhazip.com) || SERVER_IP=$(curl -s4 ipecho.net/plain)
    if [[ -z "$SERVER_IP" ]]; then
        error "无法获取服务器IP地址"
        exit 1
    fi
    log "检测到服务器IP: $SERVER_IP"
}

# 生成随机UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 生成随机端口
generate_port() {
    local min_port=10000
    local max_port=65000
    echo $((RANDOM % (max_port - min_port + 1) + min_port))
}

# 生成随机路径
generate_path() {
    echo "/$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 8 | head -n 1)"
}

# 生成随机字符串
generate_random() {
    local length=${1:-16}
    tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w $length | head -n 1
}

# 安装依赖
install_dependencies() {
    log "安装系统依赖..."
    apt update -qq
    apt install -y curl wget unzip openssl uuid-runtime jq socat cron
    
    # 安装证书管理工具
    if ! command -v acme.sh >/dev/null 2>&1; then
        log "安装 acme.sh..."
        curl https://get.acme.sh | sh -s email=admin@example.com
        source ~/.bashrc 2>/dev/null || true
        # 确保 acme.sh 可用
        export PATH="$HOME/.acme.sh:$PATH"
    fi
}

# 用户配置询问
user_configuration() {
    echo -e "${CYAN}=== 配置选项 ===${NC}"
    
    # 是否使用自定义端口
    read -p "是否使用自定义端口? (y/n, 默认: n): " custom_ports
    if [[ "$custom_ports" =~ ^[Yy]$ ]]; then
        USE_CUSTOM_PORTS=true
        echo -e "${YELLOW}将为每个协议设置自定义端口${NC}"
    fi
    
    # 是否使用域名
    read -p "是否使用自己的域名? (y/n, 默认: n): " use_domain
    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        read -p "请输入您的域名: " domain_input
        if [[ -n "$domain_input" ]]; then
            DOMAIN="$domain_input"
            USE_DOMAIN=true
            log "将使用域名: $DOMAIN"
        fi
    fi
    
    echo
}

# 生成协议端口
generate_protocol_ports() {
    log "生成协议端口配置..."
    
    for protocol in "${PROTOCOLS[@]}"; do
        if [[ "$USE_CUSTOM_PORTS" == true ]]; then
            read -p "请输入 $protocol 协议的端口 (回车使用随机端口): " custom_port
            if [[ -n "$custom_port" && "$custom_port" =~ ^[0-9]+$ && "$custom_port" -ge 1024 && "$custom_port" -le 65535 ]]; then
                PROTOCOL_PORTS["$protocol"]="$custom_port"
            else
                PROTOCOL_PORTS["$protocol"]=$(generate_port)
            fi
        else
            PROTOCOL_PORTS["$protocol"]=$(generate_port)
        fi
    done
}

# 下载并安装 sing-box
install_singbox() {
    log "下载 sing-box v$SING_BOX_VERSION..."
    
    cd /tmp
    wget -q --show-progress "$SING_BOX_URL" -O sing-box.tar.gz
    
    log "解压并安装 sing-box..."
    tar -xzf sing-box.tar.gz
    mv sing-box-*/sing-box "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sing-box"
    
    # 创建配置目录
    mkdir -p "$CONFIG_DIR"
    
    log "sing-box 安装完成"
}

# 生成证书
generate_certificates() {
    local cert_dir="$CONFIG_DIR/certs"
    mkdir -p "$cert_dir"
    
    if [[ "$USE_DOMAIN" == true ]]; then
        log "为域名 $DOMAIN 申请 SSL 证书..."
        
        # 确保 acme.sh 可用
        export PATH="$HOME/.acme.sh:$PATH"
        
        # 检查域名是否解析到当前服务器
        local domain_ip=$(dig +short "$DOMAIN" 2>/dev/null | tail -n1)
        if [[ "$domain_ip" != "$SERVER_IP" ]]; then
            warn "域名 $DOMAIN 没有解析到当前服务器IP $SERVER_IP"
            warn "检测到域名解析IP: $domain_ip"
            read -p "是否继续使用域名证书? (y/n, 默认: n): " continue_domain
            if [[ ! "$continue_domain" =~ ^[Yy]$ ]]; then
                log "改用自签名证书..."
                USE_DOMAIN=false
            fi
        fi
        
        if [[ "$USE_DOMAIN" == true ]]; then
            # 停止可能占用80端口的服务
            systemctl stop apache2 2>/dev/null || true
            systemctl stop nginx 2>/dev/null || true
            
            # 申请证书
            if ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256; then
                ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
                    --fullchain-file "$cert_dir/cert.pem" \
                    --key-file "$cert_dir/private.key"
                log "域名证书申请成功"
            else
                error "域名证书申请失败，改用自签名证书"
                USE_DOMAIN=false
            fi
        fi
    fi
    
    if [[ "$USE_DOMAIN" == false ]]; then
        log "生成自签名证书..."
        openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$SERVER_IP" \
            -keyout "$cert_dir/private.key" \
            -out "$cert_dir/cert.pem"
        log "自签名证书生成完成"
    fi
    
    # 设置证书文件权限
    chmod 600 "$cert_dir/private.key"
    chmod 644 "$cert_dir/cert.pem"
}

# 生成 VLESS-Reality 配置
generate_vless_reality_config() {
    local uuid=$(generate_uuid)
    local port=${PROTOCOL_PORTS["vless-reality"]}
    local short_id=$(generate_random 8)
    
    # 生成密钥对
    local keypair=$($INSTALL_DIR/sing-box generate reality-keypair 2>/dev/null)
    local private_key=$(echo "$keypair" | jq -r '.private_key' 2>/dev/null || generate_random 43)
    local public_key=$(echo "$keypair" | jq -r '.public_key' 2>/dev/null || generate_random 43)
    
    PROTOCOL_CONFIGS["vless-reality"]="vless://$uuid@$SERVER_IP:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#VLESS-Reality-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_xtls-reality_inbounds.json" << EOF
{
    "type": "vless",
    "tag": "vless-reality-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "uuid": "$uuid",
            "flow": "xtls-rprx-vision"
        }
    ],
    "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
        "reality": {
            "enabled": true,
            "handshake": {
                "server": "www.yahoo.com",
                "server_port": 443
            },
            "private_key": "$private_key",
            "short_id": [
                "$short_id"
            ]
        }
    }
}
EOF
}

# 生成 Hysteria2 配置
generate_hysteria2_config() {
    local uuid=$(generate_uuid)
    local port=${PROTOCOL_PORTS["hysteria2"]}
    
    PROTOCOL_CONFIGS["hysteria2"]="hysteria2://$uuid@$SERVER_IP:$port?sni=www.bing.com&alpn=h3&insecure=1#Hysteria2-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_hysteria2_inbounds.json" << EOF
{
    "type": "hysteria2",
    "tag": "hysteria2-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "password": "$uuid"
        }
    ],
    "tls": {
        "enabled": true,
        "alpn": [
            "h3"
        ],
        "certificate_path": "$CONFIG_DIR/certs/cert.pem",
        "key_path": "$CONFIG_DIR/certs/private.key"
    }
}
EOF
}

# 生成 TUIC 配置
generate_tuic_config() {
    local uuid=$(generate_uuid)
    local password=$(generate_random 16)
    local port=${PROTOCOL_PORTS["tuic"]}
    
    PROTOCOL_CONFIGS["tuic"]="tuic://$uuid:$password@$SERVER_IP:$port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#TUIC-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_tuic_inbounds.json" << EOF
{
    "type": "tuic",
    "tag": "tuic-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "uuid": "$uuid",
            "password": "$password"
        }
    ],
    "congestion_control": "bbr",
    "tls": {
        "enabled": true,
        "alpn": [
            "h3"
        ],
        "certificate_path": "$CONFIG_DIR/certs/cert.pem",
        "key_path": "$CONFIG_DIR/certs/private.key"
    }
}
EOF
}

# 生成 ShadowTLS 配置
generate_shadowtls_config() {
    local password=$(generate_random 16)
    local port=${PROTOCOL_PORTS["shadowtls"]}
    
    PROTOCOL_CONFIGS["shadowtls"]="ss://$(echo -n "chacha20-ietf-poly1305:$password" | base64)@$SERVER_IP:$port#ShadowTLS-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_ShadowTLS_inbounds.json" << EOF
{
    "type": "shadowtls",
    "tag": "shadowtls-in",
    "listen": "::",
    "listen_port": $port,
    "version": 3,
    "users": [
        {
            "password": "$password"
        }
    ],
    "handshake": {
        "server": "www.google.com",
        "server_port": 443
    },
    "detour": "shadowsocks-in"
}
EOF
}

# 生成 Shadowsocks 配置
generate_shadowsocks_config() {
    local password=$(generate_random 16)
    local port=${PROTOCOL_PORTS["shadowsocks"]}
    
    PROTOCOL_CONFIGS["shadowsocks"]="ss://$(echo -n "chacha20-ietf-poly1305:$password" | base64)@$SERVER_IP:$port#Shadowsocks-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_shadowsocks_inbounds.json" << EOF
{
    "type": "shadowsocks",
    "tag": "shadowsocks-in",
    "listen": "127.0.0.1",
    "listen_port": $((port + 1)),
    "method": "chacha20-ietf-poly1305",
    "password": "$password"
}
EOF
}

# 生成 Trojan 配置
generate_trojan_config() {
    local password=$(generate_random 16)
    local port=${PROTOCOL_PORTS["trojan"]}
    
    PROTOCOL_CONFIGS["trojan"]="trojan://$password@$SERVER_IP:$port?security=tls&type=tcp&headerType=none#Trojan-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_trojan_inbounds.json" << EOF
{
    "type": "trojan",
    "tag": "trojan-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "password": "$password"
        }
    ],
    "tls": {
        "enabled": true,
        "certificate_path": "$CONFIG_DIR/certs/cert.pem",
        "key_path": "$CONFIG_DIR/certs/private.key"
    }
}
EOF
}

# 生成 VMess-WS 配置
generate_vmess_ws_config() {
    local uuid=$(generate_uuid)
    local port=${PROTOCOL_PORTS["vmess-ws"]}
    local path=$(generate_path)
    
    local vmess_config='{
        "v": "2",
        "ps": "VMess-WS-'$SERVER_IP'",
        "add": "'$SERVER_IP'",
        "port": "'$port'",
        "id": "'$uuid'",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "",
        "path": "'$path'",
        "tls": "",
        "sni": "",
        "alpn": "",
        "fp": ""
    }'
    
    PROTOCOL_CONFIGS["vmess-ws"]="vmess://$(echo -n "$vmess_config" | base64 -w 0)"
    
    cat > "$CONFIG_DIR/_vmess-ws_inbounds.json" << EOF
{
    "type": "vmess",
    "tag": "vmess-ws-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "uuid": "$uuid",
            "alterId": 0
        }
    ],
    "transport": {
        "type": "ws",
        "path": "$path"
    }
}
EOF
}

# 生成 VLESS-WS-TLS 配置
generate_vless_ws_tls_config() {
    local uuid=$(generate_uuid)
    local port=${PROTOCOL_PORTS["vless-ws-tls"]}
    local path=$(generate_path)
    
    if [[ "$USE_DOMAIN" == true ]]; then
        PROTOCOL_CONFIGS["vless-ws-tls"]="vless://$uuid@$DOMAIN:$port?encryption=none&security=tls&type=ws&host=$DOMAIN&path=$path#VLESS-WS-TLS-$DOMAIN"
        local server_name="$DOMAIN"
    else
        PROTOCOL_CONFIGS["vless-ws-tls"]="vless://$uuid@$SERVER_IP:$port?encryption=none&security=tls&type=ws&path=$path&allowInsecure=1#VLESS-WS-TLS-$SERVER_IP"
        local server_name="$SERVER_IP"
    fi
    
    cat > "$CONFIG_DIR/_vless-ws-tls_inbounds.json" << EOF
{
    "type": "vless",
    "tag": "vless-ws-tls-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "uuid": "$uuid"
        }
    ],
    "tls": {
        "enabled": true,
        "server_name": "$server_name",
        "certificate_path": "$CONFIG_DIR/certs/cert.pem",
        "key_path": "$CONFIG_DIR/certs/private.key"
    },
    "transport": {
        "type": "ws",
        "path": "$path"
    }
}
EOF
}

# 生成 H2-Reality 配置
generate_h2_reality_config() {
    local uuid=$(generate_uuid)
    local port=${PROTOCOL_PORTS["h2-reality"]}
    local short_id=$(generate_random 8)
    
    # 生成密钥对
    local keypair=$($INSTALL_DIR/sing-box generate reality-keypair 2>/dev/null)
    local private_key=$(echo "$keypair" | jq -r '.private_key' 2>/dev/null || generate_random 43)
    local public_key=$(echo "$keypair" | jq -r '.public_key' 2>/dev/null || generate_random 43)
    
    PROTOCOL_CONFIGS["h2-reality"]="vless://$uuid@$SERVER_IP:$port?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$public_key&sid=$short_id&type=http&path=/&host=www.microsoft.com#H2-Reality-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_h2-reality_inbounds.json" << EOF
{
    "type": "vless",
    "tag": "h2-reality-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "uuid": "$uuid"
        }
    ],
    "tls": {
        "enabled": true,
        "server_name": "www.microsoft.com",
        "reality": {
            "enabled": true,
            "handshake": {
                "server": "www.microsoft.com",
                "server_port": 443
            },
            "private_key": "$private_key",
            "short_id": [
                "$short_id"
            ]
        }
    },
    "transport": {
        "type": "http"
    }
}
EOF
}

# 生成 gRPC-Reality 配置
generate_grpc_reality_config() {
    local uuid=$(generate_uuid)
    local port=${PROTOCOL_PORTS["grpc-reality"]}
    local short_id=$(generate_random 8)
    local service_name=$(generate_random 8)
    
    # 生成密钥对
    local keypair=$($INSTALL_DIR/sing-box generate reality-keypair 2>/dev/null)
    local private_key=$(echo "$keypair" | jq -r '.private_key' 2>/dev/null || generate_random 43)
    local public_key=$(echo "$keypair" | jq -r '.public_key' 2>/dev/null || generate_random 43)
    
    PROTOCOL_CONFIGS["grpc-reality"]="vless://$uuid@$SERVER_IP:$port?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=$public_key&sid=$short_id&type=grpc&serviceName=$service_name#gRPC-Reality-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_grpc-reality_inbounds.json" << EOF
{
    "type": "vless",
    "tag": "grpc-reality-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "uuid": "$uuid"
        }
    ],
    "tls": {
        "enabled": true,
        "server_name": "www.apple.com",
        "reality": {
            "enabled": true,
            "handshake": {
                "server": "www.apple.com",
                "server_port": 443
            },
            "private_key": "$private_key",
            "short_id": [
                "$short_id"
            ]
        }
    },
    "transport": {
        "type": "grpc",
        "service_name": "$service_name"
    }
}
EOF
}

# 生成 AnyTLS 配置
generate_anytls_config() {
    local uuid=$(generate_uuid)
    local port=${PROTOCOL_PORTS["anytls"]}
    
    PROTOCOL_CONFIGS["anytls"]="vless://$uuid@$SERVER_IP:$port?encryption=none&security=tls&type=tcp&headerType=none&allowInsecure=1#AnyTLS-$SERVER_IP"
    
    cat > "$CONFIG_DIR/_anytls_inbounds.json" << EOF
{
    "type": "vless",
    "tag": "anytls-in",
    "listen": "::",
    "listen_port": $port,
    "users": [
        {
            "uuid": "$uuid"
        }
    ],
    "tls": {
        "enabled": true,
        "certificate_path": "$CONFIG_DIR/certs/cert.pem",
        "key_path": "$CONFIG_DIR/certs/private.key"
    }
}
EOF
}

# 生成主配置文件
generate_main_config() {
    log "生成主配置文件..."
    
    cat > "$CONFIG_DIR/config.json" << 'EOF'
{
    "log": {
        "disabled": false,
        "level": "info",
        "timestamp": true
    },
    "inbounds": [],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [
            {
                "ip_cidr": [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "224.0.0.0/4",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10"
                ],
                "outbound": "direct"
            },
            {
                "ip_cidr": [
                    "1.0.1.0/24",
                    "1.1.1.0/24",
                    "8.8.8.0/24",
                    "8.8.4.0/24",
                    "9.9.9.0/24",
                    "149.112.112.0/24"
                ],
                "outbound": "direct"
            }
        ],
        "auto_detect_interface": true,
        "final": "direct"
    }
}
EOF
    
    # 合并所有协议配置
    local inbounds_json="["
    local first=true
    
    for config_file in "$CONFIG_DIR"/_*_inbounds.json; do
        if [[ -f "$config_file" ]]; then
            if [[ "$first" == true ]]; then
                first=false
            else
                inbounds_json+=","
            fi
            inbounds_json+="$(cat "$config_file")"
        fi
    done
    inbounds_json+="]"
    
    # 更新主配置文件的inbounds部分
    jq --argjson inbounds "$inbounds_json" '.inbounds = $inbounds' "$CONFIG_DIR/config.json" > /tmp/config.json.tmp
    mv /tmp/config.json.tmp "$CONFIG_DIR/config.json"
}

# 生成所有协议配置
generate_all_configs() {
    log "生成所有协议配置..."
    
    generate_vless_reality_config
    generate_hysteria2_config
    generate_tuic_config
    generate_shadowtls_config
    generate_shadowsocks_config
    generate_trojan_config
    generate_vmess_ws_config
    generate_vless_ws_tls_config
    generate_h2_reality_config
    generate_grpc_reality_config
    generate_anytls_config
    
    generate_main_config
}

# 创建系统服务
create_systemd_service() {
    log "创建 systemd 服务..."
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=$INSTALL_DIR/sing-box run -c $CONFIG_DIR/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box
}

# 配置防火墙
configure_firewall() {
    log "配置防火墙规则..."
    
    # 开放所有协议端口
    for protocol in "${PROTOCOLS[@]}"; do
        local port=${PROTOCOL_PORTS["$protocol"]}
        if command -v ufw >/dev/null 2>&1; then
            ufw allow "$port" >/dev/null 2>&1
        elif command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="$port/tcp" >/dev/null 2>&1
            firewall-cmd --permanent --add-port="$port/udp" >/dev/null 2>&1
        fi
    done
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

# 显示节点信息
show_node_info() {
    echo -e "${CYAN}=== 节点信息 ===${NC}"
    echo -e "${GREEN}以下是所有协议的节点配置信息，请根据您的客户端选择对应格式:${NC}"
    echo
    
    # 检查节点信息是否存在
    if [[ ! -f "$CONFIG_DIR/nodes.txt" ]]; then
        error "节点信息文件不存在，请重新生成节点"
        return 1
    fi
    
    # 直接显示节点信息文件内容（排除注释）
    while IFS= read -r line; do
        if [[ ! "$line" =~ ^# && -n "$line" ]]; then
            # 提取协议名称
            if [[ "$line" =~ (vless://|vmess://|hysteria2://|ss://|trojan://) ]]; then
                if [[ "$line" =~ #([^#]+)$ ]]; then
                    local protocol_name="${BASH_REMATCH[1]}"
                    echo -e "${YELLOW}$protocol_name:${NC}"
                fi
                echo "$line"
                echo
            fi
        fi
    done < "$CONFIG_DIR/nodes.txt"
    
    echo -e "${GREEN}节点信息文件位置: $CONFIG_DIR/nodes.txt${NC}"
    echo -e "${BLUE}提示: 可以直接复制上述链接到客户端使用${NC}"
}

# 安装函数
install_sball() {
    show_banner
    log "开始安装 SBall 科学上网代理..."
    
    check_system
    get_server_ip
    user_configuration
    install_dependencies
    generate_protocol_ports
    install_singbox
    generate_certificates
    generate_all_configs
    create_systemd_service
    configure_firewall
    
    log "启动 sing-box 服务..."
    systemctl start sing-box
    
    if systemctl is-active --quiet sing-box; then
        log "SBall 安装完成！"
        echo
        show_node_info
        echo
        log "服务状态: $(systemctl is-active sing-box)"
        log "使用 'systemctl status sing-box' 查看服务状态"
        log "使用 '$0' 打开管理菜单"
    else
        error "sing-box 服务启动失败，请检查配置"
        exit 1
    fi
}

# 更新 sing-box
update_singbox() {
    log "更新 sing-box..."
    
    systemctl stop sing-box
    
    # 备份配置
    cp -r "$CONFIG_DIR" "$CONFIG_DIR.backup.$(date +%Y%m%d_%H%M%S)"
    
    # 下载最新版本
    cd /tmp
    wget -q --show-progress "$SING_BOX_URL" -O sing-box-new.tar.gz
    tar -xzf sing-box-new.tar.gz
    
    # 替换二进制文件
    mv sing-box-*/sing-box "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sing-box"
    
    # 重启服务
    systemctl start sing-box
    
    if systemctl is-active --quiet sing-box; then
        log "sing-box 更新完成！当前版本: $SING_BOX_VERSION"
    else
        error "更新后服务启动失败，正在恢复备份..."
        rm -rf "$CONFIG_DIR"
        mv "$CONFIG_DIR.backup."* "$CONFIG_DIR"
        systemctl start sing-box
    fi
}

# 卸载 SBall
uninstall_sball() {
    echo -e "${YELLOW}警告: 此操作将完全卸载 SBall 及其所有配置！${NC}"
    read -p "确定要卸载吗? (y/n): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log "卸载 SBall..."
        
        # 停止并禁用服务
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        
        # 删除文件
        rm -f "$SERVICE_FILE"
        rm -f "$INSTALL_DIR/sing-box"
        rm -rf "$CONFIG_DIR"
        rm -f "$LOG_FILE"
        
        systemctl daemon-reload
        
        log "SBall 已完全卸载"
        echo -e "${YELLOW}请手动删除安装脚本: rm -f $0${NC}"
        echo -e "${YELLOW}如需清理防火墙规则，请手动执行相关命令${NC}"
    else
        log "取消卸载操作"
    fi
}

# 查看服务状态
show_status() {
    echo -e "${CYAN}=== 服务状态 ===${NC}"
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ sing-box 服务正在运行${NC}"
    else
        echo -e "${RED}✗ sing-box 服务已停止${NC}"
    fi
    
    echo
    systemctl status sing-box --no-pager -l
    
    echo
    echo -e "${CYAN}=== 端口监听状态 ===${NC}"
    
    if [[ -f "$CONFIG_DIR/nodes.txt" ]]; then
        for protocol in "${PROTOCOLS[@]}"; do
            local port=$(grep -o ":[0-9]\+" "$CONFIG_DIR/nodes.txt" | head -1 | tr -d ':')
            if [[ -n "$port" ]]; then
                if netstat -tlnp | grep -q ":$port "; then
                    echo -e "${GREEN}✓ $protocol (端口 $port) - 监听中${NC}"
                else
                    echo -e "${RED}✗ $protocol (端口 $port) - 未监听${NC}"
                fi
            fi
        done
    fi
}

# 查看服务日志
show_logs() {
    echo -e "${CYAN}=== sing-box 服务日志 ===${NC}"
    echo -e "${YELLOW}按 Ctrl+C 退出日志查看${NC}"
    echo
    journalctl -u sing-box -f --no-pager
}

# 启动服务
start_service() {
    log "启动 sing-box 服务..."
    systemctl start sing-box
    
    if systemctl is-active --quiet sing-box; then
        log "服务启动成功"
    else
        error "服务启动失败"
        systemctl status sing-box --no-pager -l
    fi
}

# 停止服务
stop_service() {
    log "停止 sing-box 服务..."
    systemctl stop sing-box
    
    if ! systemctl is-active --quiet sing-box; then
        log "服务已停止"
    else
        error "服务停止失败"
    fi
}

# 重启服务
restart_service() {
    log "重启 sing-box 服务..."
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        log "服务重启成功"
    else
        error "服务重启失败"
        systemctl status sing-box --no-pager -l
    fi
}

# 测试配置
test_config() {
    log "测试配置文件..."
    
    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        error "配置文件不存在"
        return 1
    fi
    
    if "$INSTALL_DIR/sing-box" check -c "$CONFIG_DIR/config.json"; then
        log "配置文件测试通过"
        return 0
    else
        error "配置文件测试失败"
        return 1
    fi
}

# 修复安装问题
fix_installation() {
    log "修复安装问题..."
    
    # 安装缺失的依赖
    log "安装 socat..."
    apt update -qq
    apt install -y socat cron
    
    # 重新生成证书
    log "重新生成证书..."
    generate_certificates
    
    # 重新生成配置
    log "重新生成配置..."
    generate_all_configs
    
    # 创建服务（如果不存在）
    if [[ ! -f "$SERVICE_FILE" ]]; then
        create_systemd_service
    fi
    
    # 配置防火墙
    configure_firewall
    
    log "修复完成，正在启动服务..."
    systemctl daemon-reload
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        log "服务启动成功！"
        show_node_info
    else
        error "服务启动失败，请查看日志"
        systemctl status sing-box --no-pager -l
    fi
}

# 备份配置
backup_config() {
    local backup_file="/root/sball_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    log "备份配置到 $backup_file..."
    
    tar -czf "$backup_file" -C / \
        "etc/sing-box" \
        "etc/systemd/system/sing-box.service" \
        "usr/local/bin/sing-box" 2>/dev/null
    
    if [[ -f "$backup_file" ]]; then
        log "备份完成: $backup_file"
    else
        error "备份失败"
    fi
}

# 恢复配置
restore_config() {
    echo "可用的备份文件:"
    ls -la /root/sball_backup_*.tar.gz 2>/dev/null || {
        warn "未找到备份文件"
        return 1
    }
    
    echo
    read -p "请输入要恢复的备份文件完整路径: " backup_file
    
    if [[ ! -f "$backup_file" ]]; then
        error "备份文件不存在"
        return 1
    fi
    
    log "从 $backup_file 恢复配置..."
    
    # 停止服务
    systemctl stop sing-box 2>/dev/null || true
    
    # 恢复文件
    tar -xzf "$backup_file" -C /
    
    # 重新加载并启动
    systemctl daemon-reload
    systemctl start sing-box
    
    if systemctl is-active --quiet sing-box; then
        log "配置恢复成功"
    else
        error "配置恢复失败"
    fi
}

# 流量统计（简单实现）
show_traffic_stats() {
    echo -e "${CYAN}=== 流量统计 ===${NC}"
    
    if command -v vnstat >/dev/null 2>&1; then
        vnstat -i eth0
    else
        echo -e "${YELLOW}安装 vnstat 以查看详细流量统计:${NC}"
        echo "apt install vnstat"
        echo
        echo -e "${BLUE}当前网络接口流量:${NC}"
        cat /proc/net/dev | grep -E "eth0|ens|venet" | head -3
    fi
}

# 系统信息
show_system_info() {
    echo -e "${CYAN}=== 系统信息 ===${NC}"
    echo -e "${BLUE}操作系统:${NC} $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo -e "${BLUE}内核版本:${NC} $(uname -r)"
    echo -e "${BLUE}架构:${NC} $(uname -m)"
    echo -e "${BLUE}CPU:${NC} $(nproc) 核心"
    echo -e "${BLUE}内存:${NC} $(free -h | awk '/^Mem:/ {print $2}')"
    echo -e "${BLUE}磁盘:${NC} $(df -h / | awk 'NR==2 {print $2 " (可用: " $4 ")"}')"
    echo -e "${BLUE}服务器IP:${NC} $SERVER_IP"
    
    if [[ -f "$CONFIG_DIR/config.json" ]]; then
        echo -e "${BLUE}sing-box版本:${NC} $($INSTALL_DIR/sing-box version 2>/dev/null | head -1 || echo "未安装")"
        echo -e "${BLUE}配置文件:${NC} $CONFIG_DIR/config.json"
        echo -e "${BLUE}协议数量:${NC} ${#PROTOCOLS[@]}"
    fi
}

# 检查更新
check_updates() {
    log "检查 sing-box 更新..."
    
    local latest_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    local current_version=$($INSTALL_DIR/sing-box version 2>/dev/null | head -1 | grep -o 'sing-box version [0-9.]*' | awk '{print $3}' || echo "unknown")
    
    echo -e "${BLUE}当前版本:${NC} $current_version"
    echo -e "${BLUE}最新版本:${NC} $latest_version"
    
    if [[ "$current_version" != "$latest_version" && "$latest_version" != "null" ]]; then
        echo -e "${YELLOW}发现新版本！${NC}"
        read -p "是否立即更新? (y/n): " update_now
        if [[ "$update_now" =~ ^[Yy]$ ]]; then
            SING_BOX_VERSION="$latest_version"
            SING_BOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-amd64.tar.gz"
            update_singbox
        fi
    else
        log "当前已是最新版本"
    fi
}

# 主菜单
show_menu() {
    clear
    show_banner
    
    # 检查安装状态
    local installed=false
    if [[ -f "$INSTALL_DIR/sing-box" && -f "$CONFIG_DIR/config.json" ]]; then
        installed=true
        local status_color=""
        if systemctl is-active --quiet sing-box; then
            status_color="${GREEN}"
            local status="运行中"
        else
            status_color="${RED}"
            local status="已停止"
        fi
        echo -e "${BLUE}服务状态:${NC} ${status_color}${status}${NC}"
        echo -e "${BLUE}服务器IP:${NC} $SERVER_IP"
        echo
    fi
    
    echo -e "${CYAN}=== SBall 管理菜单 ===${NC}"
    
    if [[ "$installed" == false ]]; then
        echo -e "${GREEN}1.${NC} 安装 SBall"
    else
        echo -e "${GREEN}1.${NC} 重新安装"
        echo -e "${GREEN}2.${NC} 更新 sing-box"
        echo -e "${GREEN}3.${NC} 卸载"
        echo -e "${GREEN}4.${NC} 查看节点信息"
        echo -e "${GREEN}5.${NC} 启动服务"
        echo -e "${GREEN}6.${NC} 停止服务"
        echo -e "${GREEN}7.${NC} 重启服务"
        echo -e "${GREEN}8.${NC} 查看服务状态"
        echo -e "${GREEN}9.${NC} 查看服务日志"
        echo -e "${YELLOW}10.${NC} 测试配置文件"
        echo -e "${YELLOW}11.${NC} 重新生成节点"
        echo -e "${YELLOW}12.${NC} 备份配置"
        echo -e "${YELLOW}13.${NC} 恢复配置"
        echo -e "${CYAN}14.${NC} 流量统计"
        echo -e "${CYAN}15.${NC} 系统信息"
        echo -e "${CYAN}16.${NC} 检查更新"
    fi
    
    echo -e "${RED}0.${NC} 退出"
    echo
}

# 主程序
main() {
    # 获取服务器IP
    get_server_ip 2>/dev/null || true
    
    # 如果没有参数，显示菜单
    if [[ $# -eq 0 ]]; then
        while true; do
            show_menu
            read -p "请选择操作 [0-16]: " choice
            
            case $choice in
                1)
                    install_sball
                    read -p "按回车键继续..."
                    ;;
                2)
                    if [[ -f "$INSTALL_DIR/sing-box" ]]; then
                        update_singbox
                    else
                        error "请先安装 SBall"
                    fi
                    read -p "按回车键继续..."
                    ;;
                3)
                    uninstall_sball
                    read -p "按回车键继续..."
                    ;;
                4)
                    if [[ -f "$CONFIG_DIR/nodes.txt" ]]; then
                        show_node_info
                    else
                        error "请先安装 SBall"
                    fi
                    read -p "按回车键继续..."
                    ;;
                5)
                    start_service
                    read -p "按回车键继续..."
                    ;;
                6)
                    stop_service
                    read -p "按回车键继续..."
                    ;;
                7)
                    restart_service
                    read -p "按回车键继续..."
                    ;;
                8)
                    show_status
                    read -p "按回车键继续..."
                    ;;
                9)
                    show_logs
                    ;;
                10)
                    test_config
                    read -p "按回车键继续..."
                    ;;
                11)
                    # 检查是否已安装
                    if [[ -f "$CONFIG_DIR/config.json" ]]; then
                        echo -e "${YELLOW}选择操作:${NC}"
                        echo "1. 重新生成节点（新端口新密钥）"
                        echo "2. 修复配置问题"
                        read -p "请选择 [1-2]: " sub_choice
                        case $sub_choice in
                            1)
                                generate_protocol_ports
                                generate_all_configs
                                restart_service
                                if systemctl is-active --quiet sing-box; then
                                    log "新节点生成完成！"
                                    show_node_info
                                else
                                    error "应用新配置失败"
                                fi
                                ;;
                            2)
                                regenerate_config
                                restart_service
                                ;;
                        esac
                    else
                        error "请先安装 SBall"
                    fi
                    read -p "按回车键继续..."
                    ;;
                12)
                    backup_config
                    read -p "按回车键继续..."
                    ;;
                13)
                    restore_config
                    read -p "按回车键继续..."
                    ;;
                14)
                    show_traffic_stats
                    read -p "按回车键继续..."
                    ;;
                15)
                    show_system_info
                    read -p "按回车键继续..."
                    ;;
                16)
                    check_updates
                    read -p "按回车键继续..."
                    ;;
                0)
                    log "感谢使用 SBall！"
                    exit 0
                    ;;
                *)
                    error "无效选择，请重新输入"
                    read -p "按回车键继续..."
                    ;;
            esac
        done
    fi
    
    # 命令行参数处理
    case "$1" in
        "install")
            install_sball
            ;;
        "uninstall")
            uninstall_sball
            ;;
        "update")
            update_singbox
            ;;
        "start")
            start_service
            ;;
        "stop")
            stop_service
            ;;
        "restart")
            restart_service
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs
            ;;
        "nodes")
            show_node_info
            ;;
        "backup")
            backup_config
            ;;
        "test")
            test_config
            ;;
        *)
            echo "SBall 科学上网代理管理脚本"
            echo
            echo "用法: $0 [命令]"
            echo
            echo "命令:"
            echo "  install   - 安装 SBall"
            echo "  uninstall - 卸载 SBall"
            echo "  update    - 更新 sing-box"
            echo "  start     - 启动服务"
            echo "  stop      - 停止服务"
            echo "  restart   - 重启服务"
            echo "  status    - 查看状态"
            echo "  logs      - 查看日志"
            echo "  nodes     - 查看节点信息"
            echo "  backup    - 备份配置"
            echo "  test      - 测试配置"
            echo
            echo "无参数运行进入交互式菜单"
            ;;
    esac
}

# 脚本入口点
main "$@"
