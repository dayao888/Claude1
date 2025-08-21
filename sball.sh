#!/bin/bash

# SBall科学上网代理工具脚本
# 型号：Claude 4 Sonnet
# 支持11种协议的多协议共存代理服务

# 脚本信息
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="SBall"
GITHUB_REPO="https://github.com/dayaocc/sball"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# 配置目录和文件
WORK_DIR="/etc/sball"
CONFIG_FILE="$WORK_DIR/config.json"
CERT_DIR="$WORK_DIR/cert"
SUB_DIR="$WORK_DIR/subscriptions"
LOG_FILE="/var/log/sball.log"
SERVICE_NAME="sball"

# Sing-box配置
SING_BOX_VERSION="1.12.0"
SING_BOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz"
SING_BOX_BIN="/usr/local/bin/sing-box"

# 协议配置
PROTOCOL_LIST=("VLESS-Reality" "Hysteria2" "TUIC" "ShadowTLS" "Shadowsocks" "Trojan" "VMess-WS" "VLESS-WS" "H2-Reality" "gRPC-Reality" "AnyTLS")
PROTOCOL_TAGS=("vless-reality" "hysteria2" "tuic" "shadowtls" "shadowsocks" "trojan" "vmess-ws" "vless-ws" "h2-reality" "grpc-reality" "anytls")

# 端口配置
START_PORT=10000
MAX_PORT=65535

# Reality目标域名列表
REALITY_DOMAINS=("www.microsoft.com" "www.cloudflare.com" "www.apple.com" "www.amazon.com" "www.google.com")

# 全局变量
SERVER_IP=""
DOMAIN_NAME=""
SELECTED_PROTOCOLS=()
PROTOCOL_PORTS=()
PROTOCOL_CONFIGS=()

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

# 检查系统环境
check_system() {
    log_info "检查系统环境..."
    
    # 检查操作系统
    if [[ ! -f /etc/os-release ]]; then
        log_error "不支持的操作系统"
        exit 1
    fi
    
    source /etc/os-release
    log_info "检测到系统: $PRETTY_NAME"
    
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        echo -e "${RED}请使用以下命令运行:${NC}"
        echo -e "${YELLOW}sudo bash $0${NC}"
        exit 1
    fi
    
    # 检查系统架构
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64)
            log_info "系统架构: x86_64"
            ;;
        aarch64|arm64)
            log_info "系统架构: ARM64"
            log_warn "ARM64架构可能需要不同的二进制文件"
            ;;
        *)
            log_warn "未测试的系统架构: $arch，可能存在兼容性问题"
            ;;
    esac
    
    # 检查网络连接
    log_info "检查网络连接..."
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log_error "网络连接失败，请检查网络设置"
        exit 1
    fi
    
    # 获取服务器IP
    log_info "获取服务器IP地址..."
    SERVER_IP=$(curl -s --connect-timeout 10 ipv4.icanhazip.com || curl -s --connect-timeout 10 ifconfig.me || curl -s --connect-timeout 10 ipinfo.io/ip)
    if [[ -z "$SERVER_IP" ]]; then
        log_error "无法获取服务器IP地址"
        log_error "请检查网络连接或手动设置SERVER_IP变量"
        exit 1
    fi
    
    # 验证IP地址格式
    if [[ ! $SERVER_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "获取到的IP地址格式不正确: $SERVER_IP"
        exit 1
    fi
    
    log_info "系统检查完成，服务器IP: $SERVER_IP"
}

# 安装依赖
install_dependencies() {
    log_info "安装系统依赖..."
    
    # 更新包管理器
    if command -v apt &> /dev/null; then
        apt update -y
        apt install -y curl wget unzip tar jq openssl ufw fail2ban
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y curl wget unzip tar jq openssl firewalld fail2ban
    else
        log_error "不支持的包管理器"
        exit 1
    fi
    
    log_info "依赖安装完成"
}

# 安装Sing-box
install_singbox() {
    log_info "安装Sing-box..."
    
    # 检查是否已安装
    if [[ -f "$SING_BOX_BIN" ]]; then
        local current_version=$("$SING_BOX_BIN" version 2>/dev/null | head -n1 | awk '{print $3}' || echo "unknown")
        log_info "当前Sing-box版本: $current_version"
        
        if [[ "$current_version" == "$SING_BOX_VERSION" ]]; then
            log_info "Sing-box已是最新版本"
            return 0
        fi
    fi
    
    # 检测系统架构
    local arch=$(uname -m)
    local download_arch
    case $arch in
        x86_64|amd64)
            download_arch="amd64"
            ;;
        aarch64|arm64)
            download_arch="arm64"
            ;;
        armv7l)
            download_arch="armv7"
            ;;
        *)
            log_error "不支持的系统架构: $arch"
            exit 1
            ;;
    esac
    
    # 构建下载URL
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${download_arch}.tar.gz"
    local temp_file="/tmp/sing-box.tar.gz"
    
    log_info "下载Sing-box v$SING_BOX_VERSION ($download_arch)..."
    
    # 下载文件
    if ! curl -L "$download_url" -o "$temp_file" --connect-timeout 30 --max-time 300; then
        log_error "下载Sing-box失败"
        exit 1
    fi
    
    # 解压并安装
    local temp_dir="/tmp/sing-box-extract"
    mkdir -p "$temp_dir"
    
    if ! tar -xzf "$temp_file" -C "$temp_dir" --strip-components=1; then
        log_error "解压Sing-box失败"
        exit 1
    fi
    
    # 复制二进制文件
    if [[ -f "$temp_dir/sing-box" ]]; then
        cp "$temp_dir/sing-box" "$SING_BOX_BIN"
        chmod +x "$SING_BOX_BIN"
    else
        log_error "找不到Sing-box二进制文件"
        exit 1
    fi
    
    # 清理临时文件
    rm -rf "$temp_file" "$temp_dir"
    
    # 验证安装
    if "$SING_BOX_BIN" version &> /dev/null; then
        local installed_version=$("$SING_BOX_BIN" version | head -n1 | awk '{print $3}')
        log_info "Sing-box安装成功，版本: $installed_version"
    else
        log_error "Sing-box安装验证失败"
        exit 1
    fi
}



# 创建工作目录
create_directories() {
    log_info "创建工作目录..."
    
    mkdir -p "$WORK_DIR" "$CERT_DIR" "$SUB_DIR"
    touch "$LOG_FILE"
    
    log_info "目录创建完成"
}

# 生成UUID
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 生成随机密码
generate_password() {
    openssl rand -base64 16
}

# 检查端口占用
check_port() {
    local port=$1
    if ss -tuln | grep -q ":$port "; then
        return 1
    fi
    return 0
}

# 分配端口
allocate_ports() {
    log_info "分配协议端口..."
    
    local current_port=$START_PORT
    PROTOCOL_PORTS=()
    
    for protocol in "${SELECTED_PROTOCOLS[@]}"; do
        while ! check_port $current_port && [[ $current_port -le $MAX_PORT ]]; do
            ((current_port++))
        done
        
        if [[ $current_port -gt $MAX_PORT ]]; then
            log_error "无可用端口"
            exit 1
        fi
        
        PROTOCOL_PORTS+=("$current_port")
        log_info "$protocol 分配端口: $current_port"
        ((current_port++))
    done
}

# 生成Reality密钥对
generate_reality_keys() {
    local keys=$("$SING_BOX_BIN" generate reality-keypair)
    echo "$keys"
}

# 生成协议配置
generate_protocol_config() {
    local protocol=$1
    local port=$2
    local uuid=$3
    local password=$4
    local short_id=$(openssl rand -hex 8)
    
    case $protocol in
        "VLESS-Reality")
            local reality_keys=$(generate_reality_keys)
            local private_key=$(echo "$reality_keys" | grep "PrivateKey" | awk '{print $2}')
            local public_key=$(echo "$reality_keys" | grep "PublicKey" | awk '{print $2}')
            local target_domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
            
            cat << EOF
{
  "type": "vless",
  "tag": "vless-reality",
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
    "server_name": "$target_domain",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "$target_domain",
        "server_port": 443
      },
      "private_key": "$private_key",
      "short_id": ["$short_id"]
    }
  },
  "multiplex": {
    "enabled": true,
    "protocol": "h2mux",
    "max_connections": 4,
    "min_streams": 4,
    "max_streams": 0
  }
}
EOF
            ;;
        "Hysteria2")
            cat << EOF
{
  "type": "hysteria2",
  "tag": "hysteria2",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "password": "$password"
    }
  ],
  "ignore_client_bandwidth": false,
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "certificate_path": "$CERT_DIR/cert.pem",
    "key_path": "$CERT_DIR/key.pem"
  },
  "brutal": {
    "enabled": true,
    "up_mbps": 100,
    "down_mbps": 100
  }
}
EOF
            ;;
        "TUIC")
            cat << EOF
{
  "type": "tuic",
  "tag": "tuic",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$uuid",
      "password": "$password"
    }
  ],
  "congestion_control": "cubic",
  "zero_rtt_handshake": false,
  "heartbeat": "10s",
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "certificate_path": "$CERT_DIR/cert.pem",
    "key_path": "$CERT_DIR/key.pem"
  }
}
EOF
            ;;
        "ShadowTLS")
            cat << EOF
{
  "type": "shadowtls",
  "tag": "shadowtls",
  "listen": "::",
  "listen_port": $port,
  "version": 3,
  "users": [
    {
      "password": "$password"
    }
  ],
  "handshake": {
    "server": "www.microsoft.com",
    "server_port": 443
  },
  "strict_mode": true,
  "detour": "shadowsocks-in"
}
EOF
            ;;
        "Shadowsocks")
            cat << EOF
{
  "type": "shadowsocks",
  "tag": "shadowsocks",
  "listen": "::",
  "listen_port": $port,
  "method": "2022-blake3-aes-128-gcm",
  "password": "$password",
  "multiplex": {
    "enabled": true,
    "protocol": "h2mux",
    "max_connections": 4,
    "min_streams": 4,
    "max_streams": 0
  }
}
EOF
            ;;
        "Trojan")
            cat << EOF
{
  "type": "trojan",
  "tag": "trojan",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "password": "$password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "$CERT_DIR/cert.pem",
    "key_path": "$CERT_DIR/key.pem"
  },
  "multiplex": {
    "enabled": true,
    "protocol": "h2mux",
    "max_connections": 4,
    "min_streams": 4,
    "max_streams": 0
  }
}
EOF
            ;;
        "VMess-WS")
            cat << EOF
{
  "type": "vmess",
  "tag": "vmess-ws",
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
    "path": "/vmess",
    "headers": {
      "Host": "$SERVER_IP"
    }
  },
  "multiplex": {
    "enabled": true,
    "protocol": "h2mux",
    "max_connections": 4,
    "min_streams": 4,
    "max_streams": 0
  }
}
EOF
            ;;
        "VLESS-WS")
            cat << EOF
{
  "type": "vless",
  "tag": "vless-ws",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$uuid",
      "flow": ""
    }
  ],
  "transport": {
    "type": "ws",
    "path": "/vless",
    "headers": {
      "Host": "$SERVER_IP"
    }
  },
  "tls": {
    "enabled": true,
    "certificate_path": "$CERT_DIR/cert.pem",
    "key_path": "$CERT_DIR/key.pem"
  },
  "multiplex": {
    "enabled": true,
    "protocol": "h2mux",
    "max_connections": 4,
    "min_streams": 4,
    "max_streams": 0
  }
}
EOF
            ;;
        "H2-Reality")
            local reality_keys=$(generate_reality_keys)
            local private_key=$(echo "$reality_keys" | grep "PrivateKey" | awk '{print $2}')
            local target_domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
            
            cat << EOF
{
  "type": "vless",
  "tag": "h2-reality",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$uuid",
      "flow": ""
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$target_domain",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "$target_domain",
        "server_port": 443
      },
      "private_key": "$private_key",
      "short_id": ["$short_id"]
    }
  },
  "transport": {
    "type": "http",
    "host": ["$target_domain"],
    "path": "/"
  }
}
EOF
            ;;
        "gRPC-Reality")
            local reality_keys=$(generate_reality_keys)
            local private_key=$(echo "$reality_keys" | grep "PrivateKey" | awk '{print $2}')
            local target_domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
            
            cat << EOF
{
  "type": "vless",
  "tag": "grpc-reality",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$uuid",
      "flow": ""
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$target_domain",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "$target_domain",
        "server_port": 443
      },
      "private_key": "$private_key",
      "short_id": ["$short_id"]
    }
  },
  "transport": {
    "type": "grpc",
    "service_name": "grpc"
  }
}
EOF
            ;;
        "AnyTLS")
            cat << EOF
{
  "type": "anytls",
  "tag": "anytls",
  "listen": "::",
  "listen_port": $port,
  "password": "$uuid",
  "tls": {
    "enabled": true,
    "certificate_path": "$CERT_DIR/cert.pem",
    "key_path": "$CERT_DIR/key.pem"
  }
}
EOF
            ;;
        *)
            log_error "不支持的协议: $protocol"
            return 1
            ;;
    esac
}

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${CYAN}================================${NC}"
    echo -e "${WHITE}    $SCRIPT_NAME 管理面板 v$SCRIPT_VERSION${NC}"
    echo -e "${CYAN}================================${NC}"
    echo -e "${PURPLE}支持11种协议的多协议共存代理服务${NC}"
    echo -e "${PURPLE}GitHub: $GITHUB_REPO${NC}"
    echo
    
    # 显示服务状态
    local service_status=$(systemctl is-active $SERVICE_NAME 2>/dev/null || echo "未安装")
    local sub_status=$(systemctl is-active sball-subscription 2>/dev/null || echo "未安装")
    
    echo -e "${YELLOW}当前状态:${NC}"
    echo -e "  代理服务: ${service_status}"
    echo -e "  订阅服务: ${sub_status}"
    echo
    
    echo -e "${GREEN}1.${NC} 安装代理服务 ${GRAY}(支持11种协议)${NC}"
    echo -e "${GREEN}2.${NC} 更新 Sing-box ${GRAY}(更新到最新版本)${NC}"
    echo -e "${GREEN}3.${NC} 卸载服务 ${GRAY}(完全清理)${NC}"
    echo -e "${GREEN}4.${NC} 查看节点信息 ${GRAY}(显示连接信息)${NC}"
    echo -e "${GREEN}5.${NC} 启动服务 ${GRAY}(启动代理)${NC}"
    echo -e "${GREEN}6.${NC} 停止服务 ${GRAY}(停止代理)${NC}"
    echo -e "${GREEN}7.${NC} 查看服务状态 ${GRAY}(检查运行状态)${NC}"
    echo -e "${GREEN}8.${NC} 查看服务日志 ${GRAY}(查看运行日志)${NC}"
    echo -e "${GREEN}9.${NC} 重启服务 ${GRAY}(重启代理服务)${NC}"
    echo -e "${GREEN}10.${NC} Fail2ban管理 ${GRAY}(防护设置)${NC}"
    echo -e "${GREEN}0.${NC} 退出脚本"
    echo
    echo -e "${CYAN}================================${NC}"
}

# 协议选择菜单
select_protocols() {
    clear
    echo -e "${CYAN}选择要安装的协议${NC}"
    echo -e "${YELLOW}提示: 输入数字选择协议，多个协议用空格分隔${NC}"
    echo
    
    for i in "${!PROTOCOL_LIST[@]}"; do
        echo -e "${GREEN}$((i+1)).${NC} ${PROTOCOL_LIST[i]}"
    done
    echo -e "${GREEN}0.${NC} 安装全部协议"
    echo
    
    read -p "请选择协议 (例如: 1 2 3): " selection
    
    SELECTED_PROTOCOLS=()
    if [[ "$selection" == "0" ]]; then
        SELECTED_PROTOCOLS=("${PROTOCOL_LIST[@]}")
    else
        for num in $selection; do
            if [[ $num -ge 1 && $num -le ${#PROTOCOL_LIST[@]} ]]; then
                SELECTED_PROTOCOLS+=("${PROTOCOL_LIST[$((num-1))]}")
            fi
        done
    fi
    
    if [[ ${#SELECTED_PROTOCOLS[@]} -eq 0 ]]; then
        log_error "未选择任何协议"
        return 1
    fi
    
    log_info "已选择协议: ${SELECTED_PROTOCOLS[*]}"
}

# 安装服务
install_service() {
    log_info "开始安装SBall代理服务..."
    
    # 检查系统
    check_system
    
    # 安装依赖
    install_dependencies
    
    # 安装Sing-box
    install_singbox
    
    # 创建目录
    create_directories
    
    # 选择协议
    if ! select_protocols; then
        return 1
    fi
    
    # 分配端口
    allocate_ports
    
    # 生成证书
    generate_certificates
    
    # 生成配置
    generate_main_config
    
    # 创建系统服务
    create_systemd_service
    
    # 配置防火墙和安全防护
    configure_firewall
    
    # IP优化和保护
    optimize_ip_protection
    
    # 保存配置信息
    save_config_info
    
    # 启动服务
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "SBall代理服务安装完成并成功启动！"
        
        # 显示节点信息
        show_node_info
    else
        log_error "服务启动失败，请检查配置和日志"
        systemctl status "$SERVICE_NAME" --no-pager
        return 1
    fi
}

# 生成自签证书
generate_certificates() {
    log_info "生成SSL证书..."
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"
    
    chmod 600 "$CERT_DIR/key.pem"
    chmod 644 "$CERT_DIR/cert.pem"
    
    log_info "证书生成完成"
}

# 生成主配置文件
generate_main_config() {
    log_info "生成Sing-box配置文件..."
    
    # 生成所有协议配置
    local inbounds="["
    local first=true
    
    for i in "${!SELECTED_PROTOCOLS[@]}"; do
        local protocol="${SELECTED_PROTOCOLS[i]}"
        local port="${PROTOCOL_PORTS[i]}"
        local uuid=$(generate_uuid)
        local password=$(generate_password)
        
        if [[ "$first" == "true" ]]; then
            first=false
        else
            inbounds="$inbounds,"
        fi
        
        local config=$(generate_protocol_config "$protocol" "$port" "$uuid" "$password")
        inbounds="$inbounds$config"
        
        # 保存协议配置信息用于后续显示
        PROTOCOL_CONFIGS[i]="$protocol:$port:$uuid:$password"
    done
    
    # 为ShadowTLS添加内部Shadowsocks入站
    for protocol in "${SELECTED_PROTOCOLS[@]}"; do
        if [[ "$protocol" == "ShadowTLS" ]]; then
            inbounds="$inbounds,{
  \"type\": \"shadowsocks\",
  \"tag\": \"shadowsocks-in\",
  \"listen\": \"127.0.0.1\",
  \"listen_port\": 8080,
  \"method\": \"2022-blake3-aes-128-gcm\",
  \"password\": \"$(generate_password)\"
}"
            break
        fi
    done
    
    inbounds="$inbounds]"
    
    cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
  },
  "inbounds": $inbounds,
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
    
    log_info "配置文件生成完成"
}

# 创建系统服务
create_systemd_service() {
    log_info "创建系统服务..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=SBall Proxy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$SING_BOX_BIN run -c $CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_info "系统服务创建完成"
}

# 配置防火墙和安全防护
configure_firewall() {
    log_info "配置防火墙规则和安全防护..."
    
    # 开放协议端口
    for port in "${PROTOCOL_PORTS[@]}"; do
        ufw allow "$port"
    done
    
    # 开放订阅服务端口
    ufw allow 8000
    
    # 配置fail2ban防护
    configure_fail2ban
    
    # 配置BBR加速
    configure_bbr
    
    # 启用防火墙
    ufw --force enable
    
    log_info "防火墙和安全防护配置完成"
}

# 配置fail2ban防护（默认关闭）
configure_fail2ban() {
    log_info "配置fail2ban防护（默认关闭状态）..."
    
    # 检测系统类型以确定正确的日志路径
    local ssh_log_path="/var/log/auth.log"
    if [[ -f "/var/log/secure" ]]; then
        ssh_log_path="/var/log/secure"  # CentOS/RHEL
    fi
    
    # 获取当前服务器IP作为白名单
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    
    # 创建fail2ban配置
    cat > "/etc/fail2ban/jail.d/sball.conf" << EOF
[DEFAULT]
# 白名单设置 - 包含服务器IP和常用内网段
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 $server_ip

[sball-ssh]
# SSH防护 - 默认关闭，可通过管理菜单启用
enabled = false
port = ssh
filter = sshd
logpath = $ssh_log_path
maxretry = 5
bantime = 3600
findtime = 600

[sball-proxy]
# 代理服务防护 - 默认关闭，可通过管理菜单启用
enabled = false
port = ${PROTOCOL_PORTS[*]}
filter = sball-proxy
logpath = $LOG_FILE
maxretry = 10
bantime = 1800
findtime = 300
EOF
    
    # 创建代理过滤规则
    cat > "/etc/fail2ban/filter.d/sball-proxy.conf" << EOF
[Definition]
failregex = ^.*\[ERROR\].*from <HOST>.*$
            ^.*connection failed.*from <HOST>.*$
            ^.*authentication failed.*from <HOST>.*$
ignoreregex =
EOF
    
    # 安装并启用fail2ban服务，但jail默认关闭
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_info "fail2ban防护配置完成（默认关闭状态，可通过菜单管理）"
}

# Fail2ban管理菜单
manage_fail2ban() {
    while true; do
        clear
        echo -e "${CYAN}================================${NC}"
        echo -e "${WHITE}    Fail2ban 防护管理${NC}"
        echo -e "${CYAN}================================${NC}"
        echo
        
        # 检查fail2ban服务状态
        local fail2ban_status=$(systemctl is-active fail2ban 2>/dev/null || echo "未安装")
        local ssh_jail_status="未知"
        local proxy_jail_status="未知"
        
        if [[ "$fail2ban_status" == "active" ]]; then
            ssh_jail_status=$(fail2ban-client status sball-ssh 2>/dev/null | grep "Status" | awk '{print $2}' || echo "关闭")
            proxy_jail_status=$(fail2ban-client status sball-proxy 2>/dev/null | grep "Status" | awk '{print $2}' || echo "关闭")
        fi
        
        echo -e "${YELLOW}当前状态:${NC}"
        echo -e "  Fail2ban服务: $fail2ban_status"
        echo -e "  SSH防护: $ssh_jail_status"
        echo -e "  代理防护: $proxy_jail_status"
        echo
        
        echo -e "${GREEN}1.${NC} 启用SSH防护 ${GRAY}(防止SSH暴力破解)${NC}"
        echo -e "${GREEN}2.${NC} 关闭SSH防护 ${GRAY}(停止SSH监控)${NC}"
        echo -e "${GREEN}3.${NC} 启用代理防护 ${GRAY}(防止代理服务攻击)${NC}"
        echo -e "${GREEN}4.${NC} 关闭代理防护 ${GRAY}(停止代理监控)${NC}"
        echo -e "${GREEN}5.${NC} 查看封禁列表 ${GRAY}(显示被封IP)${NC}"
        echo -e "${GREEN}6.${NC} 解封指定IP ${GRAY}(手动解除封禁)${NC}"
        echo -e "${GREEN}7.${NC} 添加白名单IP ${GRAY}(永久信任IP)${NC}"
        echo -e "${GREEN}8.${NC} 查看配置信息 ${GRAY}(显示当前设置)${NC}"
        echo -e "${GREEN}9.${NC} 重置为推荐配置 ${GRAY}(恢复安全设置)${NC}"
        echo -e "${GREEN}0.${NC} 返回主菜单"
        echo
        echo -e "${CYAN}================================${NC}"
        
        read -p "请选择操作 [0-9]: " choice
        
        case $choice in
            1)
                enable_ssh_protection
                ;;
            2)
                disable_ssh_protection
                ;;
            3)
                enable_proxy_protection
                ;;
            4)
                disable_proxy_protection
                ;;
            5)
                show_banned_ips
                ;;
            6)
                unban_ip
                ;;
            7)
                add_whitelist_ip
                ;;
            8)
                show_fail2ban_config
                ;;
            9)
                reset_fail2ban_config
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}无效选项，请重新选择${NC}"
                ;;
        esac
        
        if [[ $choice != 0 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

# 启用SSH防护
enable_ssh_protection() {
    log_info "启用SSH防护..."
    
    if ! systemctl is-active --quiet fail2ban; then
        log_error "Fail2ban服务未运行，请先安装代理服务"
        return 1
    fi
    
    # 修改配置文件启用SSH jail
    sed -i '/\[sball-ssh\]/,/^\[/ s/enabled = false/enabled = true/' /etc/fail2ban/jail.d/sball.conf
    
    # 重新加载配置
    fail2ban-client reload sball-ssh 2>/dev/null || fail2ban-client restart
    
    log_info "SSH防护已启用"
    echo -e "${GREEN}SSH防护已启用，将监控SSH登录失败尝试${NC}"
    echo -e "${YELLOW}配置: 5次失败尝试后封禁1小时${NC}"
}

# 关闭SSH防护
disable_ssh_protection() {
    log_info "关闭SSH防护..."
    
    if ! systemctl is-active --quiet fail2ban; then
        log_warn "Fail2ban服务未运行"
        return 1
    fi
    
    # 修改配置文件关闭SSH jail
    sed -i '/\[sball-ssh\]/,/^\[/ s/enabled = true/enabled = false/' /etc/fail2ban/jail.d/sball.conf
    
    # 停止jail并重新加载
    fail2ban-client stop sball-ssh 2>/dev/null
    fail2ban-client reload 2>/dev/null
    
    log_info "SSH防护已关闭"
    echo -e "${YELLOW}SSH防护已关闭，不再监控SSH登录${NC}"
}

# 启用代理防护
enable_proxy_protection() {
    log_info "启用代理防护..."
    
    if ! systemctl is-active --quiet fail2ban; then
        log_error "Fail2ban服务未运行，请先安装代理服务"
        return 1
    fi
    
    # 修改配置文件启用代理jail
    sed -i '/\[sball-proxy\]/,/^\[/ s/enabled = false/enabled = true/' /etc/fail2ban/jail.d/sball.conf
    
    # 重新加载配置
    fail2ban-client reload sball-proxy 2>/dev/null || fail2ban-client restart
    
    log_info "代理防护已启用"
    echo -e "${GREEN}代理防护已启用，将监控代理服务异常连接${NC}"
    echo -e "${YELLOW}配置: 10次失败尝试后封禁30分钟${NC}"
}

# 关闭代理防护
disable_proxy_protection() {
    log_info "关闭代理防护..."
    
    if ! systemctl is-active --quiet fail2ban; then
        log_warn "Fail2ban服务未运行"
        return 1
    fi
    
    # 修改配置文件关闭代理jail
    sed -i '/\[sball-proxy\]/,/^\[/ s/enabled = true/enabled = false/' /etc/fail2ban/jail.d/sball.conf
    
    # 停止jail并重新加载
    fail2ban-client stop sball-proxy 2>/dev/null
    fail2ban-client reload 2>/dev/null
    
    log_info "代理防护已关闭"
    echo -e "${YELLOW}代理防护已关闭，不再监控代理服务${NC}"
}

# 查看封禁列表
show_banned_ips() {
    echo -e "${CYAN}当前封禁IP列表:${NC}"
    echo
    
    if ! systemctl is-active --quiet fail2ban; then
        echo -e "${RED}Fail2ban服务未运行${NC}"
        return 1
    fi
    
    # 显示SSH jail封禁列表
    echo -e "${YELLOW}SSH防护封禁列表:${NC}"
    local ssh_banned=$(fail2ban-client status sball-ssh 2>/dev/null | grep "Banned IP list" | cut -d: -f2 | xargs)
    if [[ -n "$ssh_banned" && "$ssh_banned" != "" ]]; then
        echo "  $ssh_banned"
    else
        echo -e "  ${GRAY}无封禁IP${NC}"
    fi
    echo
    
    # 显示代理jail封禁列表
    echo -e "${YELLOW}代理防护封禁列表:${NC}"
    local proxy_banned=$(fail2ban-client status sball-proxy 2>/dev/null | grep "Banned IP list" | cut -d: -f2 | xargs)
    if [[ -n "$proxy_banned" && "$proxy_banned" != "" ]]; then
        echo "  $proxy_banned"
    else
        echo -e "  ${GRAY}无封禁IP${NC}"
    fi
    echo
    
    # 显示总体统计
    echo -e "${CYAN}封禁统计:${NC}"
    fail2ban-client status 2>/dev/null | grep -E "Number of jail|Currently banned" || echo -e "${RED}无法获取统计信息${NC}"
}

# 解封指定IP
unban_ip() {
    echo -e "${CYAN}解封IP地址${NC}"
    echo
    
    if ! systemctl is-active --quiet fail2ban; then
        echo -e "${RED}Fail2ban服务未运行${NC}"
        return 1
    fi
    
    read -p "请输入要解封的IP地址: " ip_address
    
    if [[ -z "$ip_address" ]]; then
        echo -e "${RED}IP地址不能为空${NC}"
        return 1
    fi
    
    # 验证IP格式
    if ! [[ $ip_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${RED}IP地址格式不正确${NC}"
        return 1
    fi
    
    # 尝试从所有jail中解封
    local unban_success=false
    
    if fail2ban-client unban "$ip_address" 2>/dev/null; then
        unban_success=true
    fi
    
    if fail2ban-client set sball-ssh unbanip "$ip_address" 2>/dev/null; then
        unban_success=true
    fi
    
    if fail2ban-client set sball-proxy unbanip "$ip_address" 2>/dev/null; then
        unban_success=true
    fi
    
    if [[ "$unban_success" == "true" ]]; then
        log_info "IP $ip_address 已解封"
        echo -e "${GREEN}IP $ip_address 已成功解封${NC}"
    else
        echo -e "${YELLOW}IP $ip_address 可能未被封禁或解封失败${NC}"
    fi
}

# 添加白名单IP
add_whitelist_ip() {
    echo -e "${CYAN}添加白名单IP${NC}"
    echo
    
    read -p "请输入要添加到白名单的IP地址或网段 (例如: 192.168.1.100 或 192.168.1.0/24): " ip_input
    
    if [[ -z "$ip_input" ]]; then
        echo -e "${RED}IP地址不能为空${NC}"
        return 1
    fi
    
    # 检查配置文件是否存在
    if [[ ! -f "/etc/fail2ban/jail.d/sball.conf" ]]; then
        echo -e "${RED}Fail2ban配置文件不存在，请先安装代理服务${NC}"
        return 1
    fi
    
    # 获取当前白名单
    local current_whitelist=$(grep "ignoreip" /etc/fail2ban/jail.d/sball.conf | cut -d= -f2 | xargs)
    
    # 检查IP是否已在白名单中
    if echo "$current_whitelist" | grep -q "$ip_input"; then
        echo -e "${YELLOW}IP $ip_input 已在白名单中${NC}"
        return 0
    fi
    
    # 添加到白名单
    sed -i "/ignoreip/s/$/ $ip_input/" /etc/fail2ban/jail.d/sball.conf
    
    # 重新加载fail2ban配置
    if systemctl is-active --quiet fail2ban; then
        fail2ban-client reload 2>/dev/null
    fi
    
    log_info "IP $ip_input 已添加到白名单"
    echo -e "${GREEN}IP $ip_input 已成功添加到白名单${NC}"
    echo -e "${YELLOW}白名单中的IP永远不会被封禁${NC}"
}

# 查看配置信息
show_fail2ban_config() {
    echo -e "${CYAN}Fail2ban配置信息${NC}"
    echo
    
    if [[ ! -f "/etc/fail2ban/jail.d/sball.conf" ]]; then
        echo -e "${RED}配置文件不存在${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}当前配置:${NC}"
    echo
    
    # 显示白名单
    echo -e "${GREEN}白名单IP:${NC}"
    local whitelist=$(grep "ignoreip" /etc/fail2ban/jail.d/sball.conf | cut -d= -f2 | xargs)
    echo "  $whitelist"
    echo
    
    # 显示SSH配置
    echo -e "${GREEN}SSH防护配置:${NC}"
    grep -A 6 "\[sball-ssh\]" /etc/fail2ban/jail.d/sball.conf | grep -E "enabled|maxretry|bantime|findtime" | sed 's/^/  /'
    echo
    
    # 显示代理配置
    echo -e "${GREEN}代理防护配置:${NC}"
    grep -A 6 "\[sball-proxy\]" /etc/fail2ban/jail.d/sball.conf | grep -E "enabled|maxretry|bantime|findtime" | sed 's/^/  /'
    echo
    
    # 显示服务状态
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}Fail2ban服务状态: 运行中${NC}"
        fail2ban-client status 2>/dev/null | head -5
    else
        echo -e "${RED}Fail2ban服务状态: 未运行${NC}"
    fi
}

# 重置为推荐配置
reset_fail2ban_config() {
    echo -e "${CYAN}重置Fail2ban为推荐配置${NC}"
    echo -e "${YELLOW}这将恢复安全的默认设置${NC}"
    echo
    
    read -p "确认重置配置? [y/N]: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}取消重置操作${NC}"
        return 0
    fi
    
    log_info "重置Fail2ban配置..."
    
    # 检测系统类型以确定正确的日志路径
    local ssh_log_path="/var/log/auth.log"
    if [[ -f "/var/log/secure" ]]; then
        ssh_log_path="/var/log/secure"  # CentOS/RHEL
    fi
    
    # 获取当前服务器IP作为白名单
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
    
    # 重新生成推荐配置
    cat > "/etc/fail2ban/jail.d/sball.conf" << EOF
[DEFAULT]
# 白名单设置 - 包含服务器IP和常用内网段
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 $server_ip

[sball-ssh]
# SSH防护 - 推荐启用
enabled = true
port = ssh
filter = sshd
logpath = $ssh_log_path
maxretry = 5
bantime = 3600
findtime = 600

[sball-proxy]
# 代理服务防护 - 推荐关闭（避免误封）
enabled = false
port = ${PROTOCOL_PORTS[*]:-"10000-20000"}
filter = sball-proxy
logpath = $LOG_FILE
maxretry = 10
bantime = 1800
findtime = 300
EOF
    
    # 重新加载配置
    if systemctl is-active --quiet fail2ban; then
        fail2ban-client reload 2>/dev/null
    fi
    
    log_info "Fail2ban配置已重置为推荐设置"
    echo -e "${GREEN}配置已重置为推荐设置:${NC}"
    echo -e "  - SSH防护: 启用 (5次失败封禁1小时)"
    echo -e "  - 代理防护: 关闭 (避免误封)"
    echo -e "  - 白名单: 包含服务器IP和内网段"
}

# 配置BBR加速
configure_bbr() {
    log_info "配置BBR网络加速..."
    
    # 检查内核版本
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local major_version=$(echo $kernel_version | cut -d. -f1)
    local minor_version=$(echo $kernel_version | cut -d. -f2)
    
    if [[ $major_version -gt 4 ]] || [[ $major_version -eq 4 && $minor_version -ge 9 ]]; then
        # 启用BBR
        echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
        echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
        
        # 应用设置
        sysctl -p
        
        log_info "BBR加速已启用"
    else
        log_warn "内核版本过低，无法启用BBR加速"
    fi
}

# IP优化和伪装
optimize_ip_protection() {
    log_info "配置IP保护和流量伪装..."
    
    # 随机化端口范围
    local port_range_start=$((RANDOM % 10000 + 20000))
    local port_range_end=$((port_range_start + 1000))
    
    # 配置iptables规则进行流量伪装
    iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443
    
    # 保存iptables规则
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    # 配置系统参数优化
    cat >> /etc/sysctl.conf << EOF
# SBall网络优化
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 65536 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
EOF
    
    sysctl -p
    
    log_info "IP保护和流量优化配置完成"
}

# 保存配置信息
save_config_info() {
    log_info "保存配置信息..."
    
    # 构建JSON字符串
    local json_content='{
  "server_ip": "'$SERVER_IP'",
  "protocols": ['
    
    for i in "${!SELECTED_PROTOCOLS[@]}"; do
        local protocol="${SELECTED_PROTOCOLS[i]}"
        local port="${PROTOCOL_PORTS[i]}"
        # 从PROTOCOL_CONFIGS数组中提取UUID和密码
        local config="${PROTOCOL_CONFIGS[i]}"
        local uuid=$(echo "$config" | cut -d':' -f3)
        local password=$(echo "$config" | cut -d':' -f4)
        
        if [[ $i -gt 0 ]]; then
            json_content+=','
        fi
        
        json_content+='\n    {
      "name": "'$protocol'",
      "port": '$port',
      "uuid": "'$uuid'",
      "password": "'$password'"
    }'
    done
    
    json_content+='\n  ],
  "install_time": "'$(date '+%Y-%m-%d %H:%M:%S')'"\n}'
    
    # 写入文件
    echo -e "$json_content" > "$WORK_DIR/config_info.json"
    
    log_info "配置信息保存完成"
}

# 生成节点链接
generate_node_link() {
    local protocol=$1
    local port=$2
    local uuid=$3
    local password=$4
    local server_ip=${SERVER_IP}
    
    case $protocol in
        "VLESS-Reality")
            local reality_keys=$(generate_reality_keys)
            local public_key=$(echo "$reality_keys" | grep "PublicKey" | awk '{print $2}')
            local target_domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
            local short_id=$(openssl rand -hex 8)
            echo "vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${target_domain}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#VLESS-Reality-${server_ip}"
            ;;
        "Hysteria2")
            local target_domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]} 
            echo "hysteria2://${uuid}@${server_ip}:${port}?sni=${target_domain}&alpn=h3&insecure=1#Hysteria2-${server_ip}"
            ;;
        "TUIC")
            echo "tuic://${uuid}:${password}@${server_ip}:${port}?congestion_control=cubic&udp_relay_mode=native&alpn=h3&allow_insecure=1#TUIC"
            ;;
        "ShadowTLS")
            local ss_password=$(generate_password)
            echo "ss://$(echo -n "2022-blake3-aes-128-gcm:${ss_password}" | base64 -w 0)@${server_ip}:${port}?plugin=shadow-tls%3Bversion%3D3%3Bhost%3Dwww.microsoft.com%3Bpassword%3D${password}#ShadowTLS"
            ;;
        "Shadowsocks")
            echo "ss://$(echo -n "2022-blake3-aes-128-gcm:${password}" | base64 -w 0)@${server_ip}:${port}#Shadowsocks"
            ;;
        "Trojan")
            echo "trojan://${password}@${server_ip}:${port}?security=tls&sni=${server_ip}&alpn=http%2F1.1&type=tcp&headerType=none#Trojan"
            ;;
        "VMess-WS")
            local vmess_json='{"v":"2","ps":"VMess-WS-'${server_ip}'","add":"'${server_ip}'","port":"'${port}'","id":"'${uuid}'","aid":"0","scy":"auto","net":"ws","type":"none","host":"","path":"/'${uuid}'-vm","tls":"","sni":"","alpn":"","fp":""}'
            echo "vmess://$(echo -n "$vmess_json" | base64 -w 0)"
            ;;
        "VLESS-WS")
            echo "vless://${uuid}@${server_ip}:${port}?encryption=none&security=tls&sni=${server_ip}&alpn=http%2F1.1&type=ws&host=${server_ip}&path=%2Fvless#VLESS-WS-TLS"
            ;;
        "H2-Reality")
            local reality_keys=$(generate_reality_keys)
            local public_key=$(echo "$reality_keys" | grep "PublicKey" | awk '{print $2}')
            local target_domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
            local short_id=$(openssl rand -hex 8)
            echo "vless://${uuid}@${server_ip}:${port}?encryption=none&security=reality&sni=${target_domain}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=http&host=${target_domain}&path=%2F#H2-Reality"
            ;;
        "gRPC-Reality")
            local reality_keys=$(generate_reality_keys)
            local public_key=$(echo "$reality_keys" | grep "PublicKey" | awk '{print $2}')
            local target_domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
            local short_id=$(openssl rand -hex 8)
            echo "vless://${uuid}@${server_ip}:${port}?encryption=none&security=reality&sni=${target_domain}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=grpc&serviceName=grpc#gRPC-Reality"
            ;;
        "AnyTLS")
            echo "anytls://${uuid}@${server_ip}:${port}?security=tls&sni=${server_ip}#AnyTLS"
            ;;
        *)
            echo "不支持的协议: $protocol"
            ;;
    esac
}

# 显示节点信息
show_node_info() {
    clear
    echo -e "${CYAN}================================${NC}"
    echo -e "${WHITE}       SBall 节点信息       ${NC}"
    echo -e "${CYAN}================================${NC}"
    echo
    
    # 获取服务器IP
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(curl -s ipv4.icanhazip.com || curl -s ifconfig.me || curl -s ipinfo.io/ip)
    fi
    
    echo -e "${GREEN}服务器IP:${NC} $SERVER_IP"
    
    # 检查服务状态
    local service_status=$(systemctl is-active $SERVICE_NAME 2>/dev/null || echo "未安装")
    local sub_status=$(systemctl is-active sball-subscription 2>/dev/null || echo "未安装")
    echo -e "${GREEN}代理服务:${NC} $service_status"
    echo -e "${GREEN}订阅服务:${NC} $sub_status"
    echo
    
    if [[ ! -f "$WORK_DIR/config_info.json" ]]; then
        echo -e "${RED}配置信息不存在，请先安装服务${NC}"
        return 1
    fi
    
    # 从配置信息文件读取协议信息
    local protocol_count=0
    
    # 清空订阅文件
    > "$SUB_DIR/nodes.txt"
    
    # 使用jq解析JSON配置文件
    if command -v jq &> /dev/null; then
        local protocols_json=$(jq -r '.protocols[] | @base64' "$WORK_DIR/config_info.json" 2>/dev/null)
        
        echo -e "${GREEN}支持的协议节点:${NC}"
        echo
        
        while IFS= read -r protocol_data; do
            if [[ -n "$protocol_data" ]]; then
                local protocol_info=$(echo "$protocol_data" | base64 -d)
                local protocol=$(echo "$protocol_info" | jq -r '.name')
                local port=$(echo "$protocol_info" | jq -r '.port')
                local uuid=$(echo "$protocol_info" | jq -r '.uuid')
                local password=$(echo "$protocol_info" | jq -r '.password')
                
                ((protocol_count++))
                echo -e "${PURPLE}[$protocol_count] $protocol${NC}"
                echo -e "   ${GRAY}端口:${NC} $port"
                echo -e "   ${GRAY}UUID:${NC} $uuid"
                echo -e "   ${GRAY}密码:${NC} $password"
                
                local node_link=$(generate_node_link "$protocol" "$port" "$uuid" "$password")
                echo -e "   ${GRAY}节点链接:${NC}"
                echo -e "   ${GREEN}$node_link${NC}"
                echo
                
                # 保存到订阅文件
                echo "$node_link" >> "$SUB_DIR/nodes.txt"
            fi
        done <<< "$protocols_json"
    else
        # 如果没有jq，使用简单的grep方式解析
        log_warn "未安装jq，使用简化解析方式"
        
        # 这里可以添加简单的解析逻辑
        echo -e "${RED}请安装jq工具以正确显示节点信息${NC}"
        echo -e "${YELLOW}安装命令: apt install jq 或 yum install jq${NC}"
        return 1
    fi
    
    if [[ $protocol_count -eq 0 ]]; then
        echo -e "${RED}未找到任何协议配置${NC}"
        return 1
    fi
    
    echo -e "${GREEN}共计 $protocol_count 个协议节点${NC}"
    echo -e "${GREEN}订阅链接:${NC} http://$SERVER_IP:8000/sub"
    echo -e "${GREEN}Base64订阅:${NC} http://$SERVER_IP:8000/subscription_base64"
    echo -e "${CYAN}================================${NC}"
    
    # 显示所有节点链接（方便复制）
    echo
    echo -e "${YELLOW}所有节点链接（可直接复制使用）:${NC}"
    echo -e "${CYAN}================================${NC}"
    
    if [[ -f "$SUB_DIR/nodes.txt" ]]; then
        local line_num=1
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                echo -e "${PURPLE}[$line_num]${NC} ${GREEN}$line${NC}"
                ((line_num++))
            fi
        done < "$SUB_DIR/nodes.txt"
    fi
    
    echo -e "${CYAN}================================${NC}"
    
    # 更新订阅文件
    if [[ -f "$SUB_DIR/nodes.txt" ]]; then
        cp "$SUB_DIR/nodes.txt" "$SUB_DIR/subscription.txt"
        base64 -w 0 "$SUB_DIR/subscription.txt" > "$SUB_DIR/subscription_base64.txt"
        log_info "订阅文件已更新"
    fi
    
    # 显示使用建议
    echo
    echo -e "${GREEN}使用建议:${NC}"
    echo -e "  1. 复制上述节点链接到客户端"
    echo -e "  2. 或使用订阅链接自动更新"
    echo -e "  3. 建议优先使用: VLESS-Reality, Hysteria2, TUIC"
    echo -e "  4. 如遇连接问题，可尝试其他协议"
    echo
}

# 生成订阅文件
generate_subscription() {
    log_info "生成订阅文件..."
    
    # 清空旧的订阅文件
    > "$SUB_DIR/nodes.txt"
    > "$SUB_DIR/subscription.txt"
    
    # 重新生成所有节点链接
    for i in "${!SELECTED_PROTOCOLS[@]}"; do
        local protocol="${SELECTED_PROTOCOLS[i]}"
        local port="${PROTOCOL_PORTS[i]}"
        local uuid=$(generate_uuid)
        local password=$(generate_password)
        
        local node_link=$(generate_node_link "$protocol" "$port" "$uuid" "$password")
        echo "$node_link" >> "$SUB_DIR/nodes.txt"
        echo "$node_link" >> "$SUB_DIR/subscription.txt"
    done
    
    # 生成Base64编码的订阅文件
    base64 -w 0 "$SUB_DIR/subscription.txt" > "$SUB_DIR/subscription_base64.txt"
    
    # 创建HTTP服务器脚本
    cat > "$SUB_DIR/http_server.py" << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import os
import base64
import json
from datetime import datetime

class SubscriptionHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # 自定义日志格式
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {format % args}")
    
    def do_GET(self):
        client_ip = self.client_address[0]
        
        if self.path in ['/subscription', '/sub']:
            try:
                with open('/etc/sball/subscriptions/subscription.txt', 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="subscription.txt"')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
                self.log_message(f"Subscription served to {client_ip}")
                
            except FileNotFoundError:
                self.send_error(404, 'Subscription file not found')
                
        elif self.path == '/subscription_base64':
            try:
                with open('/etc/sball/subscriptions/subscription_base64.txt', 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="subscription_base64.txt"')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
                self.log_message(f"Base64 subscription served to {client_ip}")
                
            except FileNotFoundError:
                self.send_error(404, 'Base64 subscription file not found')
                
        elif self.path == '/status':
            # 状态检查接口
            try:
                with open('/etc/sball/config_info.json', 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                status = {
                    'status': 'active',
                    'server_ip': config.get('server_ip', 'unknown'),
                    'protocols_count': len(config.get('protocols', [])),
                    'install_time': config.get('install_time', 'unknown'),
                    'last_update': datetime.now().isoformat()
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(status, indent=2).encode('utf-8'))
                
            except FileNotFoundError:
                self.send_error(404, 'Config file not found')
                
        else:
            self.send_error(404, 'Not Found')

if __name__ == '__main__':
    PORT = 8000
    os.chdir('/etc/sball')
    
    print(f"Starting SBall Subscription Server on port {PORT}")
    print(f"Available endpoints:")
    print(f"  - /subscription (or /sub) - Raw subscription")
    print(f"  - /subscription_base64 - Base64 encoded subscription")
    print(f"  - /status - Server status")
    
    try:
        with socketserver.TCPServer(("", PORT), SubscriptionHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except Exception as e:
        print(f"Server error: {e}")
EOF
    
    chmod +x "$SUB_DIR/http_server.py"
    
    # 创建订阅服务的systemd服务
    cat > "/etc/systemd/system/sball-subscription.service" << EOF
[Unit]
Description=SBall Subscription Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SUB_DIR
ExecStart=/usr/bin/python3 $SUB_DIR/http_server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sball-subscription
    systemctl start sball-subscription
    
    log_info "订阅服务已启动，访问地址: http://$SERVER_IP:8000/sub"
}

# 服务管理函数
start_service() {
    log_info "启动SBall服务..."
    systemctl start "$SERVICE_NAME"
    if [[ $? -eq 0 ]]; then
        log_info "服务启动成功"
    else
        log_error "服务启动失败"
    fi
}

stop_service() {
    log_info "停止SBall服务..."
    systemctl stop "$SERVICE_NAME"
    if [[ $? -eq 0 ]]; then
        log_info "服务停止成功"
    else
        log_error "服务停止失败"
    fi
}

show_service_status() {
    echo -e "${CYAN}服务状态:${NC}"
    systemctl status "$SERVICE_NAME" --no-pager
}

show_service_logs() {
    echo -e "${CYAN}服务日志:${NC}"
    if [[ -f "$LOG_FILE" ]]; then
        tail -n 50 "$LOG_FILE"
    else
        echo -e "${RED}日志文件不存在${NC}"
    fi
}

# 重启服务
restart_service() {
    log_info "重启SBall服务..."
    
    # 重启主服务
    systemctl restart "$SERVICE_NAME"
    if [[ $? -eq 0 ]]; then
        log_info "主服务重启成功"
    else
        log_error "主服务重启失败"
    fi
    
    # 重启订阅服务
    systemctl restart "sball-subscription" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        log_info "订阅服务重启成功"
    else
        log_warn "订阅服务重启失败或未安装"
    fi
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "服务重启完成并正常运行"
    else
        log_error "服务重启后状态异常"
        systemctl status "$SERVICE_NAME" --no-pager
    fi
}

# 更新Sing-box
update_singbox() {
    log_info "更新Sing-box..."
    
    # 停止服务
    systemctl stop "$SERVICE_NAME"
    
    # 重新安装
    install_singbox
    
    # 启动服务
    systemctl start "$SERVICE_NAME"
    
    log_info "Sing-box更新完成"
}

# 卸载服务
uninstall_service() {
    echo -e "${RED}警告: 此操作将完全删除SBall服务和所有配置文件${NC}"
    read -p "确认卸载? (y/N): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "取消卸载"
        return
    fi
    
    log_info "开始卸载SBall服务..."
    
    # 停止并禁用主服务
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    
    # 停止并禁用订阅服务
    systemctl stop "sball-subscription" 2>/dev/null
    systemctl disable "sball-subscription" 2>/dev/null
    
    # 删除服务文件
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    rm -f "/etc/systemd/system/sball-subscription.service"
    systemctl daemon-reload
    
    # 关闭防火墙端口
    if [[ -f "$WORK_DIR/config_info.json" ]] && command -v jq &> /dev/null; then
        local protocols_json=$(jq -r '.protocols[] | @base64' "$WORK_DIR/config_info.json" 2>/dev/null)
        while IFS= read -r protocol_data; do
            if [[ -n "$protocol_data" ]]; then
                local protocol_info=$(echo "$protocol_data" | base64 -d)
                local port=$(echo "$protocol_info" | jq -r '.port')
                ufw delete allow "$port" 2>/dev/null
            fi
        done <<< "$protocols_json"
    fi
    
    # 关闭订阅服务端口
    ufw delete allow 8000 2>/dev/null
    
    # 删除配置目录
    rm -rf "$WORK_DIR"
    
    # 删除日志文件
    rm -f "$LOG_FILE"
    
    # 删除Sing-box二进制文件
    rm -f "$SING_BOX_BIN"
    
    log_info "SBall服务卸载完成"
    echo -e "${YELLOW}请手动删除脚本文件: rm -f $0${NC}"
    echo -e "${GREEN}感谢使用SBall代理工具！${NC}"
}

# 主程序
main() {
    # 显示脚本信息
    clear
    echo -e "${CYAN}================================${NC}"
    echo -e "${WHITE}    $SCRIPT_NAME v$SCRIPT_VERSION${NC}"
    echo -e "${CYAN}================================${NC}"
    echo -e "${PURPLE}多协议科学上网代理工具${NC}"
    echo -e "${PURPLE}GitHub: $GITHUB_REPO${NC}"
    echo
    
    # 检查系统环境
    log_info "正在检查系统环境..."
    check_system
    log_info "系统环境检查完成"
    
    while true; do
        show_main_menu
        read -p "请选择操作 [0-10]: " choice
        
        case $choice in
            1)
                log_info "开始安装代理服务"
                install_service
                read -p "按回车键继续..."
                ;;
            2)
                log_info "开始更新Sing-box"
                 update_singbox
                read -p "按回车键继续..."
                ;;
            3)
                log_info "开始卸载服务"
                echo -e "${RED}警告: 此操作将完全删除SBall服务和所有配置文件${NC}"
                read -p "确认卸载? [y/N]: " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    uninstall_service
                else
                    log_info "取消卸载操作"
                fi
                read -p "按回车键继续..."
                ;;
            4)
                show_node_info
                read -p "按回车键继续..."
                ;;
            5)
                log_info "启动服务"
                start_service
                read -p "按回车键继续..."
                ;;
            6)
                log_info "停止服务"
                stop_service
                read -p "按回车键继续..."
                ;;
            7)
                show_service_status
                read -p "按回车键继续..."
                ;;
            8)
                show_service_logs
                read -p "按回车键继续..."
                ;;
            9)
                restart_service
                read -p "按回车键继续..."
                ;;
            10)
                manage_fail2ban
                read -p "按回车键继续..."
                ;;
            0)
                log_info "退出SBall管理面板"
                echo -e "${GREEN}感谢使用 $SCRIPT_NAME!${NC}"
                echo -e "${YELLOW}如有问题请访问: $GITHUB_REPO${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选项，请重新选择${NC}"
                read -p "按回车键继续..."
                ;;
        esac
        
        echo
    done
}

# 脚本入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
