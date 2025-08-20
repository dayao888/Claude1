#!/bin/bash

# SBall - Sing-box 全能科学上网程序
# 版本: 1.0.0
# 作者: Claude 4 Sonnet
# 许可证: MIT License
# 支持平台: Linux (Ubuntu--amd64)

#===========================================
# 全局变量定义
#===========================================

# 版本信息
VERSION="1.0.0"
SCRIPT_NAME="SBall"
SCRIPT_URL="https://raw.githubusercontent.com/example/sball/main/sball.sh"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 路径配置
WORK_DIR="/etc/sing-box"
CONFIG_FILE="/etc/sing-box/config.json"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
LOG_FILE="/var/log/sing-box.log"
CERT_DIR="/etc/sing-box/certs"
TEMP_DIR="/tmp/sball"

# 网络配置
PORT_RANGE="10000-65535"
DEFAULT_PORT="443"
SERVER_IP=""
DOMAIN=""

# 支持的协议列表
PROTOCOL_LIST=("vless-reality" "hysteria2" "tuic" "shadowtls" "shadowsocks" "trojan")

# 安装状态
INSTALLED=false
SELECTED_PROTOCOL=""
SELECTED_PORT=""
GENERATED_UUID=""
USE_DOMAIN=false
USE_FAIL2BAN=false
USE_PORT_PROTECTION=false


#===========================================
# 工具函数模块
#===========================================

# 信息输出函数
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

hint() {
    echo -e "${PURPLE}[HINT]${NC} $1"
}

# 用户输入函数
reading() {
    read -p "$(echo -e "${CYAN}[INPUT]${NC} $1: ")" "$2"
}

# 确认函数
confirm() {
    local prompt="$1"
    local response
    while true; do
        reading "$prompt [y/n]" response
        case "$response" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) warning "请输入 y 或 n" ;;
        esac
    done
}

# 暂停函数
pause() {
    reading "$(text 'press_enter')" _
}

# 生成随机字符串
generate_random_string() {
    local length="${1:-8}"
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

# 生成UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        # 备用UUID生成方法
        cat /proc/sys/kernel/random/uuid
    fi
}

# 生成随机端口
generate_random_port() {
    local min_port=10000
    local max_port=65535
    echo $((RANDOM % (max_port - min_port + 1) + min_port))
}

# 检查端口是否被占用
check_port() {
    local port="$1"
    if ss -tuln | grep -q ":$port "; then
        return 1
    else
        return 0
    fi
}

# 获取服务器IP
get_server_ip() {
    # 尝试多种方法获取公网IP
    local ip
    ip=$(curl -s --max-time 10 ipv4.icanhazip.com) || 
    ip=$(curl -s --max-time 10 ifconfig.me) || 
    ip=$(curl -s --max-time 10 ip.sb) || 
    ip=$(wget -qO- --timeout=10 ipecho.net/plain)
    
    if [[ -n "$ip" && "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip"
    else
        # 获取本地IP作为备用
        ip route get 8.8.8.8 | awk 'NR==1 {print $7}'
    fi
}

#===========================================
# 系统检测模块
#===========================================

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "此脚本需要root权限运行"
        error "请使用: sudo $0"
        exit 1
    fi
}

# 检查系统环境
check_system() {
    info "正在检查系统环境..."
    
    # 检查操作系统
    if [[ ! -f /etc/os-release ]]; then
        error "不支持的操作系统"
        exit 1
    fi
    
    source /etc/os-release
    
    # 检查是否为Ubuntu
    if [[ "$ID" != "ubuntu" ]]; then
        warning "建议使用 Ubuntu 系统，当前系统: $PRETTY_NAME"
        if ! confirm "是否继续安装?"; then
            exit 1
        fi
    fi
    
    # 检查系统架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *) 
            error "不支持的系统架构: $ARCH"
            exit 1
            ;;
    esac
    
    # 检查系统版本
    if [[ -n "$VERSION_ID" ]]; then
        local version_major=$(echo "$VERSION_ID" | cut -d. -f1)
        if [[ "$ID" == "ubuntu" && $version_major -lt 18 ]]; then
            error "Ubuntu 版本过低，建议使用 Ubuntu 18.04 或更高版本"
            exit 1
        fi
    fi
    
    success "系统检查通过: $PRETTY_NAME ($ARCH)"
}

# 检查网络连接
check_network() {
    info "检查网络连接..."
    
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        error "网络连接失败，请检查网络设置"
        exit 1
    fi
    
    success "网络连接正常"
}

# 检查是否已安装
check_installed() {
    if [[ -f "$CONFIG_FILE" && -f "/usr/local/bin/sing-box" ]]; then
        INSTALLED=true
        return 0
    else
        INSTALLED=false
        return 1
    fi
}

#===========================================
# 依赖安装模块
#===========================================

# 更新系统包
update_system() {
    info "更新系统包列表..."
    apt update -qq
    
    if [[ $? -ne 0 ]]; then
        error "系统包更新失败"
        exit 1
    fi
}

# 安装系统依赖
install_dependencies() {
    info "正在安装系统依赖..."
    
    local packages=("curl" "wget" "jq" "openssl" "uuid-runtime" "unzip" "tar" "systemd" "iptables" "ufw")
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            info "安装 $package..."
            apt install -y "$package" >/dev/null 2>&1
            
            if [[ $? -ne 0 ]]; then
                error "安装 $package 失败"
                exit 1
            fi
        fi
    done
    
    # 安装证书工具
    install_certbot
    
    success "系统依赖安装完成"
}

# 安装Certbot
install_certbot() {
    if ! command -v certbot >/dev/null 2>&1; then
        info "安装 Certbot..."
        
        if command -v snap >/dev/null 2>&1; then
            snap install core >/dev/null 2>&1
            snap refresh core >/dev/null 2>&1
            snap install --classic certbot >/dev/null 2>&1
            ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null
        else
            apt install -y certbot >/dev/null 2>&1
        fi
        
        if command -v certbot >/dev/null 2>&1; then
            success "Certbot 安装成功"
        else
            warning "Certbot 安装失败，将使用自签名证书"
        fi
    fi
}

#===========================================
# Sing-box核心模块
#===========================================

# 获取最新版本
get_latest_version() {
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local version
    
    version=$(curl -s --max-time 30 "$api_url" | jq -r '.tag_name' 2>/dev/null | sed 's/v//')
    
    if [[ -z "$version" || "$version" == "null" ]]; then
        # 备用版本
        version="1.12.0"
        warning "无法获取最新版本，使用默认版本: $version"
    fi
    
    echo "$version"
}

# 下载Sing-box
download_singbox() {
    local version="$1"
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${ARCH}.tar.gz"
    local temp_file="$TEMP_DIR/sing-box.tar.gz"
    
    info "正在下载 Sing-box v$version..."
    
    # 创建临时目录
    mkdir -p "$TEMP_DIR"
    
    # 下载文件
    if ! wget -q --show-progress --timeout=60 -O "$temp_file" "$download_url"; then
        error "下载 Sing-box 失败"
        return 1
    fi
    
    # 解压文件
    if ! tar -xzf "$temp_file" -C "$TEMP_DIR"; then
        error "解压 Sing-box 失败"
        return 1
    fi
    
    # 安装二进制文件
    local extracted_dir="$TEMP_DIR/sing-box-${version}-linux-${ARCH}"
    if [[ -f "$extracted_dir/sing-box" ]]; then
        cp "$extracted_dir/sing-box" "/usr/local/bin/"
        chmod +x "/usr/local/bin/sing-box"
        success "Sing-box 安装成功"
    else
        error "找不到 Sing-box 二进制文件"
        return 1
    fi
    
    # 清理临时文件
    rm -rf "$TEMP_DIR"
    
    return 0
}

# 安装Sing-box
install_singbox() {
    info "开始安装 Sing-box..."
    
    # 获取最新版本
    local version
    version=$(get_latest_version)
    
    # 下载并安装
    if download_singbox "$version"; then
        # 创建工作目录
        mkdir -p "$WORK_DIR" "$CERT_DIR"
        
        # 创建systemd服务
        create_systemd_service
        
        success "Sing-box 安装完成"
        return 0
    else
        error "Sing-box 安装失败"
        return 1
    fi
}

# 创建systemd服务
create_systemd_service() {
    info "创建 systemd 服务..."
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/sing-box run -c $CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1
    
    success "systemd 服务创建完成"
}

#===========================================
# 主程序入口
#===========================================

# 主函数
main() {
    # 检查root权限
    check_root
    
    # 检查是否已安装
    check_installed
    
    # 获取服务器IP
    SERVER_IP=$(get_server_ip)
    
    # 显示主菜单
    show_main_menu
}

# 显示主菜单
show_main_menu() {
    while true; do
        clear
        echo -e "${CYAN}======================================${NC}"
        echo -e "${WHITE}    欢迎使用 SBall${NC}"
        echo -e "${CYAN}    版本: ${GREEN}$VERSION${NC}"
        echo -e "${CYAN}======================================${NC}"
        echo
        
        if [[ "$INSTALLED" == "true" ]]; then
            echo -e "${GREEN}1.${NC} 管理配置"
            echo -e "${BLUE}2.${NC} 查看配置"
            echo -e "${BLUE}3.${NC} 查看日志"
            echo -e "${BLUE}4.${NC} 服务状态"
            echo -e "${BLUE}5.${NC} 证书信息"
            echo -e "${YELLOW}6.${NC} 更新程序"
            echo -e "${RED}7.${NC} 卸载程序"
        else
            echo -e "${GREEN}1.${NC} 一键安装"
        fi
        
        echo -e "${PURPLE}8.${NC} 语言设置"
        echo -e "${RED}0.${NC} 退出程序"
        echo
        echo -e "${CYAN}======================================${NC}"
        
        local choice
        reading "请选择操作" choice
        
        case "$choice" in
            1)
                if [[ "$INSTALLED" == "true" ]]; then
                    management_menu
                else
                    quick_install
                fi
                ;;
            2)
                if [[ "$INSTALLED" == "true" ]]; then
                    view_node_info
                    pause
                fi
                ;;
            3)
                if [[ "$INSTALLED" == "true" ]]; then
                    view_logs
                    pause
                fi
                ;;
            4)
                if [[ "$INSTALLED" == "true" ]]; then
                    check_service_status
                    pause
                fi
                ;;
            5)
                if [[ "$INSTALLED" == "true" ]]; then
                    check_certificate_info
                    pause
                fi
                ;;
            6)
                if [[ "$INSTALLED" == "true" ]]; then
                    update_singbox
                    pause
                fi
                ;;
            7)
                if [[ "$INSTALLED" == "true" ]]; then
                    uninstall_singbox
                    pause
                fi
                ;;
            8)
                switch_language
                ;;
            0)
                echo
                success "感谢使用 SBall!"
                exit 0
                ;;
            *)
                warning "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

# 一键安装函数
quick_install() {
    echo
    info "正在安装 SBall..."
    echo
    
    # 系统检查
    check_system
    check_network
    
    # 更新系统
    update_system
    
    # 安装依赖
    install_dependencies
    
    # 安装Sing-box
    if ! install_singbox; then
        error "安装失败"
        pause
        return 1
    fi
    
    # 交互式配置
    interactive_config
    
    # 生成配置文件
    if generate_config; then
        # 启动服务
        systemctl start sing-box
        
        if systemctl is-active --quiet sing-box; then
            success "安装成功"
            INSTALLED=true
            
            # 显示配置信息
            echo
            show_client_info
        else
            error "服务启动失败"
            systemctl status sing-box
        fi
    else
        error "配置生成失败"
    fi
    
    pause
}

# 交互式配置
interactive_config() {
    echo
    info "开始交互式配置..."
    echo
    
    # 选择协议
    select_protocol
    
    # 配置端口
    config_port
    
    # 配置域名
    config_domain
    
    # 配置安全选项
    config_security
    
    # 生成UUID
    GENERATED_UUID=$(generate_uuid)
    
    echo
    info "配置完成:"
    echo "  协议: $SELECTED_PROTOCOL"
    echo "  端口: $SELECTED_PORT"
    echo "  UUID: $GENERATED_UUID"
    if [[ "$USE_DOMAIN" == "true" ]]; then
        echo "  域名: $DOMAIN"
    fi
    echo
}

# 选择协议
select_protocol() {
    echo "选择协议:"
    echo
    
    local i=1
    for protocol in "${PROTOCOL_LIST[@]}"; do
        echo "$i. $protocol"
        ((i++))
    done
    echo
    
    while true; do
        local choice
        reading "请选择协议 [1-${#PROTOCOL_LIST[@]}]" choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${#PROTOCOL_LIST[@]} ]]; then
            SELECTED_PROTOCOL="${PROTOCOL_LIST[$((choice-1))]}"
            success "已选择协议: $SELECTED_PROTOCOL"
            break
        else
            warning "无效选项，请重新选择"
        fi
    done
}

# 配置端口
config_port() {
    echo
    if confirm "是否使用随机端口?"; then
        while true; do
            SELECTED_PORT=$(generate_random_port)
            if check_port "$SELECTED_PORT"; then
                success "已生成随机端口: $SELECTED_PORT"
                break
            fi
        done
    else
        while true; do
            reading "请输入端口号 [$DEFAULT_PORT]" port_input
            
            if [[ -z "$port_input" ]]; then
                port_input="$DEFAULT_PORT"
            fi
            
            if [[ "$port_input" =~ ^[0-9]+$ ]] && [[ $port_input -ge 1 && $port_input -le 65535 ]]; then
                if check_port "$port_input"; then
                    SELECTED_PORT="$port_input"
                    success "已设置端口: $SELECTED_PORT"
                    break
                else
                    warning "端口 $port_input 已被占用，请选择其他端口"
                fi
            else
                warning "无效的端口号，请输入 1-65535 之间的数字"
            fi
        done
    fi
}

# 配置域名
config_domain() {
    echo
    if confirm "是否使用域名?"; then
        USE_DOMAIN=true
        
        while true; do
            reading "请输入域名" domain_input
            
            if [[ -n "$domain_input" && "$domain_input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
                DOMAIN="$domain_input"
                success "已设置域名: $DOMAIN"
                break
            else
                warning "无效的域名格式"
            fi
        done
    else
        USE_DOMAIN=false
        info "将使用自签名证书"
    fi
}

# 配置安全选项
config_security() {
    echo
    if confirm "是否启用端口扫描防护?"; then
        USE_PORT_PROTECTION=true
        success "已启用端口扫描防护"
    else
        USE_PORT_PROTECTION=false
    fi
}

# 生成配置文件
generate_config() {
    info "正在生成配置文件..."
    
    # 创建基础配置
    create_base_config
    
    # 根据协议添加入站配置
    case "$SELECTED_PROTOCOL" in
        "vless-reality")
            add_vless_reality_inbound
            ;;
        "hysteria2")
            add_hysteria2_inbound
            ;;
        "tuic")
            add_tuic_inbound
            ;;
        "shadowtls")
            add_shadowtls_inbound
            ;;
        "shadowsocks")
            add_shadowsocks_inbound
            ;;
        "trojan")
            add_trojan_inbound
            ;;
        *)
            error "不支持的协议: $SELECTED_PROTOCOL"
            return 1
            ;;
    esac
    
    # 验证配置文件
    if /usr/local/bin/sing-box check -c "$CONFIG_FILE" >/dev/null 2>&1; then
        success "配置文件生成成功"
        return 0
    else
        error "配置文件验证失败"
        return 1
    fi
}

# 创建基础配置
create_base_config() {
    cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query",
        "detour": "direct"
      },
      {
        "tag": "local",
        "address": "local",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "local"
      }
    ]
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
        "protocol": "dns",
        "outbound": "direct"
      }
    ]
  }
}
EOF
}

# 添加VLESS-Reality入站配置
add_vless_reality_inbound() {
    info "配置 VLESS-Reality..."
    
    # 生成Reality密钥对
    local keypair_output
    keypair_output=$(/usr/local/bin/sing-box generate reality-keypair 2>/dev/null)
    
    if [[ -z "$keypair_output" ]]; then
        error "生成 Reality 密钥对失败"
        return 1
    fi
    
    local private_key
    local public_key
    private_key=$(echo "$keypair_output" | grep "PrivateKey" | awk '{print $2}')
    public_key=$(echo "$keypair_output" | grep "PublicKey" | awk '{print $2}')
    
    # 生成short_id
    local short_id
    short_id=$(openssl rand -hex 8)
    
    # Reality目标网站
    local dest="www.microsoft.com:443"
    local server_name="www.microsoft.com"
    
    # 保存公钥和short_id供客户端使用
    echo "$public_key" > "$WORK_DIR/reality_public_key"
    echo "$short_id" > "$WORK_DIR/reality_short_id"
    
    # 添加入站配置
    jq --arg port "$SELECTED_PORT" \
       --arg uuid "$GENERATED_UUID" \
       --arg private_key "$private_key" \
       --arg short_id "$short_id" \
       --arg dest "$dest" \
       --arg server_name "$server_name" '
    .inbounds += [{
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": ($port | tonumber),
      "users": [
        {
          "uuid": $uuid,
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": $server_name,
        "reality": {
          "enabled": true,
          "handshake": {
            "server": $dest,
            "server_port": 443
          },
          "private_key": $private_key,
          "short_id": [$short_id]
        }
      },
      "multiplex": {
        "enabled": true
      }
    }]' "$CONFIG_FILE" > "/tmp/config.json" && mv "/tmp/config.json" "$CONFIG_FILE"
    
    success "VLESS-Reality 配置完成"
}

# 添加Hysteria2入站配置
add_hysteria2_inbound() {
    info "配置 Hysteria2..."
    
    local cert_path
    local key_path
    
    if [[ "$USE_DOMAIN" == "true" ]]; then
        # 申请域名证书
        if setup_domain_certificate "$DOMAIN"; then
            cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            key_path="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        else
            warning "域名证书申请失败，使用自签名证书"
            generate_self_signed_cert "$DOMAIN"
            cert_path="$CERT_DIR/fullchain.pem"
            key_path="$CERT_DIR/privkey.pem"
        fi
    else
        # 生成自签名证书
        generate_self_signed_cert "localhost"
        cert_path="$CERT_DIR/fullchain.pem"
        key_path="$CERT_DIR/privkey.pem"
    fi
    
    # 添加入站配置
    jq --arg port "$SELECTED_PORT" \
       --arg uuid "$GENERATED_UUID" \
       --arg cert_path "$cert_path" \
       --arg key_path "$key_path" \
       --arg domain "${DOMAIN:-localhost}" '
    .inbounds += [{
      "type": "hysteria2",
      "tag": "hysteria2",
      "listen": "::",
      "listen_port": ($port | tonumber),
      "users": [
        {
          "password": $uuid
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": $domain,
        "alpn": ["h3"],
        "certificate_path": $cert_path,
        "key_path": $key_path
      },
      "masquerade": "https://www.bing.com"
    }]' "$CONFIG_FILE" > "/tmp/config.json" && mv "/tmp/config.json" "$CONFIG_FILE"
    
    success "Hysteria2 配置完成"
}

# 添加Shadowsocks入站配置
add_shadowsocks_inbound() {
    info "配置 Shadowsocks..."
    
    # 添加入站配置
    jq --arg port "$SELECTED_PORT" \
       --arg uuid "$GENERATED_UUID" '
    .inbounds += [{
      "type": "shadowsocks",
      "tag": "shadowsocks",
      "listen": "::",
      "listen_port": ($port | tonumber),
      "method": "chacha20-ietf-poly1305",
      "password": $uuid,
      "multiplex": {
        "enabled": true
      }
    }]' "$CONFIG_FILE" > "/tmp/config.json" && mv "/tmp/config.json" "$CONFIG_FILE"
    
    success "Shadowsocks 配置完成"
}

# 添加TUIC入站配置
add_tuic_inbound() {
    info "配置 TUIC..."
    
    # 处理证书
    local cert_path key_path
    if [[ "$USE_DOMAIN" == "true" ]]; then
        if setup_domain_certificate "$DOMAIN"; then
            cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            key_path="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        else
            warning "域名证书申请失败，使用自签名证书"
            generate_self_signed_cert "$DOMAIN"
            cert_path="$CERT_DIR/fullchain.pem"
            key_path="$CERT_DIR/privkey.pem"
        fi
    else
        generate_self_signed_cert "localhost"
        cert_path="$CERT_DIR/fullchain.pem"
        key_path="$CERT_DIR/privkey.pem"
    fi
    
    # 添加入站配置
    jq --arg port "$SELECTED_PORT" \
       --arg uuid "$GENERATED_UUID" \
       --arg cert "$cert_path" \
       --arg key "$key_path" '
    .inbounds += [{
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": ($port | tonumber),
      "users": [{
        "uuid": $uuid,
        "password": $uuid
      }],
      "congestion_control": "bbr",
      "zero_rtt_handshake": false,
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": $cert,
        "key_path": $key
      }
    }]' "$CONFIG_FILE" > "/tmp/config.json" && mv "/tmp/config.json" "$CONFIG_FILE"
    
    success "TUIC 配置完成"
}

# 添加ShadowTLS入站配置
add_shadowtls_inbound() {
    info "配置 ShadowTLS..."
    
    # 添加ShadowTLS和内部Shadowsocks入站配置
    jq --arg port "$SELECTED_PORT" \
       --arg uuid "$GENERATED_UUID" '
    .inbounds += [
      {
        "type": "shadowtls",
        "tag": "shadowtls",
        "listen": "::",
        "listen_port": ($port | tonumber),
        "detour": "shadowtls-in",
        "version": 3,
        "users": [{
          "password": $uuid
        }],
        "handshake": {
          "server": "www.microsoft.com",
          "server_port": 443
        },
        "strict_mode": true
      },
      {
        "type": "shadowsocks",
        "tag": "shadowtls-in",
        "listen": "127.0.0.1",
        "network": "tcp",
        "method": "chacha20-ietf-poly1305",
        "password": $uuid,
        "multiplex": {
          "enabled": true,
          "padding": true
        }
      }
    ]' "$CONFIG_FILE" > "/tmp/config.json" && mv "/tmp/config.json" "$CONFIG_FILE"
    
    success "ShadowTLS 配置完成"
}

# 添加Trojan入站配置
add_trojan_inbound() {
    info "配置 Trojan..."
    
    # 处理证书
    local cert_path key_path
    if [[ "$USE_DOMAIN" == "true" ]]; then
        if setup_domain_certificate "$DOMAIN"; then
            cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            key_path="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        else
            warning "域名证书申请失败，使用自签名证书"
            generate_self_signed_cert "$DOMAIN"
            cert_path="$CERT_DIR/fullchain.pem"
            key_path="$CERT_DIR/privkey.pem"
        fi
    else
        generate_self_signed_cert "localhost"
        cert_path="$CERT_DIR/fullchain.pem"
        key_path="$CERT_DIR/privkey.pem"
    fi
    
    # 添加入站配置
    jq --arg port "$SELECTED_PORT" \
       --arg uuid "$GENERATED_UUID" \
       --arg cert "$cert_path" \
       --arg key "$key_path" '
    .inbounds += [{
      "type": "trojan",
      "tag": "trojan",
      "listen": "::",
      "listen_port": ($port | tonumber),
      "users": [{
        "password": $uuid
      }],
      "tls": {
        "enabled": true,
        "certificate_path": $cert,
        "key_path": $key
      },
      "multiplex": {
        "enabled": true,
        "padding": true
      }
    }]' "$CONFIG_FILE" > "/tmp/config.json" && mv "/tmp/config.json" "$CONFIG_FILE"
    
    success "Trojan 配置完成"
}

# 证书管理函数
setup_domain_certificate() {
    local domain="$1"
    
    info "为域名 $domain 申请 Let's Encrypt 证书..."
    
    # 停止可能占用80端口的服务
    systemctl stop nginx apache2 2>/dev/null || true
    
    # 申请证书
    if certbot certonly --standalone --non-interactive --agree-tos --email "admin@$domain" -d "$domain" >/dev/null 2>&1; then
        success "证书申请成功"
        
        # 设置自动续期
        echo "0 2 * * * root certbot renew --quiet && systemctl reload sing-box" > /etc/cron.d/certbot-renew
        return 0
    else
        error "证书申请失败"
        return 1
    fi
}

# 生成自签名证书
generate_self_signed_cert() {
    local domain="$1"
    
    info "生成自签名证书..."
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/fullchain.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$domain" >/dev/null 2>&1
    
    if [[ $? -eq 0 ]]; then
        success "自签名证书生成完成"
        return 0
    else
        error "自签名证书生成失败"
        return 1
    fi
}

# 显示客户端配置信息
show_client_info() {
    echo
    echo -e "${CYAN}======================================${NC}"
    echo -e "${WHITE}           客户端配置信息${NC}"
    echo -e "${CYAN}======================================${NC}"
    echo
    
    case "$SELECTED_PROTOCOL" in
        "vless-reality")
            show_vless_reality_info
            ;;
        "hysteria2")
            show_hysteria2_info
            ;;
        "tuic")
            show_tuic_info
            ;;
        "shadowtls")
            show_shadowtls_info
            ;;
        "shadowsocks")
            show_shadowsocks_info
            ;;
        "trojan")
            show_trojan_info
            ;;
    esac
    
    echo
    echo -e "${CYAN}======================================${NC}"
    echo -e "${WHITE}           订阅链接${NC}"
    echo -e "${CYAN}======================================${NC}"
    echo
    echo -e "${GREEN}Clash:${NC} http://$SERVER_IP:8080/clash"
    echo -e "${GREEN}V2rayN:${NC} http://$SERVER_IP:8080/v2ray"
    echo -e "${GREEN}Sing-box:${NC} http://$SERVER_IP:8080/singbox"
    echo
}

# 显示VLESS-Reality信息
show_vless_reality_info() {
    local public_key
    local short_id
    
    if [[ -f "$WORK_DIR/reality_public_key" ]]; then
        public_key=$(cat "$WORK_DIR/reality_public_key")
    fi
    
    if [[ -f "$WORK_DIR/reality_short_id" ]]; then
        short_id=$(cat "$WORK_DIR/reality_short_id")
    fi
    
    echo -e "${GREEN}协议:${NC} VLESS + Reality"
    echo -e "${GREEN}地址:${NC} $SERVER_IP"
    echo -e "${GREEN}端口:${NC} $SELECTED_PORT"
    echo -e "${GREEN}UUID:${NC} $GENERATED_UUID"
    echo -e "${GREEN}流控:${NC} xtls-rprx-vision"
    echo -e "${GREEN}传输:${NC} TCP"
    echo -e "${GREEN}TLS:${NC} Reality"
    echo -e "${GREEN}SNI:${NC} www.microsoft.com"
    echo -e "${GREEN}Fingerprint:${NC} chrome"
    echo -e "${GREEN}PublicKey:${NC} $public_key"
    echo -e "${GREEN}ShortId:${NC} $short_id"
}

# 显示Hysteria2信息
show_hysteria2_info() {
    echo -e "${GREEN}协议:${NC} Hysteria2"
    echo -e "${GREEN}地址:${NC} $SERVER_IP"
    echo -e "${GREEN}端口:${NC} $SELECTED_PORT"
    echo -e "${GREEN}密码:${NC} $GENERATED_UUID"
    echo -e "${GREEN}TLS:${NC} 启用"
    if [[ "$USE_DOMAIN" == "true" ]]; then
        echo -e "${GREEN}SNI:${NC} $DOMAIN"
    else
        echo -e "${GREEN}SNI:${NC} localhost"
    fi
    echo -e "${GREEN}ALPN:${NC} h3"
    echo -e "${GREEN}伪装:${NC} https://www.bing.com"
}

# 显示Shadowsocks信息
show_shadowsocks_info() {
    echo -e "${GREEN}协议:${NC} Shadowsocks"
    echo -e "${GREEN}地址:${NC} $SERVER_IP"
    echo -e "${GREEN}端口:${NC} $SELECTED_PORT"
    echo -e "${GREEN}密码:${NC} $GENERATED_UUID"
    echo -e "${GREEN}加密:${NC} chacha20-ietf-poly1305"
    echo -e "${GREEN}多路复用:${NC} 启用"
}

# 显示TUIC信息
show_tuic_info() {
    echo -e "${GREEN}协议:${NC} TUIC"
    echo -e "${GREEN}地址:${NC} $SERVER_IP"
    echo -e "${GREEN}端口:${NC} $SELECTED_PORT"
    echo -e "${GREEN}UUID:${NC} $GENERATED_UUID"
    echo -e "${GREEN}密码:${NC} $GENERATED_UUID"
    echo -e "${GREEN}拥塞控制:${NC} BBR"
    echo -e "${GREEN}ALPN:${NC} h3"
    if [[ "$USE_DOMAIN" == "true" ]]; then
        echo -e "${GREEN}SNI:${NC} $DOMAIN"
    else
        echo -e "${GREEN}SNI:${NC} localhost"
    fi
}

# 显示ShadowTLS信息
show_shadowtls_info() {
    echo -e "${GREEN}协议:${NC} ShadowTLS"
    echo -e "${GREEN}地址:${NC} $SERVER_IP"
    echo -e "${GREEN}端口:${NC} $SELECTED_PORT"
    echo -e "${GREEN}密码:${NC} $GENERATED_UUID"
    echo -e "${GREEN}版本:${NC} 3"
    echo -e "${GREEN}握手服务器:${NC} www.microsoft.com"
    echo -e "${GREEN}内层加密:${NC} chacha20-ietf-poly1305"
    echo -e "${GREEN}严格模式:${NC} 启用"
}

# 显示Trojan信息
show_trojan_info() {
    echo -e "${GREEN}协议:${NC} Trojan"
    echo -e "${GREEN}地址:${NC} $SERVER_IP"
    echo -e "${GREEN}端口:${NC} $SELECTED_PORT"
    echo -e "${GREEN}密码:${NC} $GENERATED_UUID"
    echo -e "${GREEN}TLS:${NC} 启用"
    if [[ "$USE_DOMAIN" == "true" ]]; then
        echo -e "${GREEN}SNI:${NC} $DOMAIN"
    else
        echo -e "${GREEN}SNI:${NC} localhost"
    fi
    echo -e "${GREEN}多路复用:${NC} 启用"
}

# 管理菜单
management_menu() {
    while true; do
        clear
        echo -e "${CYAN}======================================${NC}"
        echo -e "${WHITE}           SBall 管理菜单${NC}"
        echo -e "${CYAN}======================================${NC}"
        echo
        
        echo -e "${GREEN}1.${NC} 重新配置协议"
        echo -e "${BLUE}2.${NC} 重启服务"
        echo -e "${BLUE}3.${NC} 停止服务"
        echo -e "${BLUE}4.${NC} 启动服务"
        echo -e "${YELLOW}5.${NC} 更换端口"
        echo -e "${YELLOW}6.${NC} 更新证书"
        echo -e "${PURPLE}7.${NC} 备份配置"
        echo -e "${PURPLE}8.${NC} 恢复配置"
        echo -e "${RED}9.${NC} 重置配置"
        echo -e "${RED}0.${NC} 返回主菜单"
        echo
        echo -e "${CYAN}======================================${NC}"
        
        local choice
        reading "请选择操作" choice
        
        case "$choice" in
            1)
                reconfigure_protocol
                pause
                ;;
            2)
                restart_service
                pause
                ;;
            3)
                stop_service
                pause
                ;;
            4)
                start_service
                pause
                ;;
            5)
                change_port
                pause
                ;;
            6)
                update_certificate
                pause
                ;;
            7)
                backup_config
                pause
                ;;
            8)
                restore_config
                pause
                ;;
            9)
                reset_config
                pause
                ;;
            0)
                return
                ;;
            *)
                warning "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

# 重新配置协议
reconfigure_protocol() {
    info "开始重新配置协议..."
    
    # 停止服务
    systemctl stop sing-box
    
    # 交互式配置
    interactive_config
    
    # 生成新配置
    if generate_config; then
        # 重启服务
        systemctl start sing-box
        
        if systemctl is-active --quiet sing-box; then
            success "协议重新配置成功"
            echo
            show_client_info
        else
            error "服务启动失败"
            systemctl status sing-box
        fi
    else
        error "配置生成失败"
    fi
}

# 重启服务
restart_service() {
    info "重启 Sing-box 服务..."
    systemctl restart sing-box
    
    if systemctl is-active --quiet sing-box; then
        success "服务重启成功"
    else
        error "服务重启失败"
        systemctl status sing-box
    fi
}

# 停止服务
stop_service() {
    info "停止 Sing-box 服务..."
    systemctl stop sing-box
    
    if ! systemctl is-active --quiet sing-box; then
        success "服务已停止"
    else
        error "服务停止失败"
    fi
}

# 启动服务
start_service() {
    info "启动 Sing-box 服务..."
    systemctl start sing-box
    
    if systemctl is-active --quiet sing-box; then
        success "服务启动成功"
    else
        error "服务启动失败"
        systemctl status sing-box
    fi
}

# 更换端口
change_port() {
    info "更换服务端口..."
    
    # 配置新端口
    config_port
    
    # 更新配置文件中的端口
    if [[ -f "$CONFIG_FILE" ]]; then
        jq --arg port "$SELECTED_PORT" '
        .inbounds[0].listen_port = ($port | tonumber)' "$CONFIG_FILE" > "/tmp/config.json" && mv "/tmp/config.json" "$CONFIG_FILE"
        
        # 重启服务
        systemctl restart sing-box
        
        if systemctl is-active --quiet sing-box; then
            success "端口更换成功，新端口: $SELECTED_PORT"
        else
            error "服务重启失败"
        fi
    else
        error "配置文件不存在"
    fi
}

# 更新证书
update_certificate() {
    info "更新证书..."
    
    if [[ "$USE_DOMAIN" == "true" && -n "$DOMAIN" ]]; then
        if setup_domain_certificate "$DOMAIN"; then
            systemctl restart sing-box
            success "证书更新成功"
        else
            error "证书更新失败"
        fi
    else
        warning "当前使用自签名证书，无需更新"
    fi
}

# 备份配置
backup_config() {
    info "备份配置文件..."
    
    local backup_dir="/root/sball_backup"
    local backup_file="$backup_dir/config_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    mkdir -p "$backup_dir"
    
    if tar -czf "$backup_file" -C "/" "etc/sing-box" 2>/dev/null; then
        success "配置备份成功: $backup_file"
    else
        error "配置备份失败"
    fi
}

# 恢复配置
restore_config() {
    info "恢复配置文件..."
    
    local backup_dir="/root/sball_backup"
    
    if [[ ! -d "$backup_dir" ]]; then
        error "备份目录不存在"
        return 1
    fi
    
    echo "可用的备份文件:"
    ls -la "$backup_dir"/*.tar.gz 2>/dev/null | nl
    
    local backup_file
    reading "请输入备份文件完整路径" backup_file
    
    if [[ -f "$backup_file" ]]; then
        systemctl stop sing-box
        
        if tar -xzf "$backup_file" -C "/" 2>/dev/null; then
            systemctl start sing-box
            success "配置恢复成功"
        else
            error "配置恢复失败"
        fi
    else
        error "备份文件不存在"
    fi
}

# 重置配置
reset_config() {
    if confirm "确定要重置所有配置吗？这将删除当前配置并重新安装"; then
        info "重置配置..."
        
        # 停止服务
        systemctl stop sing-box
        
        # 删除配置文件
        rm -rf "$WORK_DIR"
        
        # 重新安装
        quick_install
    fi
}

# 查看节点信息
view_node_info() {
    if [[ -f "$CONFIG_FILE" ]]; then
        show_client_info
    else
        error "配置文件不存在"
    fi
}

# 查看日志
view_logs() {
    if [[ -f "$LOG_FILE" ]]; then
        echo "最近50行日志:"
        echo
        tail -n 50 "$LOG_FILE"
    else
        warning "日志文件不存在"
    fi
}

# 检查服务状态
check_service_status() {
    echo "Sing-box 服务状态:"
    echo
    systemctl status sing-box --no-pager
}

# 检查证书信息
check_certificate_info() {
    echo "证书信息功能开发中..."
}

# 更新Sing-box
update_singbox() {
    echo "更新功能开发中..."
}

# 卸载Sing-box
uninstall_singbox() {
    if confirm "确定要卸载 SBall 吗？这将删除所有配置文件"; then
        info "开始卸载..."
        
        # 停止服务
        systemctl stop sing-box 2>/dev/null
        systemctl disable sing-box 2>/dev/null
        
        # 删除文件
        rm -f "/usr/local/bin/sing-box"
        rm -f "$SERVICE_FILE"
        rm -rf "$WORK_DIR"
        rm -f "$LOG_FILE"
        
        # 重新加载systemd
        systemctl daemon-reload
        
        success "卸载完成"
        INSTALLED=false
    fi
}

# 语言设置（已移除多语言支持）
switch_language() {
    info "当前版本仅支持中文"
    sleep 1
}

# 安全防护
security_protection() {
    while true; do
        clear
        echo -e "${CYAN}======================================${NC}"
        echo -e "${WHITE}           安全防护设置${NC}"
        echo -e "${CYAN}======================================${NC}"
        echo
        
        echo -e "${GREEN}1.${NC} 安装 Fail2ban 防护"
        echo -e "${BLUE}2.${NC} 配置 SSH 安全"
        echo -e "${YELLOW}3.${NC} 设置防火墙规则"
        echo -e "${PURPLE}4.${NC} 查看安全状态"
        echo -e "${RED}0.${NC} 返回主菜单"
        echo
        echo -e "${CYAN}======================================${NC}"
        
        local choice
        reading "请选择操作" choice
        
        case "$choice" in
            1)
                install_fail2ban
                pause
                ;;
            2)
                configure_ssh_security
                pause
                ;;
            3)
                configure_firewall
                pause
                ;;
            4)
                check_security_status
                pause
                ;;
            0)
                return
                ;;
            *)
                warning "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

# 安装Fail2ban
install_fail2ban() {
    info "安装 Fail2ban..."
    
    if command -v fail2ban-server >/dev/null 2>&1; then
        success "Fail2ban 已安装"
        return 0
    fi
    
    apt update -qq
    apt install -y fail2ban >/dev/null 2>&1
    
    if [[ $? -eq 0 ]]; then
        success "Fail2ban 安装成功"
        configure_fail2ban
    else
        error "Fail2ban 安装失败"
        return 1
    fi
}

# 配置Fail2ban
configure_fail2ban() {
    info "配置 Fail2ban..."
    
    # 创建jail.local配置文件
    cat > "/etc/fail2ban/jail.local" << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[sing-box]
enabled = true
port = $SELECTED_PORT
filter = sing-box
logpath = $LOG_FILE
maxretry = 5
bantime = 7200
EOF

    # 创建sing-box过滤器
    cat > "/etc/fail2ban/filter.d/sing-box.conf" << EOF
[Definition]
failregex = ^.*\[ERROR\].*connection from <HOST>.*$
            ^.*\[WARN\].*failed.*<HOST>.*$
ignoreregex =
EOF

    # 启动并启用fail2ban
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        success "Fail2ban 配置完成"
    else
        error "Fail2ban 启动失败"
    fi
}

# 配置SSH安全
configure_ssh_security() {
    info "配置 SSH 安全设置..."
    
    local ssh_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "$ssh_config" ]]; then
        error "SSH 配置文件不存在"
        return 1
    fi
    
    # 备份原配置
    cp "$ssh_config" "${ssh_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # 修改SSH配置
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' "$ssh_config"
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$ssh_config"
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' "$ssh_config"
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' "$ssh_config"
    
    # 添加其他安全设置
    if ! grep -q "Protocol 2" "$ssh_config"; then
        echo "Protocol 2" >> "$ssh_config"
    fi
    
    if ! grep -q "ClientAliveInterval" "$ssh_config"; then
        echo "ClientAliveInterval 300" >> "$ssh_config"
        echo "ClientAliveCountMax 2" >> "$ssh_config"
    fi
    
    # 重启SSH服务
    systemctl restart sshd
    
    if systemctl is-active --quiet sshd; then
        success "SSH 安全配置完成"
        warning "请确保已设置SSH密钥认证，否则可能无法登录"
    else
        error "SSH 服务重启失败"
        # 恢复备份
        cp "${ssh_config}.backup.$(date +%Y%m%d_%H%M%S)" "$ssh_config"
        systemctl restart sshd
    fi
}

# 配置防火墙
configure_firewall() {
    info "配置防火墙规则..."
    
    # 安装ufw
    if ! command -v ufw >/dev/null 2>&1; then
        apt install -y ufw >/dev/null 2>&1
    fi
    
    # 重置防火墙规则
    ufw --force reset >/dev/null 2>&1
    
    # 设置默认策略
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    
    # 允许SSH
    ufw allow ssh >/dev/null 2>&1
    
    # 允许sing-box端口
    if [[ -n "$SELECTED_PORT" ]]; then
        ufw allow "$SELECTED_PORT" >/dev/null 2>&1
    fi
    
    # 允许HTTP和HTTPS（用于证书申请）
    ufw allow 80 >/dev/null 2>&1
    ufw allow 443 >/dev/null 2>&1
    
    # 启用防火墙
    ufw --force enable >/dev/null 2>&1
    
    if ufw status | grep -q "Status: active"; then
        success "防火墙配置完成"
        echo
        ufw status numbered
    else
        error "防火墙配置失败"
    fi
}

# 检查安全状态
check_security_status() {
    echo -e "${CYAN}======================================${NC}"
    echo -e "${WHITE}           安全状态检查${NC}"
    echo -e "${CYAN}======================================${NC}"
    echo
    
    # 检查Fail2ban状态
    echo -e "${GREEN}Fail2ban 状态:${NC}"
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}✓ 运行中${NC}"
        echo "被封禁的IP:"
        fail2ban-client status 2>/dev/null | grep "Jail list" || echo "无数据"
    else
        echo -e "${RED}✗ 未运行${NC}"
    fi
    echo
    
    # 检查SSH配置
    echo -e "${GREEN}SSH 安全配置:${NC}"
    if grep -q "PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "${GREEN}✓ Root登录已禁用${NC}"
    else
        echo -e "${YELLOW}⚠ Root登录未禁用${NC}"
    fi
    
    if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "${GREEN}✓ 密码认证已禁用${NC}"
    else
        echo -e "${YELLOW}⚠ 密码认证未禁用${NC}"
    fi
    echo
    
    # 检查防火墙状态
    echo -e "${GREEN}防火墙状态:${NC}"
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            echo -e "${GREEN}✓ 防火墙已启用${NC}"
            echo "当前规则:"
            ufw status numbered | head -10
        else
            echo -e "${RED}✗ 防火墙未启用${NC}"
        fi
    else
        echo -e "${RED}✗ 防火墙未安装${NC}"
    fi
    echo
    
    # 检查系统更新
    echo -e "${GREEN}系统安全:${NC}"
    local updates
    updates=$(apt list --upgradable 2>/dev/null | wc -l)
    if [[ $updates -gt 1 ]]; then
        echo -e "${YELLOW}⚠ 有 $((updates-1)) 个可用更新${NC}"
    else
        echo -e "${GREEN}✓ 系统已是最新${NC}"
    fi
}

# 脚本入口点
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
