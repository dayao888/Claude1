#!/bin/bash

# SBall - Sing-box 全能安装脚本
# Version: v2.0.0
# Author: SBall Development Team
# License: MIT
# GitHub: https://github.com/dayao888/Claude1

set -e  # 遇到错误立即退出

# 调试模式检查
if [[ "${DEBUG:-false}" == "true" ]]; then
    set -x  # 启用命令跟踪
    echo "[DEBUG] 调试模式已启用"
fi

# 自动修复脚本文件格式（如果可能的话）
if command -v dos2unix >/dev/null 2>&1 && [[ -f "${BASH_SOURCE[0]}" ]]; then
    dos2unix "${BASH_SOURCE[0]}" 2>/dev/null || true
fi

# 全局变量定义
readonly SCRIPT_VERSION="2.0.0"

# 显示脚本基本信息
if [[ "${DEBUG:-false}" == "true" ]]; then
    echo "[DEBUG] 脚本版本: $SCRIPT_VERSION"
    echo "[DEBUG] 脚本路径: ${BASH_SOURCE[0]}"
    echo "[DEBUG] 执行用户: $(whoami)"
    echo "[DEBUG] 系统信息: $(uname -a)"
fi
readonly SCRIPT_NAME="SBall"
readonly GITHUB_REPO="dayao888/Claude1"
readonly SING_BOX_VERSION_API="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
readonly CONFIG_DIR="/etc/sing-box"
readonly LOG_DIR="/var/log/sing-box"
readonly SERVICE_NAME="sing-box"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# 系统信息变量
OS=""
ARCH=""
PACKAGE_MANAGER=""
SERVICE_MANAGER=""

# 配置变量
DOMAIN=""
EMAIL=""
PROTOCOLS=()
SING_BOX_VERSION=""
UUID=""
DOWNLOAD_FILE=""

# =============================================================================
# 工具函数
# =============================================================================

# 日志函数
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 控制台输出（带颜色）
    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC}  ${timestamp} - $message" >&2 ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC}  ${timestamp} - $message" >&2 ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" >&2 ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message" >&2 ;;
    esac
    
    # 写入日志文件（无颜色）
    if [[ -d "$LOG_DIR" ]]; then
        echo "[$level] $timestamp - $message" >> "$LOG_DIR/sball.log"
    fi
}

# 错误处理函数
error_exit() {
    log "ERROR" "$1"
    
    # 显示调试信息
    if [[ "${DEBUG:-false}" == "true" ]]; then
        log "DEBUG" "错误发生时的系统状态:"
        log "DEBUG" "当前用户: $(whoami)"
        log "DEBUG" "当前目录: $(pwd)"
        log "DEBUG" "可用磁盘空间: $(df -h / | tail -1 | awk '{print $4}')"
        log "DEBUG" "内存使用情况: $(free -h | grep Mem | awk '{print $3"/"$2}')"
        if [[ -n "${DOWNLOAD_FILE:-}" && -f "${DOWNLOAD_FILE}" ]]; then
            log "DEBUG" "下载文件状态: $(ls -lh "$DOWNLOAD_FILE")"
        fi
    fi
    
    # 清理可能的临时文件
    cleanup_temp_files
    
    echo -e "\n${RED}脚本执行失败！${NC}"
    echo -e "${YELLOW}如需调试信息，请设置环境变量 DEBUG=true 后重新运行脚本${NC}"
    echo -e "${YELLOW}例如: DEBUG=true bash sball.sh${NC}"
    
    exit 1
}

# 清理临时文件
cleanup_temp_files() {
    local temp_patterns=(
        "/tmp/sing-box-*"
        "/tmp/vless_reality.json"
        "/tmp/hysteria2.json"
        "/tmp/shadowsocks.json"
        "/tmp/trojan.json"
        "/tmp/tuic.json"
        "/tmp/shadowtls.json"
        "/tmp/vmess_ws.json"
        "/tmp/vless_ws.json"
        "/tmp/h2_reality.json"
        "/tmp/grpc_reality.json"
        "/tmp/anytls.json"
    )
    
    for pattern in "${temp_patterns[@]}"; do
        # 使用find而不是通配符，更安全
        find /tmp -name "$(basename "$pattern")" -type f -mtime +1 -delete 2>/dev/null || true
    done
}

# 成功提示函数
success() {
    log "INFO" "$1"
}

# 警告提示函数
warning() {
    log "WARN" "$1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "此脚本需要root权限运行，请使用 sudo 或以root用户身份运行"
    fi
}

# 检查网络连接
check_network() {
    log "INFO" "检查网络连接..."
    if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        error_exit "网络连接失败，请检查网络设置"
    fi
    success "网络连接正常"
}

# 生成UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 生成随机端口
generate_random_port() {
    local min_port=${1:-10000}
    local max_port=${2:-65535}
    local port
    local max_attempts=50
    local attempts=0
    
    while [[ $attempts -lt $max_attempts ]]; do
        port=$(shuf -i $min_port-$max_port -n 1)
        
        # 检查端口是否已被占用
        if ! netstat -tuln | grep -q ":$port "; then
            # 检查端口是否已在配置文件中使用
            if [[ -f "$CONFIG_DIR/connections.txt" ]] && grep -q ":$port:" "$CONFIG_DIR/connections.txt"; then
                ((attempts++))
                continue
            fi
            echo "$port"
            return 0
        fi
        ((attempts++))
    done
    
    error_exit "无法生成可用端口，已尝试 $max_attempts 次"
}

# 生成随机路径
generate_random_path() {
    openssl rand -hex 8
}

# 生成随机密码
generate_random_password() {
    openssl rand -base64 16
}

# =============================================================================
# 系统检测模块
# =============================================================================

# 检测操作系统
detect_os() {
    log "INFO" "检测操作系统..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    else
        error_exit "不支持的操作系统"
    fi
    
    case "$OS" in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            SERVICE_MANAGER="systemctl"
            ;;
        centos|rhel|fedora)
            PACKAGE_MANAGER="yum"
            SERVICE_MANAGER="systemctl"
            # CentOS 8+ 使用 dnf
            if [[ -n $OS_VERSION ]] && [[ $OS_VERSION -ge 8 ]] 2>/dev/null; then
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        *)
            error_exit "不支持的操作系统: $OS"
            ;;
    esac
    
    success "检测到操作系统: $OS"
}

# 检测系统架构
detect_arch() {
    log "INFO" "检测系统架构..."
    
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            error_exit "不支持的系统架构: $arch"
            ;;
    esac
    
    success "检测到系统架构: $ARCH"
}

# 检查系统资源
check_system_requirements() {
    log "INFO" "检查系统资源..."
    
    # 检查内存
    local mem_total=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [[ $mem_total -lt 512 ]]; then
        warning "系统内存不足512MB，可能影响性能"
    fi
    
    # 检查磁盘空间
    local disk_free=$(df / | awk 'NR==2{print $4}')
    if [[ $disk_free -lt 102400 ]]; then  # 100MB in KB
        warning "根目录可用空间不足100MB，可能影响安装"
    fi
    
    success "系统资源检查完成"
}

# 检查必需的命令
check_required_commands() {
    log "INFO" "检查必需的系统命令..."
    
    local required_commands=("curl" "wget" "tar" "gzip" "find" "grep" "awk" "sed" "dos2unix")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log "WARN" "缺少以下必需命令: ${missing_commands[*]}"
        log "INFO" "尝试安装缺少的依赖包..."
        return 1
    else
        success "所有必需命令都已可用"
        return 0
    fi
}

# 安装系统依赖
install_dependencies() {
    log "INFO" "安装系统依赖包..."
    
    # 首先检查必需命令
    if ! check_required_commands; then
        log "INFO" "需要安装基本依赖包"
    fi
    
    local deps_common="curl wget tar gzip openssl python3 file dos2unix"
    local deps_debian="uuid-runtime qrencode jq"
    local deps_centos="util-linux qrencode jq"
    
    case "$PACKAGE_MANAGER" in
        apt)
            apt update
            apt install -y $deps_common $deps_debian
            ;;
        yum)
            yum install -y $deps_common $deps_centos
            ;;
        dnf)
            dnf install -y $deps_common $deps_centos
            ;;
        *)
            error_exit "未知的包管理器: $PACKAGE_MANAGER"
            ;;
    esac
    
    success "系统依赖安装完成"
}

# =============================================================================
# Sing-box 管理模块
# =============================================================================

# 获取最新版本号
get_latest_version() {
    log "INFO" "获取Sing-box最新版本..."
    
    local api_response
    if ! api_response=$(curl -s --connect-timeout 10 "$SING_BOX_VERSION_API"); then
        error_exit "无法获取版本信息，请检查网络连接"
    fi
    
    SING_BOX_VERSION=$(echo "$api_response" | grep -o '"tag_name": *"[^"]*"' | sed 's/"tag_name": *"v\?\([^"]*\)"/\1/')
    
    if [[ -z "$SING_BOX_VERSION" ]]; then
        error_exit "解析版本信息失败"
    fi
    
    success "最新版本: v$SING_BOX_VERSION"
}

# 下载Sing-box
download_sing_box() {
    log "INFO" "下载Sing-box..."
    
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${ARCH}.tar.gz"
    local download_file="/tmp/sing-box-${SING_BOX_VERSION}-linux-${ARCH}.tar.gz"
    
    # 清理可能存在的旧文件
    [[ -f "$download_file" ]] && rm -f "$download_file"
    
    log "INFO" "下载地址: $download_url"
    log "INFO" "保存路径: $download_file"
    
    # 下载文件，使用更详细的选项
    local download_success=false
    local download_attempts=0
    local max_attempts=3
    
    while [[ $download_attempts -lt $max_attempts && $download_success == false ]]; do
        ((download_attempts++))
        log "INFO" "下载尝试 $download_attempts/$max_attempts"
        
        # 使用wget下载，完全静默模式避免输出污染
        if wget -q -O "$download_file" "$download_url" \
            --timeout=30 \
            --tries=1 \
            --no-verbose; then
            download_success=true
            log "INFO" "wget下载成功"
            break
        else
            local wget_exit_code=$?
            log "WARN" "wget下载失败，错误代码: $wget_exit_code"
            [[ -f "$download_file" ]] && rm -f "$download_file"
            
            if [[ $download_attempts -lt $max_attempts ]]; then
                log "INFO" "等待5秒后重试..."
                sleep 5
            fi
        fi
    done
    
    if [[ $download_success == false ]]; then
        log "WARN" "wget下载失败，尝试使用curl..."
        
        # 重置尝试次数，使用curl作为备用方案
        download_attempts=0
        while [[ $download_attempts -lt $max_attempts && $download_success == false ]]; do
            ((download_attempts++))
            log "INFO" "curl下载尝试 $download_attempts/$max_attempts"
            
            if command -v curl >/dev/null 2>&1; then
                if curl -s -L -o "$download_file" "$download_url" \
                    --connect-timeout 30 \
                    --max-time 300 \
                    --retry 0 \
                    --fail; then
                    download_success=true
                    log "INFO" "curl下载成功"
                    break
                else
                    local curl_exit_code=$?
                    log "WARN" "curl下载失败，错误代码: $curl_exit_code"
                    [[ -f "$download_file" ]] && rm -f "$download_file"
                    
                    if [[ $download_attempts -lt $max_attempts ]]; then
                        log "INFO" "等待5秒后重试..."
                        sleep 5
                    fi
                fi
            else
                log "ERROR" "curl命令不可用"
                break
            fi
        done
        
        if [[ $download_success == false ]]; then
            error_exit "下载失败，wget和curl都无法下载文件。请检查网络连接和下载地址: $download_url"
        fi
    fi
    
    # 验证下载的文件
    if [[ ! -f "$download_file" ]]; then
        error_exit "下载的文件不存在: $download_file"
    fi
    
    if [[ ! -s "$download_file" ]]; then
        error_exit "下载的文件为空: $download_file"
    fi
    
    # 验证文件类型
    local file_type
    file_type=$(file "$download_file" 2>/dev/null || echo "unknown")
    if [[ ! "$file_type" =~ "gzip compressed" ]] && [[ ! "$file_type" =~ "compressed data" ]]; then
        log "WARN" "文件类型可能异常: $file_type"
        # 检查文件头部是否为gzip格式
        local file_header
        file_header=$(hexdump -C "$download_file" | head -1 | awk '{print $2$3}')
        if [[ "$file_header" != "1f8b" ]]; then
            log "ERROR" "文件不是有效的gzip格式，文件头: $file_header"
            log "INFO" "文件前几个字节:"
            hexdump -C "$download_file" | head -3
            error_exit "下载的文件格式错误"
        fi
    fi
    
    # 显示文件大小
    local file_size
    file_size=$(ls -lh "$download_file" | awk '{print $5}')
    success "下载完成: $download_file (大小: $file_size)"
    
    # 设置全局变量
    DOWNLOAD_FILE="$download_file"
    
    # 返回成功状态
    return 0
}

# 安装Sing-box
install_sing_box() {
    local download_file="$1"
    
    log "INFO" "安装Sing-box..."
    
    # 验证输入文件
    if [[ -z "$download_file" ]]; then
        error_exit "未提供下载文件路径"
    fi
    
    if [[ ! -f "$download_file" ]]; then
        error_exit "下载文件不存在: $download_file"
    fi
    
    # 再次验证文件完整性
    log "INFO" "验证下载文件: $download_file"
    local file_info
    file_info=$(file "$download_file")
    log "INFO" "文件类型: $file_info"
    
    if [[ ! "$file_info" =~ "gzip compressed" ]] && [[ ! "$file_info" =~ "compressed data" ]]; then
        log "ERROR" "文件不是有效的gzip压缩文件: $file_info"
        log "INFO" "文件大小: $(ls -lh "$download_file" | awk '{print $5}')"
        log "INFO" "文件头部信息:"
        hexdump -C "$download_file" | head -2
        error_exit "文件格式验证失败"
    fi
    
    # 创建临时目录
    local temp_dir="/tmp/sing-box-install-$$"
    log "INFO" "创建临时目录: $temp_dir"
    
    if ! mkdir -p "$temp_dir"; then
        error_exit "无法创建临时目录: $temp_dir"
    fi
    
    # 测试tar文件完整性
    log "INFO" "测试压缩文件完整性..."
    if ! tar -tzf "$download_file" >/dev/null 2>&1; then
        rm -rf "$temp_dir"
        error_exit "压缩文件损坏或格式错误"
    fi
    
    # 解压文件
    log "INFO" "解压文件到: $temp_dir"
    if ! tar -xzf "$download_file" -C "$temp_dir" >/dev/null 2>&1; then
        local tar_error=$?
        log "ERROR" "tar解压失败，错误代码: $tar_error"
        log "INFO" "尝试列出压缩文件内容:"
        if tar -tzf "$download_file" >/dev/null 2>&1; then
            log "INFO" "压缩文件内容列表:"
            tar -tzf "$download_file" | head -10
        else
            log "ERROR" "无法列出压缩文件内容，文件可能已损坏"
        fi
        rm -rf "$temp_dir"
        error_exit "解压失败，错误代码: $tar_error"
    fi
    
    # 列出解压的内容
    log "INFO" "解压内容:"
    ls -la "$temp_dir"
    
    # 查找二进制文件
    log "INFO" "查找sing-box二进制文件..."
    local binary_file
    binary_file=$(find "$temp_dir" -name "sing-box" -type f -executable 2>/dev/null | head -1)
    
    if [[ -z "$binary_file" ]]; then
        # 尝试查找任何名为sing-box的文件
        binary_file=$(find "$temp_dir" -name "sing-box" -type f 2>/dev/null | head -1)
        if [[ -z "$binary_file" ]]; then
            log "ERROR" "在解压目录中未找到sing-box文件"
            log "INFO" "解压目录结构:"
            find "$temp_dir" -type f
            rm -rf "$temp_dir"
            error_exit "未找到sing-box二进制文件"
        fi
    fi
    
    log "INFO" "找到二进制文件: $binary_file"
    
    # 验证二进制文件
    if [[ ! -f "$binary_file" ]]; then
        rm -rf "$temp_dir"
        error_exit "二进制文件不存在: $binary_file"
    fi
    
    # 检查文件类型
    local binary_info
    binary_info=$(file "$binary_file")
    log "INFO" "二进制文件信息: $binary_info"
    
    # 安装二进制文件
    log "INFO" "安装二进制文件到 /usr/local/bin/sing-box"
    chmod +x "$binary_file"
    
    if ! cp "$binary_file" /usr/local/bin/sing-box; then
        rm -rf "$temp_dir"
        error_exit "无法复制二进制文件到 /usr/local/bin/"
    fi
    
    # 验证安装
    if command -v sing-box >/dev/null 2>&1; then
        local version_info
        version_info=$(sing-box version 2>/dev/null | head -1)
        log "INFO" "Sing-box版本: $version_info"
    else
        log "WARN" "sing-box命令不在PATH中，但文件已复制"
    fi
    
    # 创建必要目录
    log "INFO" "创建配置和日志目录"
    mkdir -p "$CONFIG_DIR" "$LOG_DIR"
    
    # 清理临时文件
    log "INFO" "清理临时文件"
    rm -rf "$temp_dir" "$download_file"
    
    success "Sing-box安装完成"
}

# 创建systemd服务
create_systemd_service() {
    log "INFO" "创建systemd服务..."
    
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box
    
    success "systemd服务创建完成"
}

# =============================================================================
# 配置管理模块
# =============================================================================

# 生成基础配置
generate_base_config() {
    log "INFO" "生成基础配置..."
    
    UUID=$(generate_uuid)
    
    cat > "$CONFIG_DIR/config.json" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_DIR/sing-box.log",
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
        "geoip": "private",
        "outbound": "direct"
      },
      {
        "geosite": "cn",
        "outbound": "direct"
      }
    ],
    "auto_detect_interface": true
  }
}
EOF
    
    success "基础配置生成完成"
}

# 添加VLESS-Reality协议
add_vless_reality() {
    local port=$(generate_random_port)
    local dest_port=443
    local server_name="www.google.com"
    # 生成Reality密钥对
    local keypair_output
    if ! keypair_output=$(sing-box generate reality-keypair 2>/dev/null); then
        error_exit "无法生成Reality密钥对，请检查sing-box是否正确安装"
    fi
    
    local private_key=$(echo "$keypair_output" | grep "PrivateKey" | awk '{print $2}')
    local public_key=$(echo "$keypair_output" | grep "PublicKey" | awk '{print $2}')
    
    if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
        error_exit "Reality密钥对生成失败"
    fi
    
    log "INFO" "添加VLESS-Reality配置 (端口: $port)..."
    
    # 创建临时配置文件来添加inbound
    local temp_config="/tmp/vless_reality.json"
    cat > "$temp_config" << EOF
{
  "type": "vless",
  "tag": "vless-reality-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$UUID",
      "flow": "xtls-rprx-vision"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$server_name",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "$server_name",
        "server_port": $dest_port
      },
      "private_key": "$private_key",
      "short_id": ["0123456789abcdef"]
    }
  }
}
EOF
    
    # 将配置添加到主配置文件中
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    # 保存连接信息
    echo "VLESS-Reality:$port:$UUID:$public_key" >> "$CONFIG_DIR/connections.txt"
    
    success "VLESS-Reality配置添加完成"
}

# 添加Hysteria2协议
add_hysteria2() {
    local port=$(generate_random_port)
    local password=$(generate_random_password)
    
    log "INFO" "添加Hysteria2配置 (端口: $port)..."
    
    local temp_config="/tmp/hysteria2.json"
    cat > "$temp_config" << EOF
{
  "type": "hysteria2",
  "tag": "hysteria2-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "password": "$password"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "www.bing.com",
    "insecure": true
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "Hysteria2:$port:$password" >> "$CONFIG_DIR/connections.txt"
    
    success "Hysteria2配置添加完成"
}

# 添加Shadowsocks协议
add_shadowsocks() {
    local port=$(generate_random_port)
    local password=$(generate_random_password)
    local method="2022-blake3-aes-128-gcm"
    
    log "INFO" "添加Shadowsocks配置 (端口: $port)..."
    
    local temp_config="/tmp/shadowsocks.json"
    cat > "$temp_config" << EOF
{
  "type": "shadowsocks",
  "tag": "shadowsocks-in",
  "listen": "::",
  "listen_port": $port,
  "method": "$method",
  "password": "$password"
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "Shadowsocks:$port:$method:$password" >> "$CONFIG_DIR/connections.txt"
    
    success "Shadowsocks配置添加完成"
}

# 添加Trojan协议
add_trojan() {
    local port=$(generate_random_port)
    local password=$(generate_random_password)
    
    log "INFO" "添加Trojan配置 (端口: $port)..."
    
    local temp_config="/tmp/trojan.json"
    cat > "$temp_config" << EOF
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
    "server_name": "www.microsoft.com",
    "insecure": true
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "Trojan:$port:$password" >> "$CONFIG_DIR/connections.txt"
    
    success "Trojan配置添加完成"
}

# 工具函数：将inbound添加到主配置文件
add_inbound_to_config() {
    local temp_config="$1"
    
    # 检查配置文件是否存在
    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        error_exit "配置文件不存在: $CONFIG_DIR/config.json"
    fi
    
    # 使用jq来合并配置（如果没有jq，使用简单的文本处理）
    if command -v jq >/dev/null 2>&1; then
        local new_config
        new_config=$(jq --argjson inbound "$(cat "$temp_config")" '.inbounds += [$inbound]' "$CONFIG_DIR/config.json")
        echo "$new_config" > "$CONFIG_DIR/config.json"
    else
        # 改进的文本处理方式
        local inbound_content
        inbound_content=$(cat "$temp_config" | tr -d '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # 备份原文件
        cp "$CONFIG_DIR/config.json" "$CONFIG_DIR/config.json.bak"
        
        # 检查是否是空的inbounds数组
        if grep -q '"inbounds":[[:space:]]*\[\]' "$CONFIG_DIR/config.json"; then
            # 如果是空数组，直接添加
            sed -i "s/\"inbounds\":[[:space:]]*\[\]/\"inbounds\": [$inbound_content]/" "$CONFIG_DIR/config.json"
        else
            # 使用Python处理JSON（更安全可靠）
            if ! python3 -c "
import json
import sys
try:
    with open('$CONFIG_DIR/config.json', 'r') as f:
        config = json.load(f)
    
    # 读取新的inbound配置
    with open('$temp_config', 'r') as f:
        new_inbound = json.load(f)
    
    # 添加到inbounds数组
    config['inbounds'].append(new_inbound)
    
    # 写回文件
    with open('$CONFIG_DIR/config.json', 'w') as f:
        json.dump(config, f, indent=2)
    print('JSON配置更新成功')
except Exception as e:
    print(f'Python处理失败: {e}', file=sys.stderr)
    sys.exit(1)
"; then
                # Python失败，使用简化的sed方案
                warning "Python JSON处理失败，使用备用方案"
                # 简单地在inbounds数组末尾前添加新配置
                local last_brace_line=$(grep -n '^[[:space:]]*]' "$CONFIG_DIR/config.json" | tail -1 | cut -d: -f1)
                if [[ -n $last_brace_line ]]; then
                    sed -i "${last_brace_line}i\\  ,$inbound_content" "$CONFIG_DIR/config.json"
                else
                    error_exit "无法找到JSON数组结束位置"
                fi
            fi
        fi
        
        # 验证JSON格式
        if ! python3 -m json.tool "$CONFIG_DIR/config.json" >/dev/null 2>&1; then
            warning "JSON格式验证失败，恢复备份文件"
            mv "$CONFIG_DIR/config.json.bak" "$CONFIG_DIR/config.json"
        else
            rm -f "$CONFIG_DIR/config.json.bak"
        fi
    fi
}

# =============================================================================
# 安全防护模块
# =============================================================================

# 配置防火墙
configure_firewall() {
    log "INFO" "配置防火墙规则..."
    
    # 检查防火墙类型
    if command -v ufw >/dev/null 2>&1; then
        configure_ufw
    elif command -v firewall-cmd >/dev/null 2>&1; then
        configure_firewalld
    elif command -v iptables >/dev/null 2>&1; then
        configure_iptables
    else
        warning "未检测到防火墙，请手动配置端口开放"
    fi
}

# 配置UFW防火墙
configure_ufw() {
    # 获取所有需要开放的端口
    local ports=()
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        while IFS= read -r line; do
            local port=$(echo "$line" | cut -d':' -f2)
            ports+=("$port")
        done < "$CONFIG_DIR/connections.txt"
    fi
    
    # 开放端口
    for port in "${ports[@]}"; do
        ufw allow "$port" >/dev/null 2>&1
    done
    
    success "UFW防火墙规则配置完成"
}

# 配置Firewalld防火墙
configure_firewalld() {
    local ports=()
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        while IFS= read -r line; do
            local port=$(echo "$line" | cut -d':' -f2)
            ports+=("$port")
        done < "$CONFIG_DIR/connections.txt"
    fi
    
    for port in "${ports[@]}"; do
        firewall-cmd --permanent --add-port="$port/tcp" >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$port/udp" >/dev/null 2>&1
    done
    
    firewall-cmd --reload >/dev/null 2>&1
    success "Firewalld防火墙规则配置完成"
}

# 配置iptables防火墙
configure_iptables() {
    local ports=()
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        while IFS= read -r line; do
            local port=$(echo "$line" | cut -d':' -f2)
            ports+=("$port")
        done < "$CONFIG_DIR/connections.txt"
    fi
    
    for port in "${ports[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
    done
    
    # 保存规则
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    success "iptables防火墙规则配置完成"
}

# 安装fail2ban
install_fail2ban() {
    log "INFO" "安装fail2ban防护..."
    
    case "$PACKAGE_MANAGER" in
        apt)
            apt install -y fail2ban
            ;;
        yum|dnf)
            $PACKAGE_MANAGER install -y epel-release
            $PACKAGE_MANAGER install -y fail2ban
            ;;
    esac
    
    # 创建fail2ban配置
    cat > /etc/fail2ban/jail.d/sing-box.conf << EOF
[sing-box]
enabled = true
port = 1:65535
filter = sing-box
logpath = $LOG_DIR/sing-box.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    # 创建过滤规则
    cat > /etc/fail2ban/filter.d/sing-box.conf << 'EOF'
[Definition]
failregex = ^.*\[ERROR\].*client <HOST>.*$
ignoreregex =
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    success "fail2ban防护配置完成"
}

# =============================================================================
# 系统优化模块
# =============================================================================

# 启用BBR
enable_bbr() {
    log "INFO" "启用BBR网络加速..."
    
    # 检查内核版本
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)
    
    if ! awk "BEGIN {exit ($kernel_version >= 4.9) ? 0 : 1}"; then
        warning "内核版本过低，BBR可能不支持"
        return
    fi
    
    # 配置BBR
    if ! grep -q "net.core.default_qdisc" /etc/sysctl.conf; then
        echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
    fi
    
    if ! grep -q "net.ipv4.tcp_congestion_control" /etc/sysctl.conf; then
        echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
    fi
    
    sysctl -p >/dev/null 2>&1
    
    success "BBR网络加速已启用"
}

# 系统参数优化
optimize_system() {
    log "INFO" "进行系统参数优化..."
    
    # 网络参数优化
    cat >> /etc/sysctl.conf << 'EOF'

# Network optimization for sing-box
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_rmem = 4096 65536 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
EOF
    
    sysctl -p >/dev/null 2>&1
    
    success "系统参数优化完成"
}

# =============================================================================
# 主菜单系统
# =============================================================================

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${CYAN}"
    echo "================= Sing-box 科学上网管理面板 ================="
    echo -e "${NC}"
    echo -e "  ${GREEN}1.${NC} 安装 / 更新 Sing-box"
    echo -e "  ${GREEN}2.${NC} 卸载 Sing-box"
    echo "  -----------------------------------------------------------"
    echo -e "  ${GREEN}3.${NC} 协议管理"
    echo "     - 添加/删除协议"
    echo "     - 修改协议配置"
    echo "     - 查看协议状态"
    echo "  -----------------------------------------------------------"
    echo -e "  ${GREEN}4.${NC} 系统信息"
    echo "     - 查看端口占用情况"
    echo "     - 查看网络优化状态"
    echo "     - 查看 fail2ban 封禁列表"
    echo "  -----------------------------------------------------------"
    echo -e "  ${GREEN}5.${NC} 证书管理"
    echo "     - 自动申请/更新证书"
    echo "     - 本地自签证书"
    echo "     - 导入自有证书"
    echo "  -----------------------------------------------------------"
    echo -e "  ${GREEN}6.${NC} 防火墙与安全"
    echo "     - BBR开关控制"
    echo "     - TCP FastOpen设置"
    echo "     - fail2ban配置"
    echo "     - IP白名单/黑名单管理"
    echo "  -----------------------------------------------------------"
    echo -e "  ${GREEN}7.${NC} 服务管理"
    echo "     - 启动/停止/重启服务"
    echo "     - 查看运行状态"
    echo "     - 查看系统日志"
    echo "  -----------------------------------------------------------"
    echo -e "  ${GREEN}8.${NC} 客户端配置"
    echo "     - 生成订阅链接"
    echo "     - 生成配置二维码"
    echo "     - 查看节点信息"
    echo "  -----------------------------------------------------------"
    echo -e "  ${GREEN}9.${NC} 高级设置"
    echo "     - CDN配置"
    echo "     - 伪装站点设置"
    echo "     - TLS指纹配置"
    echo "     - 多入口配置"
    echo "  -----------------------------------------------------------"
    echo -e "${CYAN}"
    echo "============================================================="
    echo -e "${NC}"
    echo -e "  ${RED}0.${NC} 退出"
    echo ""
    echo -ne "请选择操作 [0-9]: "
}

# 处理主菜单选择
handle_main_menu() {
    local choice
    read -r choice
    
    case $choice in
        1) install_menu ;;
        2) uninstall_menu ;;
        3) protocol_menu ;;
        4) system_info_menu ;;
        5) certificate_menu ;;
        6) security_menu ;;
        7) service_menu ;;
        8) client_config_menu ;;
        9) advanced_menu ;;
        0) exit 0 ;;
        *) 
            echo -e "${RED}无效选择，请重新输入${NC}"
            sleep 2
            ;;
    esac
}

# 安装菜单
install_menu() {
    log "INFO" "开始安装Sing-box..."
    
    # 系统检测
    detect_os
    detect_arch
    check_system_requirements
    
    # 安装依赖
    install_dependencies
    
    # 下载并安装Sing-box
    get_latest_version
    download_sing_box
    install_sing_box "$DOWNLOAD_FILE"
    
    # 创建服务
    create_systemd_service
    
    # 生成配置
    generate_base_config
    
    # 添加默认协议
    add_vless_reality
    add_hysteria2
    add_shadowsocks
    add_trojan
    add_anytls
    
    # 配置安全
    configure_firewall
    install_fail2ban
    
    # 系统优化
    enable_bbr
    optimize_system
    
    # 启动服务
    systemctl start sing-box
    
    success "Sing-box安装完成！"
    show_connection_info
    
    echo -e "\n按回车键返回主菜单..."
    read -r
}

# 显示连接信息
show_connection_info() {
    echo -e "\n${CYAN}=== 连接信息 ===${NC}"
    
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        local server_ip
        server_ip=$(curl -s ipinfo.io/ip || curl -s ifconfig.me || echo "获取失败")
        
        while IFS= read -r line; do
            local protocol=$(echo "$line" | cut -d':' -f1)
            local port=$(echo "$line" | cut -d':' -f2)
            
            echo -e "\n${GREEN}[$protocol]${NC}"
            echo -e "服务器地址: ${YELLOW}$server_ip${NC}"
            echo -e "端口: ${YELLOW}$port${NC}"
            
            case $protocol in
                "VLESS-Reality")
                    local uuid=$(echo "$line" | cut -d':' -f3)
                    local public_key=$(echo "$line" | cut -d':' -f4)
                    echo -e "UUID: ${YELLOW}$uuid${NC}"
                    echo -e "公钥: ${YELLOW}$public_key${NC}"
                    ;;
                "Hysteria2"|"Trojan"|"AnyTLS")
                    local password=$(echo "$line" | cut -d':' -f3)
                    echo -e "密码: ${YELLOW}$password${NC}"
                    ;;
                "Shadowsocks")
                    local method=$(echo "$line" | cut -d':' -f3)
                    local password=$(echo "$line" | cut -d':' -f4)
                    echo -e "加密方法: ${YELLOW}$method${NC}"
                    echo -e "密码: ${YELLOW}$password${NC}"
                    ;;
            esac
        done < "$CONFIG_DIR/connections.txt"
    else
        echo -e "${RED}未找到连接信息文件${NC}"
    fi
}

# 卸载菜单
uninstall_menu() {
    echo -e "${RED}警告: 此操作将完全删除Sing-box及其配置文件！${NC}"
    echo -ne "确认卸载? [y/N]: "
    read -r confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        log "INFO" "开始卸载Sing-box..."
        
        # 停止服务
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        
        # 删除服务文件
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload
        
        # 删除二进制文件
        rm -f /usr/local/bin/sing-box
        
        # 删除配置目录
        rm -rf "$CONFIG_DIR"
        rm -rf "$LOG_DIR"
        
        # 删除fail2ban配置
        rm -f /etc/fail2ban/jail.d/sing-box.conf
        rm -f /etc/fail2ban/filter.d/sing-box.conf
        systemctl restart fail2ban 2>/dev/null || true
        
        success "Sing-box卸载完成"
    else
        log "INFO" "取消卸载操作"
    fi
    
    echo -e "\n按回车键返回主菜单..."
    read -r
}

# 协议管理菜单
protocol_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 协议管理 ===${NC}\n"
        echo -e "  ${GREEN}1.${NC} 添加协议"
        echo -e "  ${GREEN}2.${NC} 删除协议"
        echo -e "  ${GREEN}3.${NC} 查看协议状态"
        echo -e "  ${GREEN}4.${NC} 重新生成配置"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        echo -ne "请选择操作 [0-4]: "
        
        local choice
        read -r choice
        
        case $choice in
            1) add_protocol_menu ;;
            2) remove_protocol_menu ;;
            3) show_protocol_status ;;
            4) regenerate_config ;;
            0) break ;;
            *) 
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
    done
}

# 添加协议菜单
add_protocol_menu() {
    clear
    echo -e "${CYAN}=== 添加协议 ===${NC}\n"
    echo -e "  ${GREEN}1.${NC} VLESS-Reality"
    echo -e "  ${GREEN}2.${NC} Hysteria2"
    echo -e "  ${GREEN}3.${NC} TUIC"
    echo -e "  ${GREEN}4.${NC} ShadowTLS"
    echo -e "  ${GREEN}5.${NC} Shadowsocks"
    echo -e "  ${GREEN}6.${NC} Trojan"
    echo -e "  ${GREEN}7.${NC} VMess-WS"
    echo -e "  ${GREEN}8.${NC} VLESS-WS"
    echo -e "  ${GREEN}9.${NC} H2-Reality"
    echo -e "  ${GREEN}10.${NC} gRPC-Reality"
    echo -e "  ${GREEN}11.${NC} AnyTLS"
    echo -e "  ${GREEN}12.${NC} 添加所有协议"
    echo -e "  ${RED}0.${NC} 返回"
    echo ""
    echo -ne "请选择要添加的协议 [0-12]: "
    
    local choice
    read -r choice
    
    case $choice in
        1) add_vless_reality ;;
        2) add_hysteria2 ;;
        3) add_tuic ;;
        4) add_shadowtls ;;
        5) add_shadowsocks ;;
        6) add_trojan ;;
        7) add_vmess_ws ;;
        8) add_vless_ws ;;
        9) add_h2_reality ;;
        10) add_grpc_reality ;;
        11) add_anytls ;;
        12) add_all_protocols ;;
        0) return ;;
        *) 
            echo -e "${RED}无效选择${NC}"
            sleep 1
            ;;
    esac
    
    # 重启服务以应用新配置
    systemctl restart sing-box
    echo -e "\n按回车键继续..."
    read -r
}

# 添加TUIC协议
add_tuic() {
    local port=$(generate_random_port)
    local password=$(generate_random_password)
    
    log "INFO" "添加TUIC配置 (端口: $port)..."
    
    local temp_config="/tmp/tuic.json"
    cat > "$temp_config" << EOF
{
  "type": "tuic",
  "tag": "tuic-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$UUID",
      "password": "$password"
    }
  ],
  "congestion_control": "cubic",
  "auth_timeout": "3s",
  "zero_rtt_handshake": false,
  "heartbeat": "10s"
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "TUIC:$port:$password" >> "$CONFIG_DIR/connections.txt"
    
    success "TUIC配置添加完成"
}

# 添加ShadowTLS协议
add_shadowtls() {
    local port=$(generate_random_port)
    local password=$(generate_random_password)
    
    log "INFO" "添加ShadowTLS配置 (端口: $port)..."
    
    local temp_config="/tmp/shadowtls.json"
    cat > "$temp_config" << EOF
{
  "type": "shadowtls",
  "tag": "shadowtls-in",
  "listen": "::",
  "listen_port": $port,
  "version": 3,
  "password": "$password",
  "users": [
    {
      "password": "$password"
    }
  ],
  "handshake": {
    "server": "www.cloudflare.com",
    "server_port": 443
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "ShadowTLS:$port:$password" >> "$CONFIG_DIR/connections.txt"
    
    success "ShadowTLS配置添加完成"
}

# 添加VMess-WS协议
add_vmess_ws() {
    local port=$(generate_random_port)
    local path="/$(generate_random_path)"
    
    log "INFO" "添加VMess-WS配置 (端口: $port)..."
    
    local temp_config="/tmp/vmess_ws.json"
    cat > "$temp_config" << EOF
{
  "type": "vmess",
  "tag": "vmess-ws-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$UUID",
      "alterId": 0
    }
  ],
  "transport": {
    "type": "ws",
    "path": "$path",
    "max_early_data": 0,
    "early_data_header_name": "Sec-WebSocket-Protocol"
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "VMess-WS:$port:$path" >> "$CONFIG_DIR/connections.txt"
    
    success "VMess-WS配置添加完成"
}

# 添加VLESS-WS协议
add_vless_ws() {
    local port=$(generate_random_port)
    local path="/$(generate_random_path)"
    
    log "INFO" "添加VLESS-WS配置 (端口: $port)..."
    
    local temp_config="/tmp/vless_ws.json"
    cat > "$temp_config" << EOF
{
  "type": "vless",
  "tag": "vless-ws-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$UUID"
    }
  ],
  "transport": {
    "type": "ws",
    "path": "$path",
    "max_early_data": 0,
    "early_data_header_name": "Sec-WebSocket-Protocol"
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "VLESS-WS:$port:$path" >> "$CONFIG_DIR/connections.txt"
    
    success "VLESS-WS配置添加完成"
}

# 添加H2-Reality协议
add_h2_reality() {
    local port=$(generate_random_port)
    local server_name="www.microsoft.com"
    # 生成Reality密钥对
    local keypair_output
    if ! keypair_output=$(sing-box generate reality-keypair 2>/dev/null); then
        error_exit "无法生成Reality密钥对，请检查sing-box是否正确安装"
    fi
    
    local private_key=$(echo "$keypair_output" | grep "PrivateKey" | awk '{print $2}')
    local public_key=$(echo "$keypair_output" | grep "PublicKey" | awk '{print $2}')
    
    if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
        error_exit "Reality密钥对生成失败"
    fi
    
    log "INFO" "添加H2-Reality配置 (端口: $port)..."
    
    local temp_config="/tmp/h2_reality.json"
    cat > "$temp_config" << EOF
{
  "type": "vless",
  "tag": "h2-reality-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$UUID",
      "flow": ""
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$server_name",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "$server_name",
        "server_port": 443
      },
      "private_key": "$private_key",
      "short_id": ["0123456789abcdef"]
    }
  },
  "transport": {
    "type": "http"
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "H2-Reality:$port:$UUID:$public_key" >> "$CONFIG_DIR/connections.txt"
    
    success "H2-Reality配置添加完成"
}

# 添加gRPC-Reality协议
add_grpc_reality() {
    local port=$(generate_random_port)
    local server_name="www.apple.com"
    local service_name="$(generate_random_path)"
    # 生成Reality密钥对
    local keypair_output
    if ! keypair_output=$(sing-box generate reality-keypair 2>/dev/null); then
        error_exit "无法生成Reality密钥对，请检查sing-box是否正确安装"
    fi
    
    local private_key=$(echo "$keypair_output" | grep "PrivateKey" | awk '{print $2}')
    local public_key=$(echo "$keypair_output" | grep "PublicKey" | awk '{print $2}')
    
    if [[ -z "$private_key" ]] || [[ -z "$public_key" ]]; then
        error_exit "Reality密钥对生成失败"
    fi
    
    log "INFO" "添加gRPC-Reality配置 (端口: $port)..."
    
    local temp_config="/tmp/grpc_reality.json"
    cat > "$temp_config" << EOF
{
  "type": "vless",
  "tag": "grpc-reality-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$UUID",
      "flow": ""
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$server_name",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "$server_name",
        "server_port": 443
      },
      "private_key": "$private_key",
      "short_id": ["0123456789abcdef"]
    }
  },
  "transport": {
    "type": "grpc",
    "service_name": "$service_name"
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "gRPC-Reality:$port:$service_name:$public_key" >> "$CONFIG_DIR/connections.txt"
    
    success "gRPC-Reality配置添加完成"
}

# 添加AnyTLS协议
add_anytls() {
    local port=$(generate_random_port)
    local password=$(generate_random_password)
    
    log "INFO" "添加AnyTLS配置 (端口: $port)..."
    
    local temp_config="/tmp/anytls.json"
    cat > "$temp_config" << EOF
{
  "type": "trojan",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "password": "$password"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "www.cloudflare.com",
    "insecure": false,
    "min_version": "1.2",
    "max_version": "1.3",
    "cipher_suites": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256"
    ],
    "curve_preferences": [
      "X25519",
      "P-256",
      "P-384"
    ]
  }
}
EOF
    
    add_inbound_to_config "$temp_config"
    rm -f "$temp_config"
    
    echo "AnyTLS:$port:$password" >> "$CONFIG_DIR/connections.txt"
    
    success "AnyTLS配置添加完成"
}

# 添加所有协议
add_all_protocols() {
    log "INFO" "添加所有协议配置..."
    
    add_vless_reality
    add_hysteria2
    add_tuic
    add_shadowtls
    add_shadowsocks
    add_trojan
    add_vmess_ws
    add_vless_ws
    add_h2_reality
    add_grpc_reality
    add_anytls
    
    success "所有协议配置添加完成"
}

# 服务管理菜单
service_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 服务管理 ===${NC}\n"
        
        # 显示服务状态
        local status
        if systemctl is-active sing-box >/dev/null 2>&1; then
            status="${GREEN}运行中${NC}"
        else
            status="${RED}已停止${NC}"
        fi
        
        echo -e "当前状态: $status\n"
        
        echo -e "  ${GREEN}1.${NC} 启动服务"
        echo -e "  ${GREEN}2.${NC} 停止服务"
        echo -e "  ${GREEN}3.${NC} 重启服务"
        echo -e "  ${GREEN}4.${NC} 查看状态"
        echo -e "  ${GREEN}5.${NC} 查看日志"
        echo -e "  ${GREEN}6.${NC} 实时日志"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        echo -ne "请选择操作 [0-6]: "
        
        local choice
        read -r choice
        
        case $choice in
            1) 
                systemctl start sing-box
                success "服务已启动"
                ;;
            2) 
                systemctl stop sing-box
                success "服务已停止"
                ;;
            3) 
                systemctl restart sing-box
                success "服务已重启"
                ;;
            4) 
                systemctl status sing-box
                ;;
            5) 
                journalctl -u sing-box --no-pager
                ;;
            6) 
                echo "按Ctrl+C退出日志监控"
                journalctl -u sing-box -f
                ;;
            0) break ;;
            *) 
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
        
        if [[ $choice != 6 ]]; then
            echo -e "\n按回车键继续..."
            read -r
        fi
    done
}

# 客户端配置菜单
client_config_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 客户端配置 ===${NC}\n"
        echo -e "  ${GREEN}1.${NC} 生成订阅链接"
        echo -e "  ${GREEN}2.${NC} 生成配置二维码"
        echo -e "  ${GREEN}3.${NC} 查看节点信息"
        echo -e "  ${GREEN}4.${NC} 导出配置文件"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        echo -ne "请选择操作 [0-4]: "
        
        local choice
        read -r choice
        
        case $choice in
            1) generate_subscription ;;
            2) generate_qrcode ;;
            3) show_connection_info ;;
            4) export_configs ;;
            0) break ;;
            *) 
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
        
        echo -e "\n按回车键继续..."
        read -r
    done
}

# 生成订阅链接
generate_subscription() {
    log "INFO" "生成订阅链接..."
    
    local server_ip
    server_ip=$(curl -s ipinfo.io/ip || curl -s ifconfig.me || echo "127.0.0.1")
    
    local subscription_content=""
    
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        while IFS= read -r line; do
            local protocol=$(echo "$line" | cut -d':' -f1)
            local port=$(echo "$line" | cut -d':' -f2)
            
            case $protocol in
                "VLESS-Reality")
                    local uuid=$(echo "$line" | cut -d':' -f3)
                    local public_key=$(echo "$line" | cut -d':' -f4)
                    local vless_url="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.google.com&fp=chrome&pbk=${public_key}&sid=0123456789abcdef&type=tcp&headerType=none#VLESS-Reality-${port}"
                    subscription_content+="${vless_url}\n"
                    ;;
                "Shadowsocks")
                    local method=$(echo "$line" | cut -d':' -f3)
                    local password=$(echo "$line" | cut -d':' -f4)
                    local ss_url="ss://$(echo -n "${method}:${password}" | base64 -w 0)@${server_ip}:${port}#Shadowsocks-${port}"
                    subscription_content+="${ss_url}\n"
                    ;;
                "Trojan")
                    local password=$(echo "$line" | cut -d':' -f3)
                    local trojan_url="trojan://${password}@${server_ip}:${port}?security=tls&sni=www.microsoft.com&type=tcp&headerType=none#Trojan-${port}"
                    subscription_content+="${trojan_url}\n"
                    ;;
                "AnyTLS")
                    local password=$(echo "$line" | cut -d':' -f3)
                    local anytls_url="trojan://${password}@${server_ip}:${port}?security=tls&sni=www.cloudflare.com&type=tcp&headerType=none#AnyTLS-${port}"
                    subscription_content+="${anytls_url}\n"
                    ;;
            esac
        done < "$CONFIG_DIR/connections.txt"
        
        # 保存订阅内容
        local subscription_file="$CONFIG_DIR/subscription.txt"
        echo -e "$subscription_content" > "$subscription_file"
        
        # 生成base64编码的订阅链接
        local encoded_subscription
        encoded_subscription=$(echo -e "$subscription_content" | base64 -w 0)
        
        echo -e "\n${GREEN}订阅链接生成完成:${NC}"
        echo -e "${YELLOW}data:text/plain;charset=utf-8;base64,$encoded_subscription${NC}"
        echo -e "\n订阅文件保存位置: $subscription_file"
    else
        echo -e "${RED}未找到连接信息${NC}"
    fi
}

# 生成二维码
generate_qrcode() {
    if ! command -v qrencode >/dev/null 2>&1; then
        echo -e "${RED}qrencode未安装，正在安装...${NC}"
        case "$PACKAGE_MANAGER" in
            apt) apt install -y qrencode ;;
            yum|dnf) $PACKAGE_MANAGER install -y qrencode ;;
        esac
    fi
    
    echo -e "${CYAN}选择要生成二维码的协议:${NC}\n"
    
    local count=1
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        while IFS= read -r line; do
            local protocol=$(echo "$line" | cut -d':' -f1)
            local port=$(echo "$line" | cut -d':' -f2)
            echo -e "  ${GREEN}$count.${NC} $protocol (端口: $port)"
            ((count++))
        done < "$CONFIG_DIR/connections.txt"
    fi
    
    echo ""
    echo -ne "请选择 [1-$((count-1))]: "
    read -r choice
    
    # 这里可以根据选择生成对应的二维码
    echo -e "${YELLOW}二维码生成功能开发中...${NC}"
}

# 导出配置文件
export_configs() {
    local export_dir="$HOME/sing-box-configs"
    mkdir -p "$export_dir"
    
    # 复制配置文件
    cp -r "$CONFIG_DIR"/* "$export_dir/" 2>/dev/null
    
    # 生成客户端配置
    generate_client_configs "$export_dir"
    
    success "配置文件已导出到: $export_dir"
}

# 生成客户端配置
generate_client_configs() {
    local export_dir="$1"
    
    # 为不同客户端生成配置
    mkdir -p "$export_dir/clients"
    
    # 生成Clash配置
    generate_clash_config "$export_dir/clients/clash.yaml"
    
    # 生成v2rayN配置
    generate_v2rayn_config "$export_dir/clients/v2rayn.json"
    
    success "客户端配置生成完成"
}

# 生成Clash配置
generate_clash_config() {
    local output_file="$1"
    local server_ip
    server_ip=$(curl -s ipinfo.io/ip || curl -s ifconfig.me || echo "127.0.0.1")
    
    cat > "$output_file" << EOF
mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
EOF
    
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        while IFS= read -r line; do
            local protocol=$(echo "$line" | cut -d':' -f1)
            local port=$(echo "$line" | cut -d':' -f2)
            
            case $protocol in
                "Shadowsocks")
                    local method=$(echo "$line" | cut -d':' -f3)
                    local password=$(echo "$line" | cut -d':' -f4)
                    cat >> "$output_file" << EOF
  - name: "Shadowsocks-$port"
    type: ss
    server: $server_ip
    port: $port
    cipher: $method
    password: "$password"
    
EOF
                    ;;
            esac
        done < "$CONFIG_DIR/connections.txt"
    fi
    
    cat >> "$output_file" << 'EOF'
proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - "Auto"
  - name: "Auto"
    type: url-test
    proxies: []
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,google,Proxy
  - DOMAIN,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
}

# 生成v2rayN配置
generate_v2rayn_config() {
    local output_file="$1"
    
    cat > "$output_file" << 'EOF'
{
  "log": {
    "access": "",
    "error": "",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks",
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "settings": {
        "auth": "noauth",
        "udp": true
      }
    },
    {
      "tag": "http",
      "port": 10809,
      "listen": "127.0.0.1",
      "protocol": "http",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "settings": {
        "udp": false
      }
    }
  ],
  "outbounds": [],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}
EOF
}

# 系统信息菜单
system_info_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 系统信息 ===${NC}\n"
        echo -e "  ${GREEN}1.${NC} 查看端口占用情况"
        echo -e "  ${GREEN}2.${NC} 查看网络优化状态"
        echo -e "  ${GREEN}3.${NC} 查看fail2ban状态"
        echo -e "  ${GREEN}4.${NC} 查看系统资源"
        echo -e "  ${GREEN}5.${NC} 查看Sing-box版本"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        echo -ne "请选择操作 [0-5]: "
        
        local choice
        read -r choice
        
        case $choice in
            1) show_port_usage ;;
            2) show_network_optimization ;;
            3) show_fail2ban_status ;;
            4) show_system_resources ;;
            5) show_version_info ;;
            0) break ;;
            *) 
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
        
        echo -e "\n按回车键继续..."
        read -r
    done
}

# 显示端口占用情况
show_port_usage() {
    echo -e "${CYAN}=== 端口占用情况 ===${NC}\n"
    
    if [[ -f "$CONFIG_DIR/connections.txt" ]]; then
        echo -e "${GREEN}Sing-box使用的端口:${NC}"
        while IFS= read -r line; do
            local protocol=$(echo "$line" | cut -d':' -f1)
            local port=$(echo "$line" | cut -d':' -f2)
            echo -e "  $protocol: ${YELLOW}$port${NC}"
        done < "$CONFIG_DIR/connections.txt"
        echo ""
    fi
    
    echo -e "${GREEN}所有监听端口:${NC}"
    netstat -tlnp | grep LISTEN | head -20
}

# 显示网络优化状态
show_network_optimization() {
    echo -e "${CYAN}=== 网络优化状态 ===${NC}\n"
    
    # 检查BBR状态
    local bbr_status
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        bbr_status="${GREEN}已启用${NC}"
    else
        bbr_status="${RED}未启用${NC}"
    fi
    echo -e "BBR拥塞控制: $bbr_status"
    
    # 检查TCP FastOpen状态
    local tcp_fastopen
    tcp_fastopen=$(sysctl net.ipv4.tcp_fastopen | awk '{print $3}')
    if [[ $tcp_fastopen -eq 3 ]]; then
        echo -e "TCP FastOpen: ${GREEN}已启用${NC}"
    else
        echo -e "TCP FastOpen: ${RED}未启用${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}当前网络参数:${NC}"
    sysctl net.ipv4.tcp_congestion_control
    sysctl net.ipv4.tcp_fastopen
    sysctl net.core.default_qdisc
}

# 显示fail2ban状态
show_fail2ban_status() {
    echo -e "${CYAN}=== Fail2ban状态 ===${NC}\n"
    
    if command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "${GREEN}Fail2ban运行状态:${NC}"
        systemctl status fail2ban --no-pager
        
        echo -e "\n${GREEN}监狱状态:${NC}"
        fail2ban-client status
        
        if fail2ban-client status | grep -q sing-box; then
            echo -e "\n${GREEN}Sing-box监狱详情:${NC}"
            fail2ban-client status sing-box
        fi
    else
        echo -e "${RED}Fail2ban未安装${NC}"
    fi
}

# 显示系统资源
show_system_resources() {
    echo -e "${CYAN}=== 系统资源 ===${NC}\n"
    
    echo -e "${GREEN}CPU信息:${NC}"
    grep "model name" /proc/cpuinfo | head -1
    echo -e "CPU核心数: $(nproc)"
    
    echo -e "\n${GREEN}内存信息:${NC}"
    free -h
    
    echo -e "\n${GREEN}磁盘使用:${NC}"
    df -h /
    
    echo -e "\n${GREEN}系统负载:${NC}"
    uptime
}

# 显示版本信息
show_version_info() {
    echo -e "${CYAN}=== 版本信息 ===${NC}\n"
    
    echo -e "${GREEN}脚本版本:${NC} $SCRIPT_VERSION"
    
    if command -v sing-box >/dev/null 2>&1; then
        echo -e "${GREEN}Sing-box版本:${NC} $(sing-box version | head -1)"
    else
        echo -e "${RED}Sing-box未安装${NC}"
    fi
    
    echo -e "${GREEN}操作系统:${NC} $OS"
    echo -e "${GREEN}系统架构:${NC} $ARCH"
    echo -e "${GREEN}内核版本:${NC} $(uname -r)"
}

# 安全管理菜单
security_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 防火墙与安全 ===${NC}\n"
        echo -e "  ${GREEN}1.${NC} BBR开关控制"
        echo -e "  ${GREEN}2.${NC} TCP FastOpen设置"
        echo -e "  ${GREEN}3.${NC} Fail2ban配置"
        echo -e "  ${GREEN}4.${NC} IP白名单管理"
        echo -e "  ${GREEN}5.${NC} IP黑名单管理"
        echo -e "  ${GREEN}6.${NC} 防火墙状态"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        echo -ne "请选择操作 [0-6]: "
        
        local choice
        read -r choice
        
        case $choice in
            1) toggle_bbr ;;
            2) toggle_tcp_fastopen ;;
            3) configure_fail2ban_menu ;;
            4) manage_ip_whitelist ;;
            5) manage_ip_blacklist ;;
            6) show_firewall_status ;;
            0) break ;;
            *) 
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
        
        echo -e "\n按回车键继续..."
        read -r
    done
}

# BBR开关控制
toggle_bbr() {
    echo -e "${CYAN}=== BBR控制 ===${NC}\n"
    
    local current_status
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        current_status="${GREEN}已启用${NC}"
        echo -e "当前状态: $current_status"
        echo ""
        echo -ne "是否禁用BBR? [y/N]: "
        read -r confirm
        
        if [[ $confirm =~ ^[Yy]$ ]]; then
            sed -i '/net.ipv4.tcp_congestion_control = bbr/d' /etc/sysctl.conf
            sed -i '/net.core.default_qdisc = fq/d' /etc/sysctl.conf
            sysctl -p >/dev/null 2>&1
            success "BBR已禁用"
        fi
    else
        current_status="${RED}未启用${NC}"
        echo -e "当前状态: $current_status"
        echo ""
        echo -ne "是否启用BBR? [y/N]: "
        read -r confirm
        
        if [[ $confirm =~ ^[Yy]$ ]]; then
            enable_bbr
        fi
    fi
}

# TCP FastOpen开关控制
toggle_tcp_fastopen() {
    echo -e "${CYAN}=== TCP FastOpen控制 ===${NC}\n"
    
    local current_value
    current_value=$(sysctl net.ipv4.tcp_fastopen | awk '{print $3}')
    
    if [[ $current_value -eq 3 ]]; then
        echo -e "当前状态: ${GREEN}已启用${NC}"
        echo ""
        echo -ne "是否禁用TCP FastOpen? [y/N]: "
        read -r confirm
        
        if [[ $confirm =~ ^[Yy]$ ]]; then
            sysctl -w net.ipv4.tcp_fastopen=0
            sed -i '/net.ipv4.tcp_fastopen = 3/d' /etc/sysctl.conf
            success "TCP FastOpen已禁用"
        fi
    else
        echo -e "当前状态: ${RED}未启用${NC}"
        echo ""
        echo -ne "是否启用TCP FastOpen? [y/N]: "
        read -r confirm
        
        if [[ $confirm =~ ^[Yy]$ ]]; then
            sysctl -w net.ipv4.tcp_fastopen=3
            if ! grep -q "net.ipv4.tcp_fastopen = 3" /etc/sysctl.conf; then
                echo 'net.ipv4.tcp_fastopen = 3' >> /etc/sysctl.conf
            fi
            success "TCP FastOpen已启用"
        fi
    fi
}

# Fail2ban配置菜单
configure_fail2ban_menu() {
    echo -e "${CYAN}=== Fail2ban配置 ===${NC}\n"
    echo -e "  ${GREEN}1.${NC} 查看封禁列表"
    echo -e "  ${GREEN}2.${NC} 解封IP地址"
    echo -e "  ${GREEN}3.${NC} 重启Fail2ban"
    echo -e "  ${GREEN}4.${NC} 查看日志"
    echo ""
    echo -ne "请选择操作 [1-4]: "
    
    local choice
    read -r choice
    
    case $choice in
        1) 
            if command -v fail2ban-client >/dev/null 2>&1; then
                fail2ban-client status sing-box
            else
                echo -e "${RED}Fail2ban未安装${NC}"
            fi
            ;;
        2) 
            echo -ne "请输入要解封的IP地址: "
            read -r ip_address
            if [[ -n $ip_address ]]; then
                fail2ban-client set sing-box unbanip "$ip_address"
                success "IP地址 $ip_address 已解封"
            fi
            ;;
        3) 
            systemctl restart fail2ban
            success "Fail2ban已重启"
            ;;
        4) 
            tail -50 /var/log/fail2ban.log
            ;;
    esac
}

# IP白名单管理
manage_ip_whitelist() {
    echo -e "${CYAN}=== IP白名单管理 ===${NC}\n"
    
    local whitelist_file="/etc/sing-box/whitelist.txt"
    
    echo -e "  ${GREEN}1.${NC} 查看白名单"
    echo -e "  ${GREEN}2.${NC} 添加IP到白名单"
    echo -e "  ${GREEN}3.${NC} 从白名单删除IP"
    echo ""
    echo -ne "请选择操作 [1-3]: "
    
    local choice
    read -r choice
    
    case $choice in
        1) 
            if [[ -f $whitelist_file ]]; then
                cat "$whitelist_file"
            else
                echo "白名单为空"
            fi
            ;;
        2) 
            echo -ne "请输入要添加的IP地址: "
            read -r ip_address
            if [[ -n $ip_address ]]; then
                echo "$ip_address" >> "$whitelist_file"
                # 添加防火墙规则
                iptables -I INPUT -s "$ip_address" -j ACCEPT
                success "IP地址 $ip_address 已添加到白名单"
            fi
            ;;
        3) 
            echo -ne "请输入要删除的IP地址: "
            read -r ip_address
            if [[ -n $ip_address ]]; then
                sed -i "/$ip_address/d" "$whitelist_file" 2>/dev/null
                # 删除防火墙规则
                iptables -D INPUT -s "$ip_address" -j ACCEPT 2>/dev/null
                success "IP地址 $ip_address 已从白名单删除"
            fi
            ;;
    esac
}

# IP黑名单管理
manage_ip_blacklist() {
    echo -e "${CYAN}=== IP黑名单管理 ===${NC}\n"
    
    local blacklist_file="/etc/sing-box/blacklist.txt"
    
    echo -e "  ${GREEN}1.${NC} 查看黑名单"
    echo -e "  ${GREEN}2.${NC} 添加IP到黑名单"
    echo -e "  ${GREEN}3.${NC} 从黑名单删除IP"
    echo ""
    echo -ne "请选择操作 [1-3]: "
    
    local choice
    read -r choice
    
    case $choice in
        1) 
            if [[ -f $blacklist_file ]]; then
                cat "$blacklist_file"
            else
                echo "黑名单为空"
            fi
            ;;
        2) 
            echo -ne "请输入要添加的IP地址: "
            read -r ip_address
            if [[ -n $ip_address ]]; then
                echo "$ip_address" >> "$blacklist_file"
                # 添加防火墙规则
                iptables -I INPUT -s "$ip_address" -j DROP
                success "IP地址 $ip_address 已添加到黑名单"
            fi
            ;;
        3) 
            echo -ne "请输入要删除的IP地址: "
            read -r ip_address
            if [[ -n $ip_address ]]; then
                sed -i "/$ip_address/d" "$blacklist_file" 2>/dev/null
                # 删除防火墙规则
                iptables -D INPUT -s "$ip_address" -j DROP 2>/dev/null
                success "IP地址 $ip_address 已从黑名单删除"
            fi
            ;;
    esac
}

# 显示防火墙状态
show_firewall_status() {
    echo -e "${CYAN}=== 防火墙状态 ===${NC}\n"
    
    if command -v ufw >/dev/null 2>&1; then
        echo -e "${GREEN}UFW状态:${NC}"
        ufw status verbose
    elif command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "${GREEN}Firewalld状态:${NC}"
        firewall-cmd --list-all
    else
        echo -e "${GREEN}iptables规则:${NC}"
        iptables -L -n --line-numbers
    fi
}

# 证书管理菜单
certificate_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 证书管理 ===${NC}\n"
        echo -e "  ${GREEN}1.${NC} 申请Let's Encrypt证书"
        echo -e "  ${GREEN}2.${NC} 续期证书"
        echo -e "  ${GREEN}3.${NC} 生成自签证书"
        echo -e "  ${GREEN}4.${NC} 查看证书状态"
        echo -e "  ${GREEN}5.${NC} 导入自有证书"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        echo -ne "请选择操作 [0-5]: "
        
        local choice
        read -r choice
        
        case $choice in
            1) apply_letsencrypt_certificate ;;
            2) renew_certificate ;;
            3) generate_self_signed_certificate ;;
            4) show_certificate_status ;;
            5) import_certificate ;;
            0) break ;;
            *) 
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
        
        echo -e "\n按回车键继续..."
        read -r
    done
}

# 申请Let's Encrypt证书
apply_letsencrypt_certificate() {
    echo -e "${CYAN}=== 申请Let's Encrypt证书 ===${NC}\n"
    
    echo -ne "请输入域名: "
    read -r domain
    
    if [[ -z $domain ]]; then
        echo -e "${RED}域名不能为空${NC}"
        return
    fi
    
    echo -ne "请输入邮箱地址: "
    read -r email
    
    if [[ -z $email ]]; then
        echo -e "${RED}邮箱地址不能为空${NC}"
        return
    fi
    
    log "INFO" "开始申请证书..."
    
    # 安装acme.sh
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        curl https://get.acme.sh | sh -s email="$email"
        source ~/.bashrc
    fi
    
    # 申请证书
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone
    
    if [[ $? -eq 0 ]]; then
        # 安装证书
        local cert_dir="/etc/sing-box/certs"
        mkdir -p "$cert_dir"
        
        ~/.acme.sh/acme.sh --install-cert -d "$domain" \
            --key-file "$cert_dir/private.key" \
            --fullchain-file "$cert_dir/cert.crt"
        
        success "证书申请成功"
        
        # 保存证书信息
        echo "$domain:$email:$(date '+%Y-%m-%d')" >> "$CONFIG_DIR/certificates.txt"
    else
        error_exit "证书申请失败"
    fi
}

# 续期证书
renew_certificate() {
    echo -e "${CYAN}=== 续期证书 ===${NC}\n"
    
    if [[ -f ~/.acme.sh/acme.sh ]]; then
        ~/.acme.sh/acme.sh --cron
        success "证书续期完成"
    else
        echo -e "${RED}acme.sh未安装${NC}"
    fi
}

# 生成自签证书
generate_self_signed_certificate() {
    echo -e "${CYAN}=== 生成自签证书 ===${NC}\n"
    
    echo -ne "请输入域名 (默认: localhost): "
    read -r domain
    domain=${domain:-localhost}
    
    local cert_dir="/etc/sing-box/certs"
    mkdir -p "$cert_dir"
    
    # 生成私钥
    openssl genrsa -out "$cert_dir/private.key" 2048
    
    # 生成证书请求
    openssl req -new -key "$cert_dir/private.key" -out "$cert_dir/cert.csr" -subj "/CN=$domain"
    
    # 生成自签证书
    openssl x509 -req -days 365 -in "$cert_dir/cert.csr" -signkey "$cert_dir/private.key" -out "$cert_dir/cert.crt"
    
    # 清理临时文件
    rm -f "$cert_dir/cert.csr"
    
    success "自签证书生成完成"
}

# 查看证书状态
show_certificate_status() {
    echo -e "${CYAN}=== 证书状态 ===${NC}\n"
    
    local cert_dir="/etc/sing-box/certs"
    
    if [[ -f "$cert_dir/cert.crt" ]]; then
        echo -e "${GREEN}证书信息:${NC}"
        openssl x509 -in "$cert_dir/cert.crt" -text -noout | grep -E "(Subject|Not After)"
    else
        echo -e "${RED}未找到证书文件${NC}"
    fi
    
    if [[ -f "$CONFIG_DIR/certificates.txt" ]]; then
        echo -e "\n${GREEN}管理的证书:${NC}"
        cat "$CONFIG_DIR/certificates.txt"
    fi
}

# 导入自有证书
import_certificate() {
    echo -e "${CYAN}=== 导入自有证书 ===${NC}\n"
    
    echo -ne "请输入证书文件路径 (.crt): "
    read -r cert_file
    
    echo -ne "请输入私钥文件路径 (.key): "
    read -r key_file
    
    if [[ ! -f $cert_file ]] || [[ ! -f $key_file ]]; then
        echo -e "${RED}证书或私钥文件不存在${NC}"
        return
    fi
    
    local cert_dir="/etc/sing-box/certs"
    mkdir -p "$cert_dir"
    
    cp "$cert_file" "$cert_dir/cert.crt"
    cp "$key_file" "$cert_dir/private.key"
    
    success "证书导入完成"
}

# 高级设置菜单
advanced_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 高级设置 ===${NC}\n"
        echo -e "  ${GREEN}1.${NC} CDN配置"
        echo -e "  ${GREEN}2.${NC} 伪装站点设置"
        echo -e "  ${GREEN}3.${NC} TLS指纹配置"
        echo -e "  ${GREEN}4.${NC} 多入口配置"
        echo -e "  ${GREEN}5.${NC} 性能调优"
        echo -e "  ${GREEN}6.${NC} 备份配置"
        echo -e "  ${GREEN}7.${NC} 恢复配置"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        echo -ne "请选择操作 [0-7]: "
        
        local choice
        read -r choice
        
        case $choice in
            1) configure_cdn ;;
            2) configure_camouflage ;;
            3) configure_tls_fingerprint ;;
            4) configure_multi_entrance ;;
            5) performance_tuning ;;
            6) backup_configuration ;;
            7) restore_configuration ;;
            0) break ;;
            *) 
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
        
        echo -e "\n按回车键继续..."
        read -r
    done
}

# CDN配置
configure_cdn() {
    echo -e "${CYAN}=== CDN配置 ===${NC}\n"
    echo -e "  ${GREEN}1.${NC} Cloudflare CDN"
    echo -e "  ${GREEN}2.${NC} AWS CloudFront"
    echo -e "  ${GREEN}3.${NC} 自定义CDN"
    echo ""
    echo -ne "请选择CDN类型 [1-3]: "
    
    local choice
    read -r choice
    
    case $choice in
        1) configure_cloudflare_cdn ;;
        2) configure_aws_cdn ;;
        3) configure_custom_cdn ;;
    esac
}

# 配置Cloudflare CDN
configure_cloudflare_cdn() {
    echo -e "${CYAN}=== Cloudflare CDN配置 ===${NC}\n"
    
    echo -ne "请输入Cloudflare域名: "
    read -r cf_domain
    
    echo -ne "请输入原始服务器IP: "
    read -r origin_ip
    
    if [[ -n $cf_domain && -n $origin_ip ]]; then
        # 这里可以添加Cloudflare CDN的具体配置逻辑
        echo "Domain: $cf_domain" >> "$CONFIG_DIR/cdn.conf"
        echo "Origin: $origin_ip" >> "$CONFIG_DIR/cdn.conf"
        success "Cloudflare CDN配置完成"
    fi
}

# 配置AWS CloudFront
configure_aws_cdn() {
    echo -e "${CYAN}=== AWS CloudFront配置 ===${NC}\n"
    echo -e "${YELLOW}AWS CloudFront配置功能开发中...${NC}"
}

# 配置自定义CDN
configure_custom_cdn() {
    echo -e "${CYAN}=== 自定义CDN配置 ===${NC}\n"
    echo -e "${YELLOW}自定义CDN配置功能开发中...${NC}"
}

# 伪装站点设置
configure_camouflage() {
    echo -e "${CYAN}=== 伪装站点设置 ===${NC}\n"
    
    echo -ne "请输入伪装网站URL: "
    read -r camouflage_url
    
    if [[ -n $camouflage_url ]]; then
        echo "camouflage_url=$camouflage_url" >> "$CONFIG_DIR/camouflage.conf"
        success "伪装站点设置完成"
    fi
}

# TLS指纹配置
configure_tls_fingerprint() {
    echo -e "${CYAN}=== TLS指纹配置 ===${NC}\n"
    
    echo -e "选择TLS指纹类型:"
    echo -e "  ${GREEN}1.${NC} Chrome"
    echo -e "  ${GREEN}2.${NC} Firefox"
    echo -e "  ${GREEN}3.${NC} Safari"
    echo -e "  ${GREEN}4.${NC} Edge"
    echo ""
    echo -ne "请选择 [1-4]: "
    
    local choice
    read -r choice
    
    local fingerprint
    case $choice in
        1) fingerprint="chrome" ;;
        2) fingerprint="firefox" ;;
        3) fingerprint="safari" ;;
        4) fingerprint="edge" ;;
        *) fingerprint="chrome" ;;
    esac
    
    echo "tls_fingerprint=$fingerprint" >> "$CONFIG_DIR/tls.conf"
    success "TLS指纹配置完成: $fingerprint"
}

# 多入口配置
configure_multi_entrance() {
    echo -e "${CYAN}=== 多入口配置 ===${NC}\n"
    echo -e "${YELLOW}多入口配置功能开发中...${NC}"
}

# 性能调优
performance_tuning() {
    echo -e "${CYAN}=== 性能调优 ===${NC}\n"
    
    log "INFO" "应用性能优化设置..."
    
    # 高级网络参数优化
    cat >> /etc/sysctl.conf << 'EOF'

# Advanced network optimization
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF
    
    sysctl -p >/dev/null 2>&1
    
    success "性能调优完成"
}

# 备份配置
backup_configuration() {
    echo -e "${CYAN}=== 备份配置 ===${NC}\n"
    
    local backup_dir="/root/sing-box-backup"
    local backup_file="$backup_dir/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    mkdir -p "$backup_dir"
    
    tar -czf "$backup_file" -C / etc/sing-box var/log/sing-box 2>/dev/null
    
    if [[ -f $backup_file ]]; then
        success "配置备份完成: $backup_file"
    else
        echo -e "${RED}备份失败${NC}"
    fi
}

# 恢复配置
restore_configuration() {
    echo -e "${CYAN}=== 恢复配置 ===${NC}\n"
    
    local backup_dir="/root/sing-box-backup"
    
    if [[ ! -d $backup_dir ]]; then
        echo -e "${RED}备份目录不存在${NC}"
        return
    fi
    
    echo -e "${GREEN}可用的备份文件:${NC}"
    ls -la "$backup_dir"/*.tar.gz 2>/dev/null | nl
    
    echo ""
    echo -ne "请输入备份文件完整路径: "
    read -r backup_file
    
    if [[ -f $backup_file ]]; then
        echo -e "${RED}警告: 此操作将覆盖当前配置！${NC}"
        echo -ne "确认恢复? [y/N]: "
        read -r confirm
        
        if [[ $confirm =~ ^[Yy]$ ]]; then
            systemctl stop sing-box
            tar -xzf "$backup_file" -C /
            systemctl start sing-box
            success "配置恢复完成"
        fi
    else
        echo -e "${RED}备份文件不存在${NC}"
    fi
}

# =============================================================================
# 主程序入口
# =============================================================================

# 主循环
main() {
    # 检查root权限
    check_root
    
    # 检查网络连接
    check_network
    
    # 处理命令行参数
    case "${1:-}" in
        "install")
            install_menu
            exit 0
            ;;
        "uninstall")
            uninstall_menu
            exit 0
            ;;
        "update")
            install_menu
            exit 0
            ;;
        "--help"|"-h")
            show_help
            exit 0
            ;;
        "--version"|"-v")
            echo "SBall v$SCRIPT_VERSION"
            exit 0
            ;;
    esac
    
    # 主菜单循环
    while true; do
        show_main_menu
        handle_main_menu
    done
}

# 显示帮助信息
show_help() {
    echo -e "${CYAN}SBall - Sing-box 全能安装脚本 v$SCRIPT_VERSION${NC}\n"
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  install     一键安装Sing-box"
    echo "  uninstall   卸载Sing-box"
    echo "  update      更新Sing-box"
    echo "  -h, --help  显示帮助信息"
    echo "  -v, --version 显示版本信息"
    echo ""
    echo "示例:"
    echo "  $0 install                    # 交互式安装"
    echo "  $0 install --silent          # 静默安装"
    echo "  $0 uninstall                 # 卸载"
    echo ""
}

# 显示脚本开始信息
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ____  ____        _ _ "
    echo " / ___|| __ )  __ _| | |"
    echo " \___ \|  _ \ / _\` | | |"
    echo "  ___) | |_) | (_| | | |"
    echo " |____/|____/ \__,_|_|_|"
    echo -e "${NC}"
    echo -e "${GREEN}Sing-box 全能安装脚本 v$SCRIPT_VERSION${NC}"
    echo -e "${YELLOW}作者: SBall Development Team${NC}"
    echo -e "${BLUE}项目: https://github.com/$GITHUB_REPO${NC}"
    echo ""
}

# 脚本开始执行
show_banner

# 创建日志目录
mkdir -p "$LOG_DIR"

# 启动主程序
main "$@"
