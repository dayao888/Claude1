#!/bin/bash

# =============================================================================
# Sing-box 一键安装脚本 (sball.sh)
# 版本: 2.0.0
# 作者: Sing-box Community
# 许可证: MIT
# 支持系统: Ubuntu/Debian/CentOS/RHEL
# Sing-box版本: 1.12.2
# =============================================================================

set -euo pipefail

# =============================================================================
# 全局变量定义
# =============================================================================

# 脚本信息
SCRIPT_VERSION="2.0.0"
SCRIPT_NAME="sball.sh"
SCRIPT_AUTHOR="Sing-box Community"

# Sing-box 配置
SINGBOX_VERSION="1.12.2"
SINGBOX_CONFIG_DIR="/etc/sing-box"
SINGBOX_LOG_DIR="/var/log/sing-box"
SINGBOX_DATA_DIR="/var/lib/sing-box"
SINGBOX_SERVICE_FILE="/etc/systemd/system/sing-box.service"
SINGBOX_BINARY="/usr/local/bin/sing-box"
SERVICE_NAME="sing-box"

# 网络配置
SERVER_IP=""
SERVER_DOMAIN=""
USE_CUSTOM_PORT="false"
CUSTOM_PORT_RANGE=""

# 端口配置 - 基于详细开发方案
REALITY_HANDSHAKE_PORT=443
SHADOWTLS_HANDSHAKE_PORT=443

# 协议端口数组 (将通过函数生成)
declare -a PROTOCOL_PORTS

# 协议UUID数组 (将通过函数生成)
declare -a PROTOCOL_UUIDS

# 协议配置
PROTOCOL_CONFIGS=(
    "xtls-reality"
    "vless-reality" 
    "hysteria2"
    "tuic"
    "shadowtls"
    "trojan"
    "vmess"
    "vless"
    "shadowsocks"
    "naive"
    "h2-reality"
    "grpc-reality"
    "anytls"
    "direct"
    "mixed"
)

# 证书配置
USE_DOMAIN_CERT="false"
CERT_PATH=""
KEY_PATH=""
AUTO_CERT="false"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 语言配置
LANG_CN="zh_CN"
LANG_EN="en_US"
CURRENT_LANG="${LANG_CN}"

# =============================================================================
# 多语言支持函数
# =============================================================================

# 获取本地化文本
get_text() {
    local key="$1"
    case "${CURRENT_LANG}" in
        "${LANG_CN}")
            case "${key}" in
                "welcome") echo "欢迎使用 Sing-box 一键安装脚本" ;;
                "system_check") echo "正在检查系统环境..." ;;
                "install_deps") echo "正在安装依赖包..." ;;
                "download_singbox") echo "正在下载 Sing-box..." ;;
                "generate_config") echo "正在生成配置文件..." ;;
                "start_service") echo "正在启动服务..." ;;
                "install_success") echo "安装成功！" ;;
                "install_failed") echo "安装失败！" ;;
                *) echo "${key}" ;;
            esac
            ;;
        "${LANG_EN}")
            case "${key}" in
                "welcome") echo "Welcome to Sing-box One-Click Installation Script" ;;
                "system_check") echo "Checking system environment..." ;;
                "install_deps") echo "Installing dependencies..." ;;
                "download_singbox") echo "Downloading Sing-box..." ;;
                "generate_config") echo "Generating configuration files..." ;;
                "start_service") echo "Starting service..." ;;
                "install_success") echo "Installation successful!" ;;
                "install_failed") echo "Installation failed!" ;;
                *) echo "${key}" ;;
            esac
            ;;
    esac
}

# =============================================================================
# 输出函数
# =============================================================================

# 信息输出
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 成功输出
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# 警告输出
print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 错误输出
print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# 调试输出
print_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
}

# =============================================================================
# 系统检测函数
# =============================================================================

# 检测操作系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS="$ID"
        OS_VERSION="$VERSION_ID"
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
    else
        print_error "不支持的操作系统"
        exit 1
    fi
    
    print_info "检测到操作系统: ${OS} ${OS_VERSION}"
}

# 检测系统架构
detect_arch() {
    local arch=$(uname -m)
    case "${arch}" in
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
            print_error "不支持的系统架构: ${arch}"
            exit 1
            ;;
    esac
    
    print_info "检测到系统架构: ${ARCH}"
}

# 检测网络连接
check_network() {
    print_info "$(get_text 'system_check')"
    
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        print_error "网络连接检查失败，请检查网络设置"
        exit 1
    fi
    
    print_success "网络连接正常"
}

# 获取服务器IP
get_server_ip() {
    SERVER_IP=$(curl -s --max-time 10 ipv4.icanhazip.com || curl -s --max-time 10 ifconfig.me || curl -s --max-time 10 ip.sb)
    
    if [[ -z "${SERVER_IP}" ]]; then
        print_error "无法获取服务器IP地址"
        exit 1
    fi
    
    print_info "服务器IP: ${SERVER_IP}"
}

# =============================================================================
# 端口管理函数
# =============================================================================

# 检查端口是否被占用
check_port() {
    local port="$1"
    if ss -tuln | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 生成连续可用端口
generate_consecutive_ports() {
    local start_port=10000
    local end_port=65000
    local needed_ports=15  # 15个协议端口
    
    for ((port=start_port; port<=end_port-needed_ports; port++)); do
        local all_available=true
        
        # 检查连续端口是否都可用
        for ((i=0; i<needed_ports; i++)); do
            if ! check_port $((port + i)); then
                all_available=false
                break
            fi
        done
        
        if [[ "${all_available}" == "true" ]]; then
            # 分配端口给各协议
            PROTOCOL_PORTS[0]=$((port))      # xtls-reality
            PROTOCOL_PORTS[1]=$((port + 1))  # vless-reality
            PROTOCOL_PORTS[2]=$((port + 2))  # hysteria2
            PROTOCOL_PORTS[3]=$((port + 3))  # tuic
            PROTOCOL_PORTS[4]=$((port + 4))  # shadowtls
            PROTOCOL_PORTS[5]=$((port + 5))  # trojan
            PROTOCOL_PORTS[6]=$((port + 6))  # vmess
            PROTOCOL_PORTS[7]=$((port + 7))  # vless
            PROTOCOL_PORTS[8]=$((port + 8))  # shadowsocks
            PROTOCOL_PORTS[9]=$((port + 9))  # naive
            PROTOCOL_PORTS[10]=$((port + 10)) # h2-reality
            PROTOCOL_PORTS[11]=$((port + 11)) # grpc-reality
            PROTOCOL_PORTS[12]=$((port + 12)) # anytls
            PROTOCOL_PORTS[13]=$((port + 13)) # direct
            PROTOCOL_PORTS[14]=$((port + 14)) # mixed
            
            print_success "已分配端口范围: ${port}-$((port + needed_ports - 1))"
            return 0
        fi
    done
    
    print_error "无法找到足够的连续可用端口"
    exit 1
}

# =============================================================================
# 依赖管理函数
# =============================================================================

# 安装依赖包
install_dependencies() {
    print_info "$(get_text 'install_deps')"
    
    local packages=()
    
    case "${OS}" in
        "ubuntu"|"debian")
            # 更新包列表
            apt-get update -qq
            
            packages=("curl" "wget" "unzip" "tar" "systemd" "openssl" "ca-certificates" "gnupg" "lsb-release")
            
            # 检查并安装缺失的包
            for package in "${packages[@]}"; do
                if ! dpkg -l | grep -q "^ii  ${package} "; then
                    print_info "安装 ${package}..."
                    apt-get install -y "${package}" || {
                        print_error "安装 ${package} 失败"
                        exit 1
                    }
                fi
            done
            ;;
        "centos"|"rhel"|"rocky"|"almalinux")
            # 检查包管理器
            if command -v dnf >/dev/null 2>&1; then
                PKG_MANAGER="dnf"
            elif command -v yum >/dev/null 2>&1; then
                PKG_MANAGER="yum"
            else
                print_error "未找到支持的包管理器"
                exit 1
            fi
            
            packages=("curl" "wget" "unzip" "tar" "systemd" "openssl" "ca-certificates")
            
            # 检查并安装缺失的包
            for package in "${packages[@]}"; do
                if ! rpm -q "${package}" >/dev/null 2>&1; then
                    print_info "安装 ${package}..."
                    ${PKG_MANAGER} install -y "${package}" || {
                        print_error "安装 ${package} 失败"
                        exit 1
                    }
                fi
            done
            ;;
        *)
            print_error "不支持的操作系统: ${OS}"
            exit 1
            ;;
    esac
    
    print_success "依赖包安装完成"
}

# 检查必要工具
check_required_tools() {
    local tools=("curl" "wget" "unzip" "tar" "systemctl")
    
    for tool in "${tools[@]}"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            print_error "缺少必要工具: ${tool}"
            return 1
        fi
    done
    
    print_success "所有必要工具已就绪"
    return 0
}

# =============================================================================
# Sing-box 安装函数
# =============================================================================

# 下载 Sing-box
download_singbox() {
    print_info "$(get_text 'download_singbox')"
    
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"
    local temp_dir="/tmp/sing-box-install"
    local archive_file="${temp_dir}/sing-box.tar.gz"
    
    # 创建临时目录
    mkdir -p "${temp_dir}"
    
    # 下载文件
    print_info "正在从 GitHub 下载 Sing-box ${SINGBOX_VERSION}..."
    if ! curl -L --progress-bar "${download_url}" -o "${archive_file}"; then
        print_error "下载 Sing-box 失败"
        rm -rf "${temp_dir}"
        exit 1
    fi
    
    # 验证下载文件
    if [[ ! -f "${archive_file}" ]] || [[ ! -s "${archive_file}" ]]; then
        print_error "下载的文件无效"
        rm -rf "${temp_dir}"
        exit 1
    fi
    
    # 解压文件
    print_info "正在解压 Sing-box..."
    if ! tar -xzf "${archive_file}" -C "${temp_dir}"; then
        print_error "解压 Sing-box 失败"
        rm -rf "${temp_dir}"
        exit 1
    fi
    
    # 查找二进制文件
    local binary_path=$(find "${temp_dir}" -name "sing-box" -type f -executable | head -1)
    if [[ -z "${binary_path}" ]]; then
        print_error "未找到 Sing-box 二进制文件"
        rm -rf "${temp_dir}"
        exit 1
    fi
    
    # 安装二进制文件
    print_info "正在安装 Sing-box 到 ${SINGBOX_BINARY}..."
    cp "${binary_path}" "${SINGBOX_BINARY}"
    chmod +x "${SINGBOX_BINARY}"
    
    # 清理临时文件
    rm -rf "${temp_dir}"
    
    # 验证安装
    if "${SINGBOX_BINARY}" version >/dev/null 2>&1; then
        local installed_version=$("${SINGBOX_BINARY}" version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        print_success "Sing-box ${installed_version} 安装成功"
    else
        print_error "Sing-box 安装验证失败"
        exit 1
    fi
}

# 创建系统服务
create_systemd_service() {
    print_info "正在创建 systemd 服务..."
    
    cat > "${SINGBOX_SERVICE_FILE}" << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${SINGBOX_BINARY} run -c ${SINGBOX_CONFIG_DIR}/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    print_success "systemd 服务创建完成"
}

# 创建必要目录
create_directories() {
    print_info "正在创建必要目录..."
    
    local directories=(
        "${SINGBOX_CONFIG_DIR}"
        "${SINGBOX_LOG_DIR}"
        "${SINGBOX_DATA_DIR}"
        "${SINGBOX_CONFIG_DIR}/certs"
    )
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "${dir}" ]]; then
            mkdir -p "${dir}"
            print_info "创建目录: ${dir}"
        fi
    done
    
    # 设置权限
    chmod 755 "${SINGBOX_CONFIG_DIR}"
    chmod 755 "${SINGBOX_LOG_DIR}"
    chmod 755 "${SINGBOX_DATA_DIR}"
    
    print_success "目录创建完成"
}

# =============================================================================
# UUID 和密钥生成函数
# =============================================================================

# 生成 UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        # 备用方法：使用 openssl
        openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/'
    fi
}

# 生成随机字符串
generate_random_string() {
    local length="${1:-16}"
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-${length}
}

# 生成随机路径
generate_random_path() {
    echo "/$(generate_random_string 8)"
}

# =============================================================================
# 证书管理模块
# =============================================================================

# 创建证书目录
create_cert_directory() {
    print_info "创建证书目录..."
    
    if [[ ! -d "${SINGBOX_CONFIG_DIR}/certs" ]]; then
        mkdir -p "${SINGBOX_CONFIG_DIR}/certs"
        print_success "证书目录创建完成: ${SINGBOX_CONFIG_DIR}/certs"
    else
        print_info "证书目录已存在: ${SINGBOX_CONFIG_DIR}/certs"
    fi
}

# 生成自签证书（100年有效期）
generate_self_signed_certificate() {
    print_info "正在生成自签证书..."
    
    local cert_dir="${SINGBOX_CONFIG_DIR}/certs"
    local cert_file="${cert_dir}/cert.pem"
    local key_file="${cert_dir}/private.key"
    
    # 检查证书是否已存在
    if [[ -f "${cert_file}" && -f "${key_file}" ]]; then
        print_info "证书文件已存在，检查有效期..."
        
        # 检查证书有效期（剩余天数大于30天则不重新生成）
        local expiry_date=$(openssl x509 -in "${cert_file}" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "${expiry_date}" ]]; then
            local expiry_timestamp=$(date -d "${expiry_date}" +%s 2>/dev/null || echo "0")
            local current_timestamp=$(date +%s)
            local days_left=$(( (expiry_timestamp - current_timestamp) / 86400 ))
            
            if [[ ${days_left} -gt 30 ]]; then
                print_success "现有证书仍有效（剩余${days_left}天），跳过生成"
                return 0
            fi
        fi
    fi
    
    # 生成椭圆曲线私钥（更安全，性能更好）
    if ! openssl ecparam -genkey -name prime256v1 -out "${key_file}" 2>/dev/null; then
        print_error "生成私钥失败"
        return 1
    fi
    
    # 生成自签证书（100年有效期）
    local subject="/C=US/ST=California/L=San Francisco/O=SBall/OU=Proxy/CN=${TLS_SERVER_NAME:-www.microsoft.com}"
    
    if ! openssl req -new -x509 -days 36500 -key "${key_file}" -out "${cert_file}" \
        -subj "${subject}" \
        -extensions v3_req \
        -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${TLS_SERVER_NAME:-www.microsoft.com}
DNS.2 = *.${TLS_SERVER_NAME:-www.microsoft.com}
IP.1 = ${SERVER_IP}
EOF
) 2>/dev/null; then
        print_error "生成证书失败"
        return 1
    fi
    
    # 设置证书文件权限
    chmod 644 "${cert_file}"
    chmod 600 "${key_file}"
    
    # 验证证书
    if openssl x509 -in "${cert_file}" -noout -text >/dev/null 2>&1; then
        print_success "自签证书生成完成"
        print_info "证书文件: ${cert_file}"
        print_info "私钥文件: ${key_file}"
        
        # 显示证书信息
        local cert_subject=$(openssl x509 -in "${cert_file}" -noout -subject 2>/dev/null | sed 's/subject=//')
        local cert_expiry=$(openssl x509 -in "${cert_file}" -noout -enddate 2>/dev/null | cut -d= -f2)
        print_info "证书主题: ${cert_subject}"
        print_info "证书有效期至: ${cert_expiry}"
    else
        print_error "证书验证失败"
        return 1
    fi
}

# 检查域名证书（预留功能）
check_domain_certificate() {
    local domain="$1"
    
    if [[ -z "${domain}" ]]; then
        print_debug "未提供域名，使用自签证书"
        return 1
    fi
    
    print_info "检查域名证书: ${domain}"
    
    # 这里可以扩展ACME证书申请功能
    # 目前返回失败，使用自签证书
    print_warning "域名证书功能暂未实现，将使用自签证书"
    return 1
}

# 证书管理主函数
manage_certificates() {
    print_info "开始证书管理..."
    
    # 创建证书目录
    create_cert_directory
    
    # 检查是否使用域名证书
    if [[ -n "${DOMAIN_NAME:-}" ]]; then
        if ! check_domain_certificate "${DOMAIN_NAME}"; then
            print_info "域名证书获取失败，使用自签证书"
            generate_self_signed_certificate
        fi
    else
        # 生成自签证书
        generate_self_signed_certificate
    fi
    
    print_success "证书管理完成"
}

# =============================================================================
# 协议配置生成函数
# =============================================================================

# 生成协议配置变量
generate_protocol_variables() {
    print_info "正在生成协议配置变量..."
    
    # 生成UUID数组
    for i in {0..14}; do
        PROTOCOL_UUIDS[${i}]=$(generate_uuid)
    done
    
    # 生成密码和路径
    HYSTERIA2_OBFS_PASSWORD=$(generate_random_string 16)
    HYSTERIA2_PASSWORD=$(generate_random_string 16)
    TUIC_PASSWORD=$(generate_random_string 16)
    SHADOWTLS_PASSWORD=$(generate_random_string 16)
    TROJAN_PASSWORD=$(generate_random_string 16)
    VMESS_WS_PATH=$(generate_random_string 8)
    VLESS_WS_PATH=$(generate_random_string 8)
    MIXED_PASSWORD=$(generate_random_string 16)
    
    # Reality 密钥对生成
    local reality_keys=$("${SINGBOX_BINARY}" generate reality-keypair)
    REALITY_PRIVATE_KEY=$(echo "${reality_keys}" | grep "PrivateKey:" | awk '{print $2}')
    REALITY_PUBLIC_KEY=$(echo "${reality_keys}" | grep "PublicKey:" | awk '{print $2}')
    
    # TLS服务器配置
    TLS_SERVER_NAME="www.microsoft.com"
    
    print_success "协议配置变量生成完成"
}

# 生成XTLS-Reality配置
generate_xtls_reality_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/xtls-reality.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "vless",
            "tag": "xtls-reality-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[0]},
            "users": [
                {
                    "uuid": "${PROTOCOL_UUIDS[0]}",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${TLS_SERVER_NAME}",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "${TLS_SERVER_NAME}",
                        "server_port": ${REALITY_HANDSHAKE_PORT}
                    },
                    "private_key": "${REALITY_PRIVATE_KEY}",
                    "short_id": [""]
                }
            },
            "multiplex": {
                "enabled": true,
                "padding": true,
                "brutal": {
                    "enabled": true,
                    "up_mbps": 1000,
                    "down_mbps": 1000
                }
            }
        }
    ]
}
EOF
    
    print_info "XTLS-Reality配置已生成: ${config_file}"
}

# 生成VLESS-Reality配置
generate_vless_reality_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/vless-reality.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-reality-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[1]},
            "users": [
                {
                    "uuid": "${PROTOCOL_UUIDS[1]}",
                    "flow": ""
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${TLS_SERVER_NAME}",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "${TLS_SERVER_NAME}",
                        "server_port": ${REALITY_HANDSHAKE_PORT}
                    },
                    "private_key": "${REALITY_PRIVATE_KEY}",
                    "short_id": [""]
                }
            }
        }
    ]
}
EOF
    
    print_info "VLESS-Reality配置已生成: ${config_file}"
}

# 生成Hysteria2配置
generate_hysteria2_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/hysteria2.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[2]},
            "users": [
                {
                    "password": "${PROTOCOL_UUIDS[2]}"
                }
            ],
            "ignore_client_bandwidth": false,
            "obfs": {
                "type": "salamander",
                "password": "${HYSTERIA2_OBFS_PASSWORD}"
            },
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "min_version": "1.3",
                "max_version": "1.3",
                "certificate_path": "${SINGBOX_CONFIG_DIR}/certs/cert.pem",
                "key_path": "${SINGBOX_CONFIG_DIR}/certs/private.key"
            }
        }
    ]
}
EOF
    
    print_info "Hysteria2配置已生成: ${config_file}"
}

# 生成TUIC配置
generate_tuic_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/tuic.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[3]},
            "users": [
                {
                    "uuid": "${PROTOCOL_UUIDS[3]}",
                    "password": "${TUIC_PASSWORD}"
                }
            ],
            "congestion_control": "bbr",
            "zero_rtt_handshake": false,
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "${SINGBOX_CONFIG_DIR}/certs/cert.pem",
                "key_path": "${SINGBOX_CONFIG_DIR}/certs/private.key"
            }
        }
    ]
}
EOF
    
    print_info "TUIC配置已生成: ${config_file}"
}

# 生成ShadowTLS配置
generate_shadowtls_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/shadowtls.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "shadowtls",
            "tag": "shadowtls-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[4]},
            "detour": "shadowtls-ss",
            "version": 3,
            "users": [
                {
                    "password": "${SHADOWTLS_PASSWORD}"
                }
            ],
            "handshake": {
                "server": "${TLS_SERVER_NAME}",
                "server_port": ${SHADOWTLS_HANDSHAKE_PORT}
            },
            "strict_mode": true
        },
        {
            "type": "shadowsocks",
            "tag": "shadowtls-ss",
            "listen": "127.0.0.1",
            "network": "tcp",
            "method": "2022-blake3-aes-128-gcm",
            "password": "${SHADOWTLS_PASSWORD}"
        }
    ]
}
EOF
    
    print_info "ShadowTLS配置已生成: ${config_file}"
}

# 生成Trojan配置
generate_trojan_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/trojan.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[5]},
            "users": [
                {
                    "password": "${TROJAN_PASSWORD}"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "${SINGBOX_CONFIG_DIR}/certs/cert.pem",
                "key_path": "${SINGBOX_CONFIG_DIR}/certs/private.key"
            }
        }
    ]
}
EOF
    
    print_info "Trojan配置已生成: ${config_file}"
}

# 生成VMess配置
generate_vmess_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/vmess.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "vmess",
            "tag": "vmess-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[6]},
            "users": [
                {
                    "uuid": "${PROTOCOL_UUIDS[6]}",
                    "alterId": 0
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/${VMESS_WS_PATH}",
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol"
            },
            "tls": {
                "enabled": true,
                "certificate_path": "${SINGBOX_CONFIG_DIR}/certs/cert.pem",
                "key_path": "${SINGBOX_CONFIG_DIR}/certs/private.key"
            }
        }
    ]
}
EOF
    
    print_info "VMess配置已生成: ${config_file}"
}

# 生成VLESS配置
generate_vless_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/vless.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[7]},
            "users": [
                {
                    "uuid": "${PROTOCOL_UUIDS[7]}"
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/${VLESS_WS_PATH}",
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol"
            },
            "tls": {
                "enabled": true,
                "certificate_path": "${SINGBOX_CONFIG_DIR}/certs/cert.pem",
                "key_path": "${SINGBOX_CONFIG_DIR}/certs/private.key"
            }
        }
    ]
}
EOF
    
    print_info "VLESS配置已生成: ${config_file}"
}

# 生成Shadowsocks配置
generate_shadowsocks_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/shadowsocks.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[8]},
            "method": "2022-blake3-aes-128-gcm",
            "password": "${PROTOCOL_UUIDS[8]}"
        }
    ]
}
EOF
    
    print_info "Shadowsocks配置已生成: ${config_file}"
}

# 生成Naive配置
generate_naive_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/naive.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "naive",
            "tag": "naive-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[9]},
            "users": [
                {
                    "username": "user",
                    "password": "${PROTOCOL_UUIDS[9]}"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "${SINGBOX_CONFIG_DIR}/certs/cert.pem",
                "key_path": "${SINGBOX_CONFIG_DIR}/certs/private.key"
            }
        }
    ]
}
EOF
    
    print_info "Naive配置已生成: ${config_file}"
}

# 生成H2-Reality配置
generate_h2_reality_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/h2-reality.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "vless",
            "tag": "h2-reality-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[10]},
            "users": [
                {
                    "uuid": "${PROTOCOL_UUIDS[10]}"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${TLS_SERVER_NAME}",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "${TLS_SERVER_NAME}",
                        "server_port": ${REALITY_HANDSHAKE_PORT}
                    },
                    "private_key": "${REALITY_PRIVATE_KEY}",
                    "short_id": [""]
                }
            },
            "transport": {
                "type": "http"
            }
        }
    ]
}
EOF
    
    print_info "H2-Reality配置已生成: ${config_file}"
}

# 生成gRPC-Reality配置
generate_grpc_reality_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/grpc-reality.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "vless",
            "tag": "grpc-reality-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[11]},
            "users": [
                {
                    "uuid": "${PROTOCOL_UUIDS[11]}"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${TLS_SERVER_NAME}",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "${TLS_SERVER_NAME}",
                        "server_port": ${REALITY_HANDSHAKE_PORT}
                    },
                    "private_key": "${REALITY_PRIVATE_KEY}",
                    "short_id": [""]
                }
            },
            "transport": {
                "type": "grpc",
                "service_name": "grpc"
            }
        }
    ]
}
EOF
    
    print_info "gRPC-Reality配置已生成: ${config_file}"
}

# 生成AnyTLS配置
generate_anytls_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/anytls.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "anytls",
            "tag": "anytls-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[12]},
            "users": [
                {
                    "name": "user1",
                    "password": "${PROTOCOL_UUIDS[12]}"
                }
            ],
            "padding_scheme": [
                "stop=8",
                "0=30-30",
                "1=100-400",
                "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
                "3=9-9,500-1000",
                "4=500-1000",
                "5=500-1000",
                "6=500-1000",
                "7=500-1000"
            ],
            "tls": {
                "enabled": true,
                "certificate_path": "${SINGBOX_CONFIG_DIR}/certs/cert.pem",
                "key_path": "${SINGBOX_CONFIG_DIR}/certs/private.key"
            }
        }
    ]
}
EOF
    
    print_info "AnyTLS配置已生成: ${config_file}"
}

# 生成Direct配置
generate_direct_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/direct.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "direct",
            "tag": "direct-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[13]},
            "network": "tcp",
            "override_address": "127.0.0.1",
            "override_port": 80
        }
    ]
}
EOF
    
    print_info "Direct配置已生成: ${config_file}"
}

# 生成Mixed配置
generate_mixed_config() {
    local config_file="${SINGBOX_CONFIG_DIR}/mixed.json"
    
    cat > "${config_file}" << EOF
{
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "::",
            "listen_port": ${PROTOCOL_PORTS[14]},
            "users": [
                {
                    "username": "user",
                    "password": "${MIXED_PASSWORD}"
                }
            ]
        }
    ]
}
EOF
    
    print_info "Mixed配置已生成: ${config_file}"
}

# 生成主配置文件
generate_main_config() {
    print_info "$(get_text 'generate_config')"
    
    local config_file="${SINGBOX_CONFIG_DIR}/config.json"
    
    cat > "${config_file}" << EOF
{
    "log": {
        "disabled": false,
        "level": "info",
        "output": "${SINGBOX_LOG_DIR}/sing-box.log",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "type": "https",
                "tag": "google",
                "server": "8.8.8.8",
                "domain_resolver": "local"
            },
            {
                "type": "https",
                "tag": "cloudflare", 
                "server": "1.1.1.1",
                "domain_resolver": "local"
            },
            {
                "type": "udp",
                "tag": "local",
                "server": "223.5.5.5",
                "detour": "direct"
            }
        ],
        "rules": [],
        "final": "google",
        "strategy": "prefer_ipv4",
        "disable_cache": false,
        "disable_expire": false,
        "default_domain_resolver": "local"
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
        },
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["direct"]
        }
    ],
    "route": {
        "rule_set": [
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
            }
        ],
        "rules": [
            {
                "action": "sniff"
            },
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
                    "fe80::/10",
                    "ff00::/8"
                ],
                "outbound": "direct"
            },
            {
                "rule_set": ["geosite-cn"],
                "outbound": "direct"
            },
            {
                "rule_set": ["geoip-cn"],
                "outbound": "direct"
            },
            {
                "domain_suffix": [
                    ".cn",
                    ".com.cn",
                    ".net.cn",
                    ".org.cn",
                    ".gov.cn",
                    ".edu.cn"
                ],
                "outbound": "direct"
            }
        ],
        "final": "proxy",
        "auto_detect_interface": true
    }
}
EOF
    
    print_success "主配置文件已生成: ${config_file}"
}

# 生成所有协议配置
generate_all_configs() {
    print_info "正在生成所有协议配置..."
    
    # 生成协议变量
    generate_protocol_variables
    
    # 生成各协议配置
    generate_xtls_reality_config
    generate_vless_reality_config
    generate_hysteria2_config
    generate_tuic_config
    generate_shadowtls_config
    generate_trojan_config
    generate_vmess_config
    generate_vless_config
    generate_shadowsocks_config
    generate_naive_config
    generate_h2_reality_config
    generate_grpc_reality_config
    generate_anytls_config
    generate_direct_config
    generate_mixed_config
    
    # 生成主配置
    generate_main_config
    
    print_success "所有协议配置生成完成"
}

# =============================================================================
# 服务管理模块
# =============================================================================

# 启动Sing-box服务
start_singbox_service() {
    print_info "正在启动Sing-box服务..."
    
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        print_warning "Sing-box服务已在运行中"
        return 0
    fi
    
    if systemctl start "${SERVICE_NAME}" 2>/dev/null; then
        sleep 2
        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            print_success "Sing-box服务启动成功"
            return 0
        else
            print_error "Sing-box服务启动失败"
            show_service_logs
            return 1
        fi
    else
        print_error "无法启动Sing-box服务"
        return 1
    fi
}

# 停止Sing-box服务
stop_singbox_service() {
    print_info "正在停止Sing-box服务..."
    
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        print_warning "Sing-box服务未在运行"
        return 0
    fi
    
    if systemctl stop "${SERVICE_NAME}" 2>/dev/null; then
        sleep 2
        if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
            print_success "Sing-box服务停止成功"
            return 0
        else
            print_error "Sing-box服务停止失败"
            return 1
        fi
    else
        print_error "无法停止Sing-box服务"
        return 1
    fi
}

# 重启Sing-box服务
restart_singbox_service() {
    print_info "正在重启Sing-box服务..."
    
    if systemctl restart "${SERVICE_NAME}" 2>/dev/null; then
        sleep 3
        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            print_success "Sing-box服务重启成功"
            return 0
        else
            print_error "Sing-box服务重启失败"
            show_service_logs
            return 1
        fi
    else
        print_error "无法重启Sing-box服务"
        return 1
    fi
}

# 重载Sing-box服务配置
reload_singbox_service() {
    print_info "正在重载Sing-box服务配置..."
    
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        print_warning "服务未运行，将启动服务"
        start_singbox_service
        return $?
    fi
    
    # 发送SIGHUP信号重载配置
    local pid=$(systemctl show --property MainPID --value "${SERVICE_NAME}")
    if [[ -n "${pid}" && "${pid}" != "0" ]]; then
        if kill -HUP "${pid}" 2>/dev/null; then
            print_success "Sing-box配置重载成功"
            return 0
        else
            print_warning "配置重载失败，尝试重启服务"
            restart_singbox_service
            return $?
        fi
    else
        print_warning "无法获取服务PID，尝试重启服务"
        restart_singbox_service
        return $?
    fi
}

# 查看服务状态
show_service_status() {
    print_info "Sing-box服务状态信息："
    echo
    
    # 基本状态信息
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        print_success "服务状态: ${GREEN}运行中${NC}"
    else
        print_error "服务状态: ${RED}已停止${NC}"
    fi
    
    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        print_info "开机自启: ${GREEN}已启用${NC}"
    else
        print_warning "开机自启: ${YELLOW}未启用${NC}"
    fi
    
    # 详细状态信息
    echo
    print_info "详细状态信息："
    systemctl status "${SERVICE_NAME}" --no-pager -l 2>/dev/null || {
        print_error "无法获取服务状态信息"
        return 1
    }
    
    # 端口监听状态
    echo
    print_info "端口监听状态："
    local listening_ports=$(ss -tlnp 2>/dev/null | grep sing-box | awk '{print $4}' | cut -d: -f2 | sort -n | tr '\n' ' ')
    if [[ -n "${listening_ports}" ]]; then
        print_success "监听端口: ${listening_ports}"
    else
        print_warning "未检测到监听端口"
    fi
    
    # 内存使用情况
    local memory_usage=$(systemctl show --property MemoryCurrent --value "${SERVICE_NAME}" 2>/dev/null)
    if [[ -n "${memory_usage}" && "${memory_usage}" != "[not set]" ]]; then
        local memory_mb=$((memory_usage / 1024 / 1024))
        print_info "内存使用: ${memory_mb}MB"
    fi
}

# 查看服务日志
show_service_logs() {
    local lines="${1:-50}"
    
    print_info "Sing-box服务日志 (最近${lines}行)："
    echo
    
    if journalctl -u "${SERVICE_NAME}" -n "${lines}" --no-pager 2>/dev/null; then
        return 0
    else
        print_error "无法获取服务日志"
        
        # 尝试查看日志文件
        if [[ -f "${SINGBOX_LOG_DIR}/sing-box.log" ]]; then
            print_info "尝试查看日志文件："
            tail -n "${lines}" "${SINGBOX_LOG_DIR}/sing-box.log" 2>/dev/null || {
                print_error "无法读取日志文件"
                return 1
            }
        else
            print_error "日志文件不存在"
            return 1
        fi
    fi
}

# 实时查看服务日志
follow_service_logs() {
    print_info "实时查看Sing-box服务日志 (按Ctrl+C退出)："
    echo
    
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u "${SERVICE_NAME}" -f --no-pager 2>/dev/null || {
            print_error "无法实时查看systemd日志"
            
            # 尝试tail日志文件
            if [[ -f "${SINGBOX_LOG_DIR}/sing-box.log" ]]; then
                print_info "尝试实时查看日志文件："
                tail -f "${SINGBOX_LOG_DIR}/sing-box.log" 2>/dev/null || {
                    print_error "无法实时查看日志文件"
                    return 1
                }
            else
                print_error "日志文件不存在"
                return 1
            fi
        }
    else
        print_error "journalctl命令不可用"
        return 1
    fi
}

# 启用开机自启
enable_service_autostart() {
    print_info "正在启用Sing-box开机自启..."
    
    if systemctl enable "${SERVICE_NAME}" 2>/dev/null; then
        print_success "开机自启启用成功"
        return 0
    else
        print_error "开机自启启用失败"
        return 1
    fi
}

# 禁用开机自启
disable_service_autostart() {
    print_info "正在禁用Sing-box开机自启..."
    
    if systemctl disable "${SERVICE_NAME}" 2>/dev/null; then
        print_success "开机自启禁用成功"
        return 0
    else
        print_error "开机自启禁用失败"
        return 1
    fi
}

# 检查配置文件语法
check_config_syntax() {
    print_info "正在检查配置文件语法..."
    
    local config_file="${SINGBOX_CONFIG_DIR}/config.json"
    
    if [[ ! -f "${config_file}" ]]; then
        print_error "配置文件不存在: ${config_file}"
        return 1
    fi
    
    # 使用sing-box检查配置
    if "${SINGBOX_BINARY}" check -c "${config_file}" 2>/dev/null; then
        print_success "配置文件语法正确"
        return 0
    else
        print_error "配置文件语法错误"
        print_info "详细错误信息："
        "${SINGBOX_BINARY}" check -c "${config_file}" 2>&1 || true
        return 1
    fi
}

# 服务管理主菜单
service_management_menu() {
    while true; do
        echo
        print_info "========== Sing-box 服务管理 =========="
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 重载配置"
        echo "5. 查看状态"
        echo "6. 查看日志"
        echo "7. 实时日志"
        echo "8. 启用开机自启"
        echo "9. 禁用开机自启"
        echo "10. 检查配置语法"
        echo "0. 返回主菜单"
        print_info "======================================="
        echo
        
        read -p "请选择操作 [0-10]: " choice
        
        case "${choice}" in
            1)
                start_singbox_service
                ;;
            2)
                stop_singbox_service
                ;;
            3)
                restart_singbox_service
                ;;
            4)
                reload_singbox_service
                ;;
            5)
                show_service_status
                ;;
            6)
                echo
                read -p "显示日志行数 [默认50]: " log_lines
                log_lines=${log_lines:-50}
                show_service_logs "${log_lines}"
                ;;
            7)
                follow_service_logs
                ;;
            8)
                enable_service_autostart
                ;;
            9)
                disable_service_autostart
                ;;
            10)
                check_config_syntax
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选择，请重新输入"
                ;;
        esac
        
        echo
        read -p "按回车键继续..."
    done
}

# =============================================================================
# 节点信息生成模块
# =============================================================================

# Base64编码函数
base64_encode() {
    if command -v base64 >/dev/null 2>&1; then
        echo -n "$1" | base64 -w 0
    else
        echo -n "$1" | openssl base64 -A
    fi
}

# 生成VLESS-Reality节点链接
generate_vless_reality_link() {
    local uuid="${PROTOCOL_UUIDS[0]}"
    local port="${PROTOCOL_PORTS[0]}"
    local sni="www.yahoo.com"
    local public_key="${REALITY_PUBLIC_KEY}"
    local short_id=""
    
    echo "vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#VLESS-Reality-${SERVER_IP}"
}

# 生成Hysteria2节点链接
generate_hysteria2_link() {
    local password="${PROTOCOL_UUIDS[2]}"
    local port="${PROTOCOL_PORTS[2]}"
    local sni="www.bing.com"
    
    echo "hysteria2://${password}@${SERVER_IP}:${port}?sni=${sni}&alpn=h3&insecure=1#Hysteria2-${SERVER_IP}"
}

# 生成VMess节点链接
generate_vmess_link() {
    local uuid="${PROTOCOL_UUIDS[6]}"
    local port="${PROTOCOL_PORTS[6]}"
    local path="/${VMESS_WS_PATH}"
    
    local vmess_json=$(cat << EOF
{
  "v": "2",
  "ps": "VMess-WS-${SERVER_IP}",
  "add": "${SERVER_IP}",
  "port": "${port}",
  "id": "${uuid}",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "${path}",
  "tls": "",
  "sni": "",
  "alpn": ""
}
EOF
    )
    
    echo "vmess://$(base64_encode "${vmess_json}")"
}

# 生成TUIC节点链接
generate_tuic_link() {
    local uuid="${PROTOCOL_UUIDS[3]}"
    local password="${TUIC_PASSWORD}"
    local port="${PROTOCOL_PORTS[3]}"
    
    echo "tuic://${uuid}:${password}@${SERVER_IP}:${port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#TUIC-${SERVER_IP}"
}

# 生成ShadowTLS节点链接
generate_shadowtls_link() {
    local password="${SHADOWTLS_PASSWORD}"
    local port="${PROTOCOL_PORTS[4]}"
    local sni="www.microsoft.com"
    
    echo "shadowtls://${password}@${SERVER_IP}:${port}?version=3&sni=${sni}&strict=true#ShadowTLS-v3-${SERVER_IP}"
}

# 生成Trojan节点链接
generate_trojan_link() {
    local password="${TROJAN_PASSWORD}"
    local port="${PROTOCOL_PORTS[5]}"
    
    echo "trojan://${password}@${SERVER_IP}:${port}?allowInsecure=1&sni=${SERVER_IP}#Trojan-${SERVER_IP}"
}

# 生成VLESS-WS节点链接
generate_vless_ws_link() {
    local uuid="${PROTOCOL_UUIDS[7]}"
    local port="${PROTOCOL_PORTS[7]}"
    local path="/${VLESS_WS_PATH}"
    
    echo "vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=tls&sni=${SERVER_IP}&type=ws&host=${SERVER_IP}&path=${path}#VLESS-WS-${SERVER_IP}"
}

# 生成Shadowsocks节点链接
generate_shadowsocks_link() {
    local method="aes-256-gcm"
    local password="${PROTOCOL_UUIDS[8]}"
    local port="${PROTOCOL_PORTS[8]}"
    local auth=$(base64_encode "${method}:${password}")
    
    echo "ss://${auth}@${SERVER_IP}:${port}#Shadowsocks-${SERVER_IP}"
}

# 生成Naive节点链接
generate_naive_link() {
    local uuid="${PROTOCOL_UUIDS[9]}"
    local port="${PROTOCOL_PORTS[9]}"
    
    echo "https://${uuid}:${uuid}@${SERVER_IP}:${port}#Naive-${SERVER_IP}"
}

# 生成H2-Reality节点链接
generate_h2_reality_link() {
    local uuid="${PROTOCOL_UUIDS[10]}"
    local port="${PROTOCOL_PORTS[10]}"
    local sni="www.apple.com"
    local public_key="${REALITY_PUBLIC_KEY}"
    local short_id=""
    
    echo "vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=http&path=/http#H2-Reality-${SERVER_IP}"
}

# 生成gRPC-Reality节点链接
generate_grpc_reality_link() {
    local uuid="${PROTOCOL_UUIDS[11]}"
    local port="${PROTOCOL_PORTS[11]}"
    local sni="www.cloudflare.com"
    local public_key="${REALITY_PUBLIC_KEY}"
    local short_id=""
    
    echo "vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=grpc&serviceName=grpc#gRPC-Reality-${SERVER_IP}"
}

# 生成Clash配置
generate_clash_config() {
    cat > "${SINGBOX_CONFIG_DIR}/clash.yaml" << EOF
port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - name: "VLESS-Reality-${SERVER_IP}"
    type: vless
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[0]}
    uuid: ${PROTOCOL_UUIDS[0]}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    servername: www.yahoo.com
    reality-opts:
      public-key: ${REALITY_PUBLIC_KEY}
      short-id: ""

  - name: "Hysteria2-${SERVER_IP}"
    type: hysteria2
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[2]}
    password: ${PROTOCOL_UUIDS[2]}
    sni: www.bing.com
    skip-cert-verify: true

  - name: "VMess-WS-${SERVER_IP}"
    type: vmess
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[6]}
    uuid: ${PROTOCOL_UUIDS[6]}
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /${VMESS_WS_PATH}

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - "VLESS-Reality-${SERVER_IP}"
      - "Hysteria2-${SERVER_IP}"
      - "VMess-WS-${SERVER_IP}"

rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - IP-CIDR,1.0.1.0/24,DIRECT
  - IP-CIDR,1.0.2.0/23,DIRECT
  - IP-CIDR,1.0.8.0/21,DIRECT
  - IP-CIDR,1.0.32.0/19,DIRECT
  - IP-CIDR,1.1.0.0/24,DIRECT
  - IP-CIDR,1.1.8.0/24,DIRECT
  - IP-CIDR,1.2.0.0/23,DIRECT
  - IP-CIDR,1.2.4.0/22,DIRECT
  - MATCH,🚀 节点选择
EOF

    print_success "Clash配置已生成: ${SINGBOX_CONFIG_DIR}/clash.yaml"
}

# 生成Sing-box客户端配置
generate_singbox_client_config() {
    cat > "${SINGBOX_CONFIG_DIR}/client.json" << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "google",
        "server": "8.8.8.8"
      }
    ]
  },
  "inbounds": [
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "VLESS-Reality",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[0]},
      "uuid": "${PROTOCOL_UUIDS[0]}",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "${REALITY_PUBLIC_KEY}",
          "short_id": ""
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "Hysteria2",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[2]},
      "password": "${PROTOCOL_UUIDS[2]}",
      "tls": {
        "enabled": true,
        "server_name": "www.bing.com",
        "insecure": true
      }
    },
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
          "1.0.1.0/24",
          "1.0.2.0/23",
          "1.0.8.0/21",
          "1.0.32.0/19",
          "1.1.0.0/24",
          "1.1.8.0/24",
          "1.2.0.0/23",
          "1.2.4.0/22"
        ],
        "outbound": "direct"
      },
      {
        "domain_suffix": [
          ".cn",
          ".com.cn",
          ".net.cn",
          ".org.cn",
          ".gov.cn",
          ".edu.cn"
        ],
        "outbound": "direct"
      }
    ],
    "final": "VLESS-Reality"
  }
}
EOF

    print_success "Sing-box客户端配置已生成: ${SINGBOX_CONFIG_DIR}/client.json"
}

# 显示所有节点信息
show_node_info() {
    echo
    print_info "========== 节点信息 =========="
    echo
    
    print_info "1. VLESS-Reality:"
    echo "$(generate_vless_reality_link)"
    echo
    
    print_info "2. Hysteria2:"
    echo "$(generate_hysteria2_link)"
    echo
    
    print_info "3. TUIC:"
    echo "$(generate_tuic_link)"
    echo
    
    print_info "4. ShadowTLS v3:"
    echo "$(generate_shadowtls_link)"
    echo
    
    print_info "5. Trojan:"
    echo "$(generate_trojan_link)"
    echo
    
    print_info "6. VMess-WS:"
    echo "$(generate_vmess_link)"
    echo
    
    print_info "7. VLESS-WS:"
    echo "$(generate_vless_ws_link)"
    echo
    
    print_info "8. Shadowsocks:"
    echo "$(generate_shadowsocks_link)"
    echo
    
    print_info "9. Naive:"
    echo "$(generate_naive_link)"
    echo
    
    print_info "10. H2-Reality:"
    echo "$(generate_h2_reality_link)"
    echo
    
    print_info "11. gRPC-Reality:"
    echo "$(generate_grpc_reality_link)"
    echo
    
    print_info "12. AnyTLS:"
    echo "anytls://user1:${PROTOCOL_UUIDS[12]}@${SERVER_IP}:${PROTOCOL_PORTS[12]}?sni=${SERVER_IP}&allowInsecure=1#AnyTLS-${SERVER_IP}"
    echo
    
    print_info "13. Direct:"
    echo "direct://${SERVER_IP}:${PROTOCOL_PORTS[13]}#Direct-${SERVER_IP}"
    echo
    
    print_info "14. Mixed:"
    echo "mixed://user:${MIXED_PASSWORD}@${SERVER_IP}:${PROTOCOL_PORTS[14]}#Mixed-${SERVER_IP}"
    echo
    
    print_info "=============================="
    echo
    
    print_info "配置文件位置:"
    print_info "- Clash配置: ${SINGBOX_CONFIG_DIR}/clash.yaml"
    print_info "- Sing-box客户端配置: ${SINGBOX_CONFIG_DIR}/client.json"
    echo
}

# 生成所有客户端配置
generate_all_client_configs() {
    print_info "正在生成客户端配置文件..."
    
    generate_clash_config
    generate_singbox_client_config
    
    print_success "所有客户端配置生成完成"
}

# =============================================================================
# 主安装函数
# =============================================================================

# 更新主安装函数
main_install() {
    print_info "$(get_text 'welcome')"
    print_info "脚本版本: ${SCRIPT_VERSION}"
    print_info "Sing-box版本: ${SINGBOX_VERSION}"
    
    # 系统检测
    detect_os
    detect_arch
    check_network
    get_server_ip
    
    # 安装依赖
    install_dependencies
    
    # 检查工具
    if ! check_required_tools; then
        print_error "系统环境检查失败"
        exit 1
    fi
    
    # 端口分配
    generate_consecutive_ports
    
    # 创建目录
    create_directories
    
    # 下载安装 Sing-box
    download_singbox
    
    # 管理证书
    manage_certificates
    
    # 创建系统服务
    create_systemd_service
    
    # 生成所有协议配置
    generate_all_configs
    
    # 生成客户端配置
    generate_all_client_configs
    
    print_success "$(get_text 'install_success')"
    print_info "所有15种协议配置已生成完成"
    
    # 启动服务
    print_info "正在启动 Sing-box 服务..."
    if start_singbox_service; then
        print_success "Sing-box 服务启动成功"
        echo
        # 显示节点信息
        show_node_info
    else
        print_error "Sing-box 服务启动失败，请检查配置"
        print_info "您可以稍后使用菜单选项1重新启动服务"
    fi
}

# =============================================================================
# 管理菜单模块
# =============================================================================

# 卸载Sing-box
uninstall_singbox() {
    print_warning "即将卸载Sing-box及所有相关配置"
    echo
    read -p "确认卸载？[y/N]: " confirm
    
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        print_info "取消卸载操作"
        return 0
    fi
    
    print_info "正在卸载Sing-box..."
    
    # 停止并禁用服务
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        print_info "停止Sing-box服务..."
        systemctl stop "${SERVICE_NAME}" 2>/dev/null
    fi
    
    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        print_info "禁用Sing-box开机自启..."
        systemctl disable "${SERVICE_NAME}" 2>/dev/null
    fi
    
    # 删除systemd服务文件
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        print_info "删除systemd服务文件..."
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
    fi
    
    # 删除二进制文件
    if [[ -f "${SINGBOX_BINARY}" ]]; then
        print_info "删除Sing-box二进制文件..."
        rm -f "${SINGBOX_BINARY}"
    fi
    
    # 删除配置目录
    if [[ -d "${SINGBOX_CONFIG_DIR}" ]]; then
        print_info "删除配置目录..."
        rm -rf "${SINGBOX_CONFIG_DIR}"
    fi
    
    # 删除日志目录
    if [[ -d "${SINGBOX_LOG_DIR}" ]]; then
        print_info "删除日志目录..."
        rm -rf "${SINGBOX_LOG_DIR}"
    fi
    
    print_success "Sing-box卸载完成"
    echo
    print_warning "注意：如需删除安装脚本，请手动执行以下命令："
    print_info "rm -f $0"
    echo
}

# 更新Sing-box
update_singbox() {
    print_info "正在检查Sing-box更新..."
    
    # 获取当前版本
    local current_version=""
    if [[ -f "${SINGBOX_BINARY}" ]]; then
        current_version=$("${SINGBOX_BINARY}" version 2>/dev/null | grep -oP 'sing-box version \K[0-9.]+' || echo "未知")
    fi
    
    print_info "当前版本: ${current_version}"
    print_info "目标版本: ${SINGBOX_VERSION}"
    
    if [[ "${current_version}" == "${SINGBOX_VERSION}" ]]; then
        print_success "已是最新版本，无需更新"
        return 0
    fi
    
    echo
    read -p "确认更新到版本 ${SINGBOX_VERSION}？[y/N]: " confirm
    
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        print_info "取消更新操作"
        return 0
    fi
    
    # 停止服务
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        print_info "停止Sing-box服务..."
        systemctl stop "${SERVICE_NAME}"
    fi
    
    # 备份当前配置
    local backup_dir="/tmp/singbox_backup_$(date +%Y%m%d_%H%M%S)"
    if [[ -d "${SINGBOX_CONFIG_DIR}" ]]; then
        print_info "备份当前配置到: ${backup_dir}"
        mkdir -p "${backup_dir}"
        cp -r "${SINGBOX_CONFIG_DIR}"/* "${backup_dir}/" 2>/dev/null || true
    fi
    
    # 下载新版本
    if download_singbox; then
        print_success "Sing-box更新完成"
        
        # 重启服务
        if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
            print_info "重启Sing-box服务..."
            systemctl start "${SERVICE_NAME}"
            
            if systemctl is-active --quiet "${SERVICE_NAME}"; then
                print_success "服务重启成功"
            else
                print_error "服务重启失败，请检查配置"
                show_service_logs 20
            fi
        fi
    else
        print_error "更新失败"
        
        # 恢复备份
        if [[ -d "${backup_dir}" ]]; then
            print_info "恢复备份配置..."
            cp -r "${backup_dir}"/* "${SINGBOX_CONFIG_DIR}/" 2>/dev/null || true
        fi
        
        return 1
    fi
}

# 主菜单
show_main_menu() {
    clear
    echo
    print_info "========================================"
    print_info "         SBall Sing-box 管理脚本"
    print_info "========================================"
    print_info "脚本版本: ${SCRIPT_VERSION}"
    print_info "Sing-box版本: ${SINGBOX_VERSION}"
    
    # 显示服务状态
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        print_success "服务状态: 运行中"
    else
        print_error "服务状态: 已停止"
    fi
    
    print_info "========================================"
    echo
    echo "1. 安装 Sing-box"
    echo "2. 更新 Sing-box"
    echo "3. 卸载 Sing-box"
    echo "4. 查看节点信息"
    echo "5. 启动/停止服务"
    echo "6. 查看服务状态"
    echo "7. 查看服务日志"
    echo "8. 退出"
    echo
}

# 主菜单循环
main_menu() {
    while true; do
        show_main_menu
        read -p "请选择操作 [1-8]: " choice
        
        case "${choice}" in
            1)
                echo
                print_info "开始安装Sing-box..."
                echo
                
                # 检查是否已安装
                if [[ -f "${SINGBOX_BINARY}" ]] && systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
                    print_warning "Sing-box已安装，如需重新安装请先卸载"
                    echo
                    read -p "按回车键继续..."
                    continue
                fi
                
                main_install
                echo
                read -p "按回车键继续..."
                ;;
            2)
                echo
                update_singbox
                echo
                read -p "按回车键继续..."
                ;;
            3)
                echo
                uninstall_singbox
                echo
                read -p "按回车键继续..."
                ;;
            4)
                echo
                if [[ ! -f "${SINGBOX_CONFIG_DIR}/config.json" ]]; then
                    print_error "Sing-box未安装或配置文件不存在"
                else
                    show_node_info
                fi
                echo
                read -p "按回车键继续..."
                ;;
            5)
                echo
                if [[ ! -f "${SINGBOX_BINARY}" ]]; then
                    print_error "Sing-box未安装"
                else
                    service_management_menu
                fi
                ;;
            6)
                echo
                if [[ ! -f "${SINGBOX_BINARY}" ]]; then
                    print_error "Sing-box未安装"
                else
                    show_service_status
                fi
                echo
                read -p "按回车键继续..."
                ;;
            7)
                echo
                if [[ ! -f "${SINGBOX_BINARY}" ]]; then
                    print_error "Sing-box未安装"
                else
                    echo
                    read -p "显示日志行数 [默认50]: " log_lines
                    log_lines=${log_lines:-50}
                    show_service_logs "${log_lines}"
                fi
                echo
                read -p "按回车键继续..."
                ;;
            8)
                echo
                print_info "感谢使用SBall Sing-box管理脚本！"
                exit 0
                ;;
            *)
                echo
                print_error "无效选择，请重新输入"
                echo
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# =============================================================================
# 脚本入口点
# =============================================================================

# 检查运行权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本需要root权限运行"
        print_info "请使用: sudo $0"
        exit 1
    fi
}

# 脚本主函数
main() {
    # 检查root权限
    check_root
    
    # 解析命令行参数
    case "${1:-}" in
        "install" | "-i")
            main_install
            ;;
        "uninstall" | "-u")
            uninstall_singbox
            ;;
        "update" | "-up")
            update_singbox
            ;;
        "status" | "-s")
            show_service_status
            ;;
        "start")
            start_singbox_service
            ;;
        "stop")
            stop_singbox_service
            ;;
        "restart")
            restart_singbox_service
            ;;
        "logs" | "-l")
            show_service_logs "${2:-50}"
            ;;
        "info" | "-n")
            show_node_info
            ;;
        "menu" | "")
            main_menu
            ;;
        "help" | "-h" | "--help")
            echo "SBall Sing-box 管理脚本"
            echo
            echo "用法: $0 [选项]"
            echo
            echo "选项:"
            echo "  install, -i     安装Sing-box"
            echo "  uninstall, -u   卸载Sing-box"
            echo "  update, -up     更新Sing-box"
            echo "  status, -s      查看服务状态"
            echo "  start           启动服务"
            echo "  stop            停止服务"
            echo "  restart         重启服务"
            echo "  logs, -l [行数] 查看日志"
            echo "  info, -n        显示节点信息"
            echo "  menu            显示交互菜单（默认）"
            echo "  help, -h        显示帮助信息"
            echo
            ;;
        *)
            print_error "未知参数: $1"
            print_info "使用 '$0 help' 查看帮助信息"
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"
