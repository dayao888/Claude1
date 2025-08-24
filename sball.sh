#!/usr/bin/env bash

# SBall科学上网一键安装脚本
# 版本: v2.0.0 (2025.01.21)
# 基于 Sing-box 1.12.2 开发
# 支持11种主流代理协议，集成流量混淆和安全增强技术

# 脚本版本和基本信息
VERSION='v2.0.0 (2025.01.21)'
SING_BOX_VERSION='1.12.2'
SCRIPT_NAME='SBall'

# 默认变量配置
GH_PROXY='gh-proxy.com/'
TEMP_DIR='/tmp/sball'
WORK_DIR='/etc/sball'
START_PORT_DEFAULT='8881'
MIN_PORT=1000
MAX_PORT=65535
TLS_SERVER_DEFAULT='addons.mozilla.org'

# 11种主流代理协议列表
PROTOCOL_LIST=(
    "VLESS-Reality"     # 0
    "Hysteria2"         # 1
    "TUIC"              # 2
    "ShadowTLS"         # 3
    "Shadowsocks"       # 4
    "Trojan"            # 5
    "VMESS-WS"          # 6
    "VLESS-WS-TLS"      # 7
    "H2-Reality"        # 8
    "gRPC-Reality"      # 9
    "AnyTLS"            # 10
)

# 协议标签
NODE_TAG=(
    "vless-reality"     # 0
    "hysteria2"         # 1
    "tuic"              # 2
    "shadowtls"         # 3
    "shadowsocks"       # 4
    "trojan"            # 5
    "vmess-ws"          # 6
    "vless-ws-tls"      # 7
    "h2-reality"        # 8
    "grpc-reality"      # 9
    "anytls"            # 10
)

# 协议端口分配（将在input_config函数中动态生成）
declare -a PROTOCOL_PORTS
# 全局凭据与标识数组
declare -a UUID_ARRAY
declare -A PASSWORD_ARRAY

# CDN域名列表
CDN_DOMAIN=("skk.moe" "ip.sb" "time.is" "cfip.xxxxxxxx.tk" "bestcf.top" "cdn.2020111.xyz" "xn--b6gac.eu.org")

# 多语言支持
export DEBIAN_FRONTEND=noninteractive

# 错误处理
trap "rm -rf $TEMP_DIR >/dev/null 2>&1 ; echo -e '\n' ;exit" INT QUIT TERM EXIT

# 创建临时目录
mkdir -p $TEMP_DIR

# 多语言文本定义
E[0]="Language:\n 1. English (default) \n 2. 简体中文"
C[0]="${E[0]}"
E[1]="SBall Sing-box Installation Script"
C[1]="SBall Sing-box 一键安装脚本"
E[2]="Downloading Sing-box. Please wait..."
C[2]="下载 Sing-box 中，请稍等..."
E[3]="Input errors up to 5 times. Script aborted."
C[3]="输入错误达5次，脚本退出"
E[4]="The script supports Debian, Ubuntu, CentOS, Alpine, Fedora or Arch systems only."
C[4]="本脚本只支持 Debian、Ubuntu、CentOS、Alpine、Fedora 或 Arch 系统"
E[5]="Install dependencies:"
C[5]="安装依赖列表:"
E[6]="All dependencies already exist."
C[6]="所有依赖已存在，不需要额外安装"
E[7]="Please enter VPS IP (Default: \${SERVER_IP_DEFAULT}):"
C[7]="请输入 VPS IP (默认为: \${SERVER_IP_DEFAULT}):"
E[8]="Please enter starting port (Default: \${START_PORT_DEFAULT}):"
C[8]="请输入开始端口号 (默认为: \${START_PORT_DEFAULT}):"
E[9]="Please enter UUID (Default: \${UUID_DEFAULT}):"
C[9]="请输入 UUID (默认为: \${UUID_DEFAULT}):"
E[10]="Please enter node name (Default: \${NODE_NAME_DEFAULT}):"
C[10]="请输入节点名称 (默认为: \${NODE_NAME_DEFAULT}):"
E[11]="Choose:"
C[11]="请选择:"
E[12]="Install SBall Sing-box"
C[12]="安装 SBall Sing-box"
E[13]="View node information (sball -n)"
C[13]="查看节点信息 (sball -n)"
E[14]="Change ports (sball -p)"
C[14]="更换端口 (sball -p)"
E[15]="Update Sing-box (sball -v)"
C[15]="更新 Sing-box (sball -v)"
E[16]="Uninstall (sball -u)"
C[16]="卸载 (sball -u)"
E[17]="Exit"
C[17]="退出"
E[18]="Please enter correct number"
C[18]="请输入正确数字"
E[19]="Successful"
C[19]="成功"
E[20]="Failed"
C[20]="失败"

# 颜色和输出函数
warning() { echo -e "\033[31m\033[01m$*\033[0m"; }
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; }
info() { echo -e "\033[32m\033[01m$*\033[0m"; }
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }
reading() { read -rp "$(info "$1")" "$2"; }
text() { 
    local key="$*"
    local lang_var="${L}[$key]"
    local content="${!lang_var}"
    
    # 安全处理包含变量的文本
    if [[ "$content" =~ \$ ]]; then
        # 使用printf替代eval来安全处理变量替换
        content=$(printf '%s\n' "$content" | sed "s/\${SERVER_IP_DEFAULT}/$SERVER_IP_DEFAULT/g")
    fi
    
    echo "$content"
}

# 选择语言
select_language() {
    if [ -z "$L" ]; then
        if [ -s ${WORK_DIR}/language ]; then
            L=$(cat ${WORK_DIR}/language)
        else
            L=E && hint "\n $(text 0) \n" && reading " $(text 11) " LANGUAGE
            [ "$LANGUAGE" = 2 ] && L=C
        fi
    fi
}

# 检查root权限
check_root() {
    [ "$(id -u)" != 0 ] && error "\n 必须以root权限运行脚本 \n"
}

# 检查系统架构
check_arch() {
    case "$(uname -m)" in
        aarch64|arm64 )
            SING_BOX_ARCH=arm64
            ;;
        x86_64|amd64 )
            SING_BOX_ARCH=amd64
            ;;
        armv7l )
            SING_BOX_ARCH=armv7
            ;;
        * )
            error "当前架构 $(uname -m) 暂不支持"
    esac
}

# 检查操作系统
check_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        SYSTEM=$ID
        VERSION_ID=${VERSION_ID%%.*}
    else
        error "$(text 4)"
    fi
    
    case "$SYSTEM" in
        debian|ubuntu|centos|fedora|alpine|arch )
            ;;
        * )
            error "$(text 4)"
    esac
}

# 安装依赖
install_dependencies() {
    local DEPS=()
    
    case "$SYSTEM" in
        debian|ubuntu )
            DEPS=(curl wget unzip jq)
            apt update -y
            apt install -y "${DEPS[@]}"
            ;;
        centos|fedora )
            DEPS=(curl wget unzip jq)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "${DEPS[@]}"
            else
                yum install -y "${DEPS[@]}"
            fi
            ;;
        alpine )
            DEPS=(curl wget unzip jq)
            apk add --no-cache "${DEPS[@]}"
            ;;
        arch )
            DEPS=(curl wget unzip jq)
            pacman -Sy --noconfirm "${DEPS[@]}"
            ;;
    esac
    
    info "$(text 5) ${DEPS[*]}"
}

# 生成UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 生成随机字符串
generate_random_string() {
    local length=${1:-8}
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c $length
}

# 生成自签名TLS证书
generate_tls_certificate() {
    info "正在生成自签名TLS证书..."
    
    # 检查openssl是否安装
    if ! command -v openssl >/dev/null 2>&1; then
        case "$SYSTEM" in
            debian|ubuntu )
                apt install -y openssl
                ;;
            centos|fedora )
                if command -v dnf >/dev/null 2>&1; then
                    dnf install -y openssl
                else
                    yum install -y openssl
                fi
                ;;
            alpine )
                apk add --no-cache openssl
                ;;
            arch )
                pacman -Sy --noconfirm openssl
                ;;
        esac
    fi
    
    # 生成私钥
    openssl genrsa -out ${WORK_DIR}/private.key 2048
    
    # 生成证书签名请求配置
    cat > ${WORK_DIR}/cert.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = SBall
OU = IT Department
CN = ${TLS_SERVER_DEFAULT}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${TLS_SERVER_DEFAULT}
DNS.2 = *.${TLS_SERVER_DEFAULT}
IP.1 = ${SERVER_IP}
EOF
    
    # 生成自签名证书
    openssl req -new -x509 -key ${WORK_DIR}/private.key -out ${WORK_DIR}/cert.crt -days 365 -config ${WORK_DIR}/cert.conf -extensions v3_req
    
    # 设置文件权限
    chmod 600 ${WORK_DIR}/private.key
    chmod 644 ${WORK_DIR}/cert.crt
    
    # 清理临时文件
    rm -f ${WORK_DIR}/cert.conf
    
    info "TLS证书生成完成"
    info "证书文件: ${WORK_DIR}/cert.crt"
    info "私钥文件: ${WORK_DIR}/private.key"
}

# 获取服务器IP
get_server_ip() {
    local ip
    ip=$(curl -s4 ip.sb) || ip=$(curl -s4 ifconfig.me) || ip=$(curl -s4 icanhazip.com)
    echo "$ip"
}

# 下载Sing-box
download_sing_box() {
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${SING_BOX_ARCH}.tar.gz"
    
    info "$(text 2)"
    
    cd $TEMP_DIR
    if ! wget -O sing-box.tar.gz "$download_url"; then
        error "下载 Sing-box 失败"
    fi
    
    tar -xzf sing-box.tar.gz
    mv sing-box-*/sing-box ${WORK_DIR}/
    chmod +x ${WORK_DIR}/sing-box
    
    info "Sing-box 下载完成"
}

# 创建工作目录
create_work_dir() {
    mkdir -p ${WORK_DIR}/{conf,subscribe}
    mkdir -p /var/log/sball
}

# 输入配置信息
input_config() {
    # 获取服务器IP
    SERVER_IP_DEFAULT=$(get_server_ip)
    reading "\n $(text 7) " SERVER_IP
    SERVER_IP=${SERVER_IP:-"$SERVER_IP_DEFAULT"}
    
    # 输入起始端口
    reading "\n $(text 8) " START_PORT
    START_PORT=${START_PORT:-"$START_PORT_DEFAULT"}
    
    # 为每个协议生成独立的UUID（确保每次安装都是独立的）
    info "正在为每个协议生成独立的UUID..."
    declare -a UUID_ARRAY
    for i in {0..10}; do
        UUID_ARRAY[$i]=$(generate_uuid)
    done
    # 主UUID（用于向后兼容）
    UUID=${UUID_ARRAY[0]}
    info "生成的主UUID: $UUID"
    
    # 输入节点名称（每次生成新的随机后缀）
    NODE_NAME_DEFAULT="SBall-$(generate_random_string 6)"
    reading "\n $(text 10) " NODE_NAME
    NODE_NAME=${NODE_NAME:-"$NODE_NAME_DEFAULT"}
    info "节点名称: $NODE_NAME"
    
    # 生成端口数组
    for i in {0..10}; do
        PROTOCOL_PORTS[i]=$((START_PORT + i))
    done
    info "端口范围: ${START_PORT} - $((START_PORT + 10))"
    
    # 强制生成新的Reality密钥对（确保每次安装都是独立的）
    info "正在生成Reality密钥对..."
    REALITY_KEYPAIR=$(${WORK_DIR}/sing-box generate reality-keypair)
    REALITY_PRIVATE_KEY=$(echo "$REALITY_KEYPAIR" | grep 'PrivateKey:' | awk '{print $2}')
    REALITY_PUBLIC_KEY=$(echo "$REALITY_KEYPAIR" | grep 'PublicKey:' | awk '{print $2}')
    REALITY_SHORT_ID=$(generate_random_string 8)
    info "Reality公钥: $REALITY_PUBLIC_KEY"
    info "Reality短ID: $REALITY_SHORT_ID"
    
    # 强制生成新的随机密码（确保每次安装都是独立的）
    info "正在生成随机密码..."
    PASSWORD_ARRAY["hysteria2"]=$(generate_random_string 16)
    PASSWORD_ARRAY["tuic"]=$(generate_random_string 16)
    PASSWORD_ARRAY["shadowtls"]=$(generate_random_string 16)
     PASSWORD_ARRAY["shadowsocks"]=$(generate_random_string 16)
     PASSWORD_ARRAY["trojan"]=$(generate_random_string 16)
     PASSWORD_ARRAY["anytls"]=$(generate_random_string 16)
    
    # 向后兼容的密码变量
    HYSTERIA2_PASSWORD=${PASSWORD_ARRAY["hysteria2"]}
    TUIC_PASSWORD=${PASSWORD_ARRAY["tuic"]}
     SHADOWTLS_PASSWORD=${PASSWORD_ARRAY["shadowtls"]}
     SHADOWSOCKS_PASSWORD=${PASSWORD_ARRAY["shadowsocks"]}
     TROJAN_PASSWORD=${PASSWORD_ARRAY["trojan"]}
     ANYTLS_PASSWORD=${PASSWORD_ARRAY["anytls"]}
    
    WS_PATH="/$(generate_random_string 10)"
    info "Hysteria2密码: $HYSTERIA2_PASSWORD"
     info "TUIC密码: $TUIC_PASSWORD"
     info "ShadowTLS密码: $SHADOWTLS_PASSWORD"
     info "Shadowsocks密码: $SHADOWSOCKS_PASSWORD"
     info "Trojan密码: $TROJAN_PASSWORD"
     info "AnyTLS密码: $ANYTLS_PASSWORD"
     info "WebSocket路径: $WS_PATH"
    
    # Shadowsocks密码已在上面生成
    
    # 生成自签名TLS证书
    generate_tls_certificate
}

# 主安装函数
install_sball() {
    check_root
    check_arch
    check_system
    select_language
    
    info "\n=== $(text 1) ==="
    info "版本: $VERSION"
    info "Sing-box: $SING_BOX_VERSION"
    info "支持协议: ${#PROTOCOL_LIST[@]} 种\n"
    
    install_dependencies
    create_work_dir
    download_sing_box
    input_config
    
    # 生成配置文件
    generate_main_config
    generate_protocol_configs
    
    # 创建系统服务
    create_systemd_service
    
    # 启动服务
    systemctl enable sball
    systemctl start sball
    
    # 生成节点信息
    generate_node_links
    
    info "\n=== 安装完成 ==="
    info "节点信息已保存到: ${WORK_DIR}/subscribe/"
    info "管理命令: sball"
    info "查看节点: sball -n"
    info "查看状态: systemctl status sball"
}

# 生成主配置文件
generate_main_config() {
    cat > ${WORK_DIR}/config.json << EOF
{
  "log": {
    "level": "info",
    "output": "/var/log/sball/sball.log",
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
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[0]},
      "users": [
        {
          "uuid": "${UUID_ARRAY[0]}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${TLS_SERVER_DEFAULT}",
            "server_port": 443
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": ["${REALITY_SHORT_ID}"]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[1]},
      "users": [
        {
          "password": "${HYSTERIA2_PASSWORD}"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "key_path": "${WORK_DIR}/private.key",
        "certificate_path": "${WORK_DIR}/cert.crt"
      }
    },
    {
      "type": "shadowtls",
      "tag": "shadowtls-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[3]},
      "version": 3,
      "password": "${SHADOWTLS_PASSWORD}",
      "handshake": {
        "server": "${TLS_SERVER_DEFAULT}",
        "server_port": 443
      },
      "strict_mode": true,
      "detour": "shadowtls-ss-in"
    },
    {
      "type": "shadowsocks",
      "tag": "shadowtls-ss-in",
      "listen": "127.0.0.1",
      "listen_port": $((PROTOCOL_PORTS[3] + 1000)),
      "method": "2022-blake3-aes-128-gcm",
      "password": "${SHADOWTLS_PASSWORD}"
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[2]},
      "users": [
        {
          "uuid": "${UUID_ARRAY[2]}",
          "password": "${TUIC_PASSWORD}"
        }
      ],
      "congestion_control": "bbr",
      "udp_relay_mode": "native",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "key_path": "${WORK_DIR}/private.key",
        "certificate_path": "${WORK_DIR}/cert.crt"
      }
    },
    {
      "type": "shadowsocks",
      "tag": "shadowsocks-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[4]},
      "method": "2022-blake3-aes-128-gcm",
      "password": "${SHADOWSOCKS_PASSWORD}"
    },
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
        "server_name": "${TLS_SERVER_DEFAULT}",
        "key_path": "${WORK_DIR}/private.key",
        "certificate_path": "${WORK_DIR}/cert.crt"
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws-tls-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[6]},
      "users": [
        {
          "uuid": "${UUID_ARRAY[6]}"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "key_path": "${WORK_DIR}/private.key",
        "certificate_path": "${WORK_DIR}/cert.crt"
      }
    },
    {
      "type": "vless",
      "tag": "vless-ws-tls-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[7]},
      "users": [
        {
          "uuid": "${UUID_ARRAY[7]}"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vless"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "key_path": "${WORK_DIR}/private.key",
        "certificate_path": "${WORK_DIR}/cert.crt"
      }
    },
    {
      "type": "vless",
      "tag": "h2-reality-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[8]},
      "users": [
        {
          "uuid": "${UUID_ARRAY[8]}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "transport": {
        "type": "http"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${TLS_SERVER_DEFAULT}",
            "server_port": 443
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": ["${REALITY_SHORT_ID}"]
        }
      }
    },
    {
      "type": "vless",
      "tag": "grpc-reality-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[9]},
      "users": [
        {
          "uuid": "${UUID_ARRAY[9]}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "transport": {
        "type": "grpc",
        "service_name": "grpc"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${TLS_SERVER_DEFAULT}",
            "server_port": 443
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": ["${REALITY_SHORT_ID}"]
        }
      }
    },
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "::",
      "listen_port": ${PROTOCOL_PORTS[10]},
      "password": "${ANYTLS_PASSWORD}",
      "idle_session_check_interval": "30s",
      "idle_session_timeout": "300s",
      "min_idle_session": 10
    }
  ],
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
        "action": "sniff"
      },
      {
        "ip_cidr": [
          "10.0.0.0/8",
          "172.16.0.0/12",
          "192.168.0.0/16",
          "127.0.0.0/8"
        ],
        "outbound": "direct"
      },
      {
        "domain_suffix": [
          ".cn",
          ".com.cn",
          ".net.cn",
          ".org.cn"
        ],
        "outbound": "direct"
      },
      {
        "protocol": "dns",
        "outbound": "direct"
      }
    ]
  }
}
EOF
}

# 生成协议配置文件（已简化为主配置文件中的inbounds）
generate_protocol_configs() {
    info "协议配置已集成到主配置文件中..."
    # 所有协议配置现在直接在generate_main_config()中生成
    # 不再需要独立的协议配置文件
}



# 创建系统服务
create_systemd_service() {
    cat > /etc/systemd/system/sball.service << EOF
[Unit]
Description=SBall Sing-box Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=${WORK_DIR}/sing-box run -c ${WORK_DIR}/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
}

# 生成节点链接
generate_node_links() {
    info "$(text 11)"
    
    # 创建订阅目录
    mkdir -p ${WORK_DIR}/subscribe
    
    # 确保所有参数都已正确生成
    if [[ -z "$UUID" || -z "$SERVER_IP" || -z "$NODE_NAME" ]]; then
        error "关键参数未生成，请重新运行安装"
        return 1
    fi
    
    # 验证端口数组
    if [[ ${#PROTOCOL_PORTS[@]} -lt 11 ]]; then
        error "端口数组未正确生成，请重新运行安装"
        return 1
    fi
    
    # 生成节点信息文件
    cat > ${WORK_DIR}/subscribe/nodes.txt << EOF
# SBall 节点信息
# 生成时间: $(date)
# 节点名称: $NODE_NAME
# 服务器IP: $SERVER_IP
# UUID: $UUID
# 起始端口: $START_PORT
# Reality公钥: $REALITY_PUBLIC_KEY
# Reality短ID: $REALITY_SHORT_ID

=== VLESS-Reality 节点 ===
vless://${UUID_ARRAY[0]}@${SERVER_IP}:${PROTOCOL_PORTS[0]}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${TLS_SERVER_DEFAULT}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp&headerType=none#${NODE_NAME}-VLESS-Reality

=== Hysteria2 节点 ===
hysteria2://${HYSTERIA2_PASSWORD}@${SERVER_IP}:${PROTOCOL_PORTS[1]}/?sni=${TLS_SERVER_DEFAULT}&alpn=h3#${NODE_NAME}-Hysteria2

=== TUIC 节点 ===
tuic://${UUID_ARRAY[2]}:${TUIC_PASSWORD}@${SERVER_IP}:${PROTOCOL_PORTS[2]}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=${TLS_SERVER_DEFAULT}#${NODE_NAME}-TUIC

=== ShadowTLS 节点 ===
ss://$(echo -n "2022-blake3-aes-128-gcm:${SHADOWTLS_PASSWORD}" | base64 -w 0)@${SERVER_IP}:${PROTOCOL_PORTS[3]}#${NODE_NAME}-ShadowTLS

=== Shadowsocks 节点 ===
ss://$(echo -n "2022-blake3-aes-128-gcm:${SHADOWSOCKS_PASSWORD}" | base64 -w 0)@${SERVER_IP}:${PROTOCOL_PORTS[4]}#${NODE_NAME}-Shadowsocks

=== Trojan 节点 ===
trojan://${TROJAN_PASSWORD}@${SERVER_IP}:${PROTOCOL_PORTS[5]}?security=tls&sni=${TLS_SERVER_DEFAULT}&type=tcp&headerType=none#${NODE_NAME}-Trojan

=== VMess-WS 节点 ===
vmess://$(echo -n '{
  "v": "2",
  "ps": "'${NODE_NAME}'-VMess-WS",
  "add": "'${SERVER_IP}'",
  "port": "'${PROTOCOL_PORTS[6]}'",
  "id": "'${UUID_ARRAY[6]}'",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "'${TLS_SERVER_DEFAULT}'",
  "path": "'${WS_PATH}'",
  "tls": "",
  "sni": "",
  "alpn": ""
}' | base64 -w 0)

=== VLESS-WS-TLS 节点 ===
vless://${UUID_ARRAY[7]}@${SERVER_IP}:${PROTOCOL_PORTS[7]}?encryption=none&security=tls&sni=${TLS_SERVER_DEFAULT}&type=ws&host=${TLS_SERVER_DEFAULT}&path=${WS_PATH}#${NODE_NAME}-VLESS-WS-TLS

=== H2-Reality 节点 ===
vless://${UUID_ARRAY[8]}@${SERVER_IP}:${PROTOCOL_PORTS[8]}?encryption=none&security=reality&sni=${TLS_SERVER_DEFAULT}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=http&path=${WS_PATH}#${NODE_NAME}-H2-Reality

=== gRPC-Reality 节点 ===
vless://${UUID_ARRAY[9]}@${SERVER_IP}:${PROTOCOL_PORTS[9]}?encryption=none&security=reality&sni=${TLS_SERVER_DEFAULT}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=grpc&serviceName=grpc#${NODE_NAME}-gRPC-Reality

=== AnyTLS 节点 ===
trojan://${ANYTLS_PASSWORD}@${SERVER_IP}:${PROTOCOL_PORTS[10]}?security=tls&sni=${TLS_SERVER_DEFAULT}&type=tcp&headerType=none#${NODE_NAME}-AnyTLS

EOF

    # 保存生成的参数到配置文件
    cat > ${WORK_DIR}/subscribe/config_params.txt << EOF
# SBall 配置参数记录
# 生成时间: $(date)

[基本信息]
服务器IP: $SERVER_IP
节点名称: $NODE_NAME
UUID: $UUID
起始端口: $START_PORT

[UUID数组]
UUID_ARRAY_0: ${UUID_ARRAY[0]}
UUID_ARRAY_1: ${UUID_ARRAY[1]}
UUID_ARRAY_2: ${UUID_ARRAY[2]}
UUID_ARRAY_3: ${UUID_ARRAY[3]}
UUID_ARRAY_4: ${UUID_ARRAY[4]}
UUID_ARRAY_5: ${UUID_ARRAY[5]}
UUID_ARRAY_6: ${UUID_ARRAY[6]}
UUID_ARRAY_7: ${UUID_ARRAY[7]}
UUID_ARRAY_8: ${UUID_ARRAY[8]}
UUID_ARRAY_9: ${UUID_ARRAY[9]}
UUID_ARRAY_10: ${UUID_ARRAY[10]}

[端口分配]
VLESS-Reality: ${PROTOCOL_PORTS[0]}
Hysteria2: ${PROTOCOL_PORTS[1]}
TUIC: ${PROTOCOL_PORTS[2]}
ShadowTLS: ${PROTOCOL_PORTS[3]}
Shadowsocks: ${PROTOCOL_PORTS[4]}
Trojan: ${PROTOCOL_PORTS[5]}
VMess-WS: ${PROTOCOL_PORTS[6]}
VLESS-WS-TLS: ${PROTOCOL_PORTS[7]}
H2-Reality: ${PROTOCOL_PORTS[8]}
gRPC-Reality: ${PROTOCOL_PORTS[9]}
AnyTLS: ${PROTOCOL_PORTS[10]}

[Reality配置]
私钥: $REALITY_PRIVATE_KEY
公钥: $REALITY_PUBLIC_KEY
短ID: $REALITY_SHORT_ID

[密码配置]
ShadowTLS密码: $SHADOWTLS_PASSWORD
Hysteria2密码: $HYSTERIA2_PASSWORD
TUIC密码: $TUIC_PASSWORD
Shadowsocks密码: $SHADOWSOCKS_PASSWORD
Trojan密码: $TROJAN_PASSWORD
AnyTLS密码: $ANYTLS_PASSWORD
WebSocket路径: $WS_PATH

EOF

    info "配置参数已保存到: ${WORK_DIR}/subscribe/config_params.txt"
    
    # 生成Clash配置
    generate_clash_config
    
    # 生成sing-box客户端配置
    generate_singbox_client_config
}

# 生成Clash配置
generate_clash_config() {
    cat > ${WORK_DIR}/subscribe/clash.yaml << EOF
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - name: "${NODE_NAME}-VLESS-Reality"
    type: vless
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[0]}
    uuid: ${UUID}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: ${REALITY_PUBLIC_KEY}
      short-id: ${REALITY_SHORT_ID}
    client-fingerprint: chrome
    
  - name: "${NODE_NAME}-Hysteria2"
    type: hysteria2
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[1]}
    password: ${HYSTERIA2_PASSWORD}
    sni: ${TLS_SERVER_DEFAULT}
    
  - name: "${NODE_NAME}-TUIC"
    type: tuic
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[2]}
    uuid: ${UUID_ARRAY[2]}
    password: ${TUIC_PASSWORD}
    sni: ${TLS_SERVER_DEFAULT}
    
  - name: "${NODE_NAME}-ShadowTLS"
    type: ss
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[3]}
    cipher: 2022-blake3-aes-128-gcm
    password: ${SHADOWTLS_PASSWORD}
    plugin: shadow-tls
    plugin-opts:
      host: ${TLS_SERVER_DEFAULT}
      version: 3
    
  - name: "${NODE_NAME}-Shadowsocks"
    type: ss
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[4]}
    cipher: 2022-blake3-aes-128-gcm
    password: ${SHADOWSOCKS_PASSWORD}
    
  - name: "${NODE_NAME}-Trojan"
    type: trojan
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[5]}
    password: ${TROJAN_PASSWORD}
    sni: ${TLS_SERVER_DEFAULT}
    
  - name: "${NODE_NAME}-VMess-WS-TLS"
    type: vmess
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[6]}
    uuid: ${UUID_ARRAY[6]}
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    sni: ${TLS_SERVER_DEFAULT}
    ws-opts:
      path: ${WS_PATH}
      headers:
        Host: ${TLS_SERVER_DEFAULT}
    
  - name: "${NODE_NAME}-VLESS-WS-TLS"
    type: vless
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[7]}
    uuid: ${UUID_ARRAY[7]}
    network: ws
    tls: true
    sni: ${TLS_SERVER_DEFAULT}
    ws-opts:
      path: ${WS_PATH}
      headers:
        Host: ${TLS_SERVER_DEFAULT}
    
  - name: "${NODE_NAME}-H2-Reality"
    type: vless
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[8]}
    uuid: ${UUID_ARRAY[8]}
    network: h2
    tls: true
    reality-opts:
      public-key: ${REALITY_PUBLIC_KEY}
      short-id: ${REALITY_SHORT_ID}
    client-fingerprint: chrome
    
  - name: "${NODE_NAME}-gRPC-Reality"
    type: vless
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[9]}
    uuid: ${UUID_ARRAY[9]}
    network: grpc
    tls: true
    reality-opts:
      public-key: ${REALITY_PUBLIC_KEY}
      short-id: ${REALITY_SHORT_ID}
    grpc-opts:
      grpc-service-name: grpc
    client-fingerprint: chrome
    
  - name: "${NODE_NAME}-AnyTLS"
    type: trojan
    server: ${SERVER_IP}
    port: ${PROTOCOL_PORTS[10]}
    password: ${ANYTLS_PASSWORD}
    sni: ${TLS_SERVER_DEFAULT}
    # Note: Clash不直接支持AnyTLS，使用Trojan兼容模式

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - "${NODE_NAME}-VLESS-Reality"
      - "${NODE_NAME}-Hysteria2"
      - "${NODE_NAME}-TUIC"
      - "${NODE_NAME}-ShadowTLS"
      - "${NODE_NAME}-Shadowsocks"
      - "${NODE_NAME}-Trojan"
      - "${NODE_NAME}-VMess-WS-TLS"
      - "${NODE_NAME}-VLESS-WS-TLS"
      - "${NODE_NAME}-H2-Reality"
      - "${NODE_NAME}-gRPC-Reality"
      - "${NODE_NAME}-AnyTLS"

rules:
  - DOMAIN-SUFFIX,openai.com,🚀 节点选择
  - DOMAIN-SUFFIX,chatgpt.com,🚀 节点选择
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
EOF
}

# 生成sing-box客户端配置
generate_singbox_client_config() {
    cat > ${WORK_DIR}/subscribe/singbox-client.json << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query"
      },
      {
        "tag": "local",
        "address": "local"
      }
    ],
    "rules": [
      {
        "geosite": "cn",
        "server": "local"
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
      "tag": "vless-reality",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[0]},
      "uuid": "${UUID_ARRAY[0]}",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "${REALITY_PUBLIC_KEY}",
          "short_id": "${REALITY_SHORT_ID}"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[1]},
      "password": "${HYSTERIA2_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[2]},
      "uuid": "${UUID_ARRAY[2]}",
      "password": "${TUIC_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}"
      }
    },
    {
      "type": "shadowtls",
      "tag": "shadowtls",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[3]},
      "version": 3,
      "password": "${SHADOWTLS_PASSWORD}",
      "detour": "shadowtls-ss"
    },
    {
      "type": "shadowsocks",
      "tag": "shadowtls-ss",
      "server": "127.0.0.1",
      "server_port": $((PROTOCOL_PORTS[3] + 1000)),
      "method": "2022-blake3-aes-128-gcm",
      "password": "${SHADOWTLS_PASSWORD}"
    },
    {
      "type": "shadowsocks",
      "tag": "shadowsocks",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[4]},
      "method": "2022-blake3-aes-128-gcm",
      "password": "${SHADOWSOCKS_PASSWORD}"
    },
    {
      "type": "trojan",
      "tag": "trojan",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[5]},
      "password": "${TROJAN_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}"
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws-tls",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[6]},
      "uuid": "${UUID_ARRAY[6]}",
      "transport": {
        "type": "ws",
        "path": "${WS_PATH}"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}"
      }
    },
    {
      "type": "vless",
      "tag": "vless-ws-tls",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[7]},
      "uuid": "${UUID_ARRAY[7]}",
      "transport": {
        "type": "ws",
        "path": "${WS_PATH}"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}"
      }
    },
    {
      "type": "vless",
      "tag": "h2-reality",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[8]},
      "uuid": "${UUID_ARRAY[8]}",
      "flow": "xtls-rprx-vision",
      "transport": {
        "type": "http"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "${REALITY_PUBLIC_KEY}",
          "short_id": "${REALITY_SHORT_ID}"
        }
      }
    },
    {
      "type": "vless",
      "tag": "grpc-reality",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[9]},
      "uuid": "${UUID_ARRAY[9]}",
      "flow": "xtls-rprx-vision",
      "transport": {
        "type": "grpc",
        "service_name": "grpc"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SERVER_DEFAULT}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "${REALITY_PUBLIC_KEY}",
          "short_id": "${REALITY_SHORT_ID}"
        }
      }
    },
    {
      "type": "anytls",
      "tag": "anytls",
      "server": "${SERVER_IP}",
      "server_port": ${PROTOCOL_PORTS[10]},
      "password": "${ANYTLS_PASSWORD}",
      "idle_session_check_interval": "30s",
      "idle_session_timeout": "300s",
      "min_idle_session": 10
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
        "geosite": "cn",
        "outbound": "direct"
      },
      {
        "geoip": "cn",
        "outbound": "direct"
      }
    ],
    "final": "vless-reality"
  }
}
EOF
}

# 显示主菜单
show_menu() {
    select_language
    
    echo
    info "=== SBall Sing-box 管理脚本 ==="
    info "版本: $VERSION"
    echo
    hint "1. $(text 12)"
    hint "2. $(text 13)"
    hint "3. $(text 14)"
    hint "4. $(text 15)"
    hint "5. $(text 16)"
    hint "0. $(text 17)"
    echo
    reading "$(text 11) " CHOICE
    
    case "$CHOICE" in
        1 )
            install_sball
            ;;
        2 )
            show_node_info
            ;;
        3 )
            change_ports
            ;;
        4 )
            update_sing_box
            ;;
        5 )
            uninstall_sball
            ;;
        0 )
            exit 0
            ;;
        * )
            warning "$(text 18)"
            show_menu
    esac
}

# 显示节点信息
show_node_info() {
    if [ -f ${WORK_DIR}/subscribe/nodes.txt ]; then
        cat ${WORK_DIR}/subscribe/nodes.txt
    else
        warning "节点信息文件不存在"
    fi
}

# 更换端口
change_ports() {
    info "更换端口功能"
    
    # 停止服务
    systemctl stop sball
    
    # 重新输入配置
    input_config
    
    # 重新生成配置
    generate_main_config
    generate_protocol_configs
    
    # 重新生成节点信息
    generate_node_links
    
    # 重启服务
    systemctl start sball
    
    info "端口更换完成"
}

# 更新Sing-box
update_sing_box() {
    info "更新Sing-box"
    
    # 停止服务
    systemctl stop sball
    
    # 备份当前配置
    cp ${WORK_DIR}/config.json ${WORK_DIR}/config.json.bak
    
    # 下载最新版本
    download_sing_box
    
    # 重启服务
    systemctl start sball
    
    info "Sing-box更新完成"
}

# 卸载
uninstall_sball() {
    warning "确认卸载SBall？(y/N)"
    read -r confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # 停止并禁用服务
        systemctl stop sball
        systemctl disable sball
        
        # 删除服务文件
        rm -f /etc/systemd/system/sball.service
        systemctl daemon-reload
        
        # 删除工作目录
        rm -rf ${WORK_DIR}
        
        # 删除日志目录
        rm -rf /var/log/sball
        
        # 删除快捷命令
        rm -f /usr/local/bin/sball
        
        info "SBall卸载完成"
    else
        info "取消卸载"
    fi
}

# 创建快捷命令
create_shortcut() {
    cat > /usr/local/bin/sball << 'EOF'
#!/bin/bash
bash /etc/sball/sball.sh "$@"
EOF
    chmod +x /usr/local/bin/sball
}

# 主函数
main() {
    case "$1" in
        -n|--node )
            show_node_info
            ;;
        -p|--port )
            change_ports
            ;;
        -v|--version )
            update_sing_box
            ;;
        -u|--uninstall )
            uninstall_sball
            ;;
        * )
            show_menu
            ;;
    esac
}

# 如果直接运行脚本，显示菜单
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
