#!/usr/bin/env bash
# sball.sh - Sing-box 一键安装与管理脚本 (Ubuntu amd64)
# MIT License
# 作者：dayao + ChatGPT（按《开发计划书》实现）
# 版本：2025-08-24

set -euo pipefail

# ========= 可调参数（按需修改） =========
SB_VERSION="1.12.2"
SB_TGZ_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-amd64.tar.gz"
INSTALL_DIR="/usr/local/bin"
SB_BIN="${INSTALL_DIR}/sing-box"
CONF_DIR="/etc/sing-box"
CERT_DIR="${CONF_DIR}/certs"
DATA_DIR="/var/lib/sing-box"
LOG_DIR="/var/log/sing-box"
UNIT_FILE="/etc/systemd/system/sing-box.service"
MENU_TITLE="sball 科学上网 - 一键安装与管理"
LANGUAGE="zh-CN"
DEFAULT_SNI_LIST=("www.yahoo.com" "www.bing.com" "www.cloudflare.com" "www.microsoft.com" "www.amazon.com" "www.wikipedia.org")
# =====================================

# 全局变量（安装过程中生成）
UUID=""
PASSWORD=""
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
REALITY_SHORT_ID=""
PUB_IP=""
DOMAIN=""
USE_DOMAIN_TLS="no"

# ----- 工具函数 -----
red(){ echo -e "\e[31m$*\e[0m"; }
green(){ echo -e "\e[32m$*\e[0m"; }
yellow(){ echo -e "\e[33m$*\e[0m"; }
blue(){ echo -e "\e[34m$*\e[0m"; }

need_root(){
  if [[ $EUID -ne 0 ]]; then
    red "请用 root 运行：sudo bash sball.sh"
    exit 1
  fi
}

need_ubuntu_amd64(){
  if ! command -v dpkg >/dev/null 2>&1; then
    red "当前系统非 Debian/Ubuntu 系。建议 Ubuntu 20.04/22.04/24.04 amd64。"
    exit 1
  fi
  arch="$(dpkg --print-architecture)"
  if [[ "$arch" != "amd64" ]]; then
    red "当前架构为 ${arch}，本脚本仅支持 amd64。"
    exit 1
  fi
}

rand_port(){
  # 避开常见端口，选 20000-59999
  shuf -i 20000-59999 -n 1
}

ensure_deps(){
  apt-get update -y
  apt-get install -y --no-install-recommends \
    curl wget tar xz-utils jq qrencode uuid-runtime openssl ca-certificates netcat lsof
}

ensure_dirs(){
  mkdir -p "$CONF_DIR" "$CERT_DIR" "$DATA_DIR" "$LOG_DIR"
  touch "${LOG_DIR}/access.log" "${LOG_DIR}/error.log"
}

get_pub_ip(){
  # 多源兜底
  PUB_IP="$(curl -fsS --max-time 5 https://api.ipify.org || true)"
  [[ -z "${PUB_IP}" ]] && PUB_IP="$(curl -fsS --max-time 5 https://ifconfig.me || true)"
  [[ -z "${PUB_IP}" ]] && PUB_IP="$(curl -fsS --max-time 5 https://ipv4.icanhazip.com || true)"
  if [[ -z "${PUB_IP}" ]]; then
    red "无法获取公网 IP，请检查出网。稍后节点展示将回退为 服务器IP=本机IP。"
    PUB_IP="$(hostname -I | awk '{print $1}')"
  fi
}

install_singbox(){
  if [[ -x "$SB_BIN" ]]; then
    green "检测到 sing-box 已存在：$("$SB_BIN" version || true)"
  else
    yellow "下载并安装 sing-box v${SB_VERSION} ..."
    tmpdir="$(mktemp -d)"
    cd "$tmpdir"
    curl -fL "$SB_TGZ_URL" -o sb.tgz
    tar -xzf sb.tgz
    install -m 0755 "sing-box-${SB_VERSION}-linux-amd64/sing-box" "$SB_BIN"
    cd /
    rm -rf "$tmpdir"
    green "sing-box 安装完成：$("$SB_BIN" version)"
  fi
}

generate_base_secrets(){
  UUID="$(uuidgen)"
  PASSWORD="$(openssl rand -hex 16)"
  REALITY_SHORT_ID="$(openssl rand -hex 4)"    # 8 hex chars
  # Reality 密钥对
  kjson="$("$SB_BIN" generate reality-keypair)"
  REALITY_PRIVATE_KEY="$(echo "$kjson" | jq -r '.private_key')"
  REALITY_PUBLIC_KEY="$(echo "$kjson" | jq -r '.public_key')"
}

ask_domain_tls(){
  echo
  yellow "是否使用你自己的域名为 WS/TLS 与 Trojan 提供证书？(y/N)"
  read -r ans
  if [[ "${ans,,}" == "y" ]]; then
    read -rp "请输入已解析到本机IP(${PUB_IP})的域名：" DOMAIN
    if [[ -z "$DOMAIN" ]]; then
      red "未输入域名，回退为自签证书（客户端需允许 insecure）。"
      USE_DOMAIN_TLS="no"
    else
      USE_DOMAIN_TLS="yes"
    fi
  else
    USE_DOMAIN_TLS="no"
  fi
}

issue_certificates(){
  if [[ "${USE_DOMAIN_TLS}" == "yes" ]]; then
    yellow "为 ${DOMAIN} 申请自签证书（简化；如需 ACME 可自行替换）..."
    # 自签（3650 天），生产请改为 ACME/真实证书；客户端需配合或信任
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout "${CERT_DIR}/${DOMAIN}.key" \
      -out "${CERT_DIR}/${DOMAIN}.crt" \
      -subj "/CN=${DOMAIN}"
    chmod 600 "${CERT_DIR}/${DOMAIN}.key"
  else
    yellow "未使用域名：将生成自签证书供 Trojan/VLESS-WS-TLS 测试使用（客户端需允许 insecure）。"
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout "${CERT_DIR}/self.key" \
      -out "${CERT_DIR}/self.crt" \
      -subj "/CN=localhost"
    chmod 600 "${CERT_DIR}/self.key"
  fi
}

write_systemd_unit(){
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
User=root
WorkingDirectory=${CONF_DIR}
ExecStart=${SB_BIN} run -c ${CONF_DIR}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=100000
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

# ---------- 生成多协议配置 ----------
# 端口规划（随机）：
PORT_VLESS_REALITY="$(rand_port)"
PORT_HYSTERIA2="$(rand_port)"
PORT_TUIC="$(rand_port)"
PORT_SHADOWTLS="$(rand_port)"
PORT_SS2022="$(rand_port)"
PORT_TROJAN="$(rand_port)"
PORT_VMESS_WS="$(rand_port)"
PORT_VLESS_WS="$(rand_port)"
PORT_GRPC_REALITY="$(rand_port)"
# 预留（默认不启用）
PORT_ANYTLS="$(rand_port)"
PORT_H2_REALITY="$(rand_port)"

WS_PATH_VMESS="/$(uuidgen | tr 'A-Z' 'a-z')-vm"
WS_PATH_VLESS="/$(uuidgen | tr 'A-Z' 'a-z')-vl"

make_config(){
  local sni="${DEFAULT_SNI_LIST[$((RANDOM % ${#DEFAULT_SNI_LIST[@]}))]}"

  # 证书路径选择
  local crt key
  if [[ "${USE_DOMAIN_TLS}" == "yes" ]]; then
    crt="${CERT_DIR}/${DOMAIN}.crt"
    key="${CERT_DIR}/${DOMAIN}.key"
  else
    crt="${CERT_DIR}/self.crt"
    key="${CERT_DIR}/self.key"
  fi

  # 生成主配置（inbounds 汇总；outbounds 直连+阻断；日志）
  cat > "${CONF_DIR}/config.json" <<JSON
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": ${PORT_VLESS_REALITY},
      "users": [{ "uuid": "${UUID}", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "${sni}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${sni}", "server_port": 443 },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": "${REALITY_SHORT_ID}"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": ${PORT_HYSTERIA2},
      "users": [{ "password": "${PASSWORD}" }],
      "tls": {
        "enabled": true,
        "insecure": true,
        "server_name": "h3.${sni}"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": ${PORT_TUIC},
      "users": [{ "uuid": "${UUID}", "password": "${PASSWORD}" }],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "insecure": true,
        "server_name": "tuic.${sni}"
      }
    },
    {
      "type": "shadowtls",
      "tag": "shadowtls-in",
      "listen": "::",
      "listen_port": ${PORT_SHADOWTLS},
      "version": 3,
      "users": [{ "password": "${PASSWORD}" }],
      "handshake": { "server": "${sni}", "server_port": 443 }
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022-in",
      "listen": "::",
      "listen_port": ${PORT_SS2022},
      "method": "2022-blake3-aes-128-gcm",
      "password": "${PASSWORD}"
    },
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": ${PORT_TROJAN},
      "users": [{ "password": "${PASSWORD}" }],
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN:-localhost}",
        "certificate_path": "${crt}",
        "key_path": "${key}",
        "insecure": ${USE_DOMAIN_TLS=="yes" && echo false || echo true}
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws-in",
      "listen": "::",
      "listen_port": ${PORT_VMESS_WS},
      "users": [{ "uuid": "${UUID}" }],
      "transport": {
        "type": "ws",
        "path": "${WS_PATH_VMESS}"
      }
    },
    {
      "type": "vless",
      "tag": "vless-ws-in",
      "listen": "::",
      "listen_port": ${PORT_VLESS_WS},
      "users": [{ "uuid": "${UUID}" }],
      "transport": {
        "type": "ws",
        "path": "${WS_PATH_VLESS}"
      },
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN:-localhost}",
        "certificate_path": "${crt}",
        "key_path": "${key}",
        "insecure": ${USE_DOMAIN_TLS=="yes" && echo false || echo true}
      }
    },
    {
      "type": "vless",
      "tag": "grpc-reality-in",
      "listen": "::",
      "listen_port": ${PORT_GRPC_REALITY},
      "users": [{ "uuid": "${UUID}" }],
      "transport": {
        "type": "grpc",
        "service_name": "grpc-reality"
      },
      "tls": {
        "enabled": true,
        "server_name": "${sni}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${sni}", "server_port": 443 },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": "${REALITY_SHORT_ID}"
        }
      }
    }
    /* 预留：AnyTLS / H2-Reality，根据后续需要启用 */
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ]
}
JSON
}

# ---------- 节点分享链接 ----------
print_nodes(){
  local host="${PUB_IP}"
  if [[ "${USE_DOMAIN_TLS}" == "yes" ]]; then
    host="${DOMAIN}"
  fi

  echo
  green "=========== 节点信息（请妥善保存） ==========="
  echo

  # VLESS Reality (Vision)
  local vless_real="vless://${UUID}@${PUB_IP}:${PORT_VLESS_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DEFAULT_SNI_LIST[0]}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#VLESS-Reality-${PUB_IP}"
  echo "$vless_real"
  echo

  # Hysteria2
  local hy2="hysteria2://${PASSWORD}@${PUB_IP}:${PORT_HYSTERIA2}?sni=${DEFAULT_SNI_LIST[1]}&alpn=h3&insecure=1#Hysteria2-${PUB_IP}"
  echo "$hy2"
  echo

  # TUIC v5（部分客户端以 tuic:// 方案；v2rayN 走 sing-box json 导入更稳）
  local tuic="tuic://${UUID}:${PASSWORD}@${PUB_IP}:${PORT_TUIC}?congestion_control=bbr&sni=tuic.${DEFAULT_SNI_LIST[0]}&allow_insecure=1#TUIC-${PUB_IP}"
  echo "$tuic"
  echo

  # ShadowTLS v3（通常配合下游再转发；此处展示直连）
  local shadowtls="shadowtls://${PASSWORD}@${PUB_IP}:${PORT_SHADOWTLS}?sni=${DEFAULT_SNI_LIST[0]}#ShadowTLS3-${PUB_IP}"
  echo "$shadowtls"
  echo

  # Shadowsocks 2022
  local method="2022-blake3-aes-128-gcm"
  local ss_base64="$(echo -n "${method}:${PASSWORD}" | base64 -w0)"
  local ss="ss://${ss_base64}@${PUB_IP}:${PORT_SS2022}#SS2022-${PUB_IP}"
  echo "$ss"
  echo

  # Trojan-TLS
  local trojan="trojan://${PASSWORD}@${host}:${PORT_TROJAN}?security=tls&sni=${DOMAIN:-localhost}&alpn=h2%2Chttp%2F1.1&fp=chrome#Trojan-TLS-${host}"
  echo "$trojan"
  echo

  # VMess-WS（明文 WS，用于反代或内网穿透；公网建议加 CDN/NGINX）
  local vm_json=$(cat <<EOV
{
  "v": "2",
  "ps": "VMess-WS-${PUB_IP}",
  "add": "${PUB_IP}",
  "port": "${PORT_VMESS_WS}",
  "id": "${UUID}",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "${WS_PATH_VMESS}",
  "tls": "",
  "sni": "",
  "alpn": "",
  "fp": ""
}
EOV
)
  local vmess_link="vmess://$(echo -n "$vm_json" | tr -d '\n' | base64 -w0)"
  echo "$vmess_link"
  echo

  # VLESS-WS(+TLS 可选)
  local vless_ws="vless://${UUID}@${host}:${PORT_VLESS_WS}?encryption=none&security=tls&type=ws&path=${WS_PATH_VLESS}&sni=${DOMAIN:-localhost}&fp=chrome&alpn=h2%2Chttp%2F1.1#VLESS-WS-${host}"
  echo "$vless_ws"
  echo

  # gRPC-Reality（部分客户端支持度较新）
  local grpc_reality="vless://${UUID}@${PUB_IP}:${PORT_GRPC_REALITY}?encryption=none&security=reality&sni=${DEFAULT_SNI_LIST[0]}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=grpc&serviceName=grpc-reality#gRPC-Reality-${PUB_IP}"
  echo "$grpc_reality"
  echo

  yellow "提示：若使用自签证书，客户端需开启允许不安全证书（insecure/skip-cert-verify）。"
  echo
}

# ---------- 管理动作 ----------
start_sb(){ systemctl enable --now sing-box && green "sing-box 已启动"; }
stop_sb(){ systemctl stop sing-box && green "sing-box 已停止"; }
status_sb(){ systemctl status sing-box --no-pager; }
log_sb(){ journalctl -u sing-box -n 100 --no-pager; }

# ---------- 安装流程 ----------
do_install(){
  need_root
  need_ubuntu_amd64
  ensure_deps
  ensure_dirs
  install_singbox
  get_pub_ip
  generate_base_secrets
  ask_domain_tls
  issue_certificates
  make_config
  write_systemd_unit
  start_sb
  green "安装完成！"
  print_nodes
}

do_update(){
  need_root
  install_singbox
  systemctl restart sing-box || true
  green "已更新并重启 sing-box：$("$SB_BIN" version)"
}

do_uninstall(){
  need_root
  yellow "将卸载 sing-box 服务与配置（保留二进制），是否继续？(y/N)"
  read -r c
  if [[ "${c,,}" != "y" ]]; then
    echo "已取消"; return
  fi
  systemctl disable --now sing-box || true
  rm -f "$UNIT_FILE"
  systemctl daemon-reload
  rm -rf "$CONF_DIR" "$LOG_DIR" "$DATA_DIR"
  green "已卸载服务与配置。"
  yellow "如需删除二进制，请手动执行：rm -f ${SB_BIN}"
  yellow "如需删除根目录的脚本文件，请手动执行：rm -f ./sball.sh"
}

print_menu(){
  clear
  blue "================ ${MENU_TITLE} ================"
  echo "1) 安装"
  echo "2) 更新 sing-box"
  echo "3) 卸载（保留二进制，配置删除）"
  echo "4) 查看节点信息"
  echo "5) 启动 sing-box"
  echo "6) 停止 sing-box"
  echo "7) 查看服务状态"
  echo "8) 查看服务日志"
  echo "9) 退出"
  echo "==============================================="
  read -rp "请选择操作 [1-9]: " op
  case "$op" in
    1) do_install ;;
    2) do_update ;;
    3) do_uninstall ;;
    4) get_pub_ip; # 尝试读取现有配置的关键信息
       if [[ -f "${CONF_DIR}/config.json" ]]; then
         # 从配置中抽取 Reality 公钥、短ID、端口等
         UUID="$(jq -r '.inbounds[] | select(.tag=="vless-reality-in") | .users[0].uuid' ${CONF_DIR}/config.json)"
         REALITY_PUBLIC_KEY="$(jq -r '.inbounds[] | select(.tag=="vless-reality-in") | .tls.reality.private_key' ${CONF_DIR}/config.json 2>/dev/null | xargs -I{} ${SB_BIN} generate reality-keypair --private-key {} 2>/dev/null | jq -r '.public_key' || echo "")"
         REALITY_SHORT_ID="$(jq -r '.inbounds[] | select(.tag=="vless-reality-in") | .tls.reality.short_id' ${CONF_DIR}/config.json)"
         PASSWORD="$(jq -r '.inbounds[] | select(.tag=="hysteria2-in") | .users[0].password' ${CONF_DIR}/config.json)"
         PORT_VLESS_REALITY="$(jq -r '.inbounds[] | select(.tag=="vless-reality-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_HYSTERIA2="$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_TUIC="$(jq -r '.inbounds[] | select(.tag=="tuic-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_SHADOWTLS="$(jq -r '.inbounds[] | select(.tag=="shadowtls-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_SS2022="$(jq -r '.inbounds[] | select(.tag=="ss2022-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_TROJAN="$(jq -r '.inbounds[] | select(.tag=="trojan-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_VMESS_WS="$(jq -r '.inbounds[] | select(.tag=="vmess-ws-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_VLESS_WS="$(jq -r '.inbounds[] | select(.tag=="vless-ws-in") | .listen_port' ${CONF_DIR}/config.json)"
         PORT_GRPC_REALITY="$(jq -r '.inbounds[] | select(.tag=="grpc-reality-in") | .listen_port' ${CONF_DIR}/config.json)"

         # 判断是否存在域名证书（简单判定）
         if [[ -f "${CERT_DIR}/self.crt" ]]; then
           USE_DOMAIN_TLS="no"
         else
           USE_DOMAIN_TLS="yes"
           DOMAIN="$(ls ${CERT_DIR}/*.crt 2>/dev/null | sed 's#.*/##' | sed 's#\.crt##' | head -n1)"
         fi
         print_nodes
       else
         red "未检测到 ${CONF_DIR}/config.json"
       fi
       ;;
    5) start_sb ;;
    6) stop_sb ;;
    7) status_sb ;;
    8) log_sb ;;
    9) exit 0 ;;
    *) echo "无效选择";;
  esac
  read -rp "按回车返回菜单..." _
  print_menu
}

# ---------- 入口 ----------
if [[ "${1:-}" == "install" ]]; then
  do_install
elif [[ "${1:-}" == "update" ]]; then
  do_update
elif [[ "${1:-}" == "uninstall" ]]; then
  do_uninstall
else
  print_menu
fi
