#!/bin/bash

# SBall服务修复脚本
# 用于修复服务启动失败的问题

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

# 配置变量
SERVICE_NAME="sball"
CONFIG_FILE="/etc/sball/config.json"
WORK_DIR="/etc/sball"
LOG_FILE="/var/log/sball.log"
SING_BOX_BIN="/usr/local/bin/sing-box"

echo -e "${CYAN}=== SBall服务修复工具 ===${NC}"
echo -e "${YELLOW}此工具将尝试修复服务启动失败的问题${NC}"
echo

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}错误: 请使用root权限运行此脚本${NC}"
    echo "使用命令: sudo bash fix-service.sh"
    exit 1
fi

# 停止现有服务
echo -e "${BLUE}1. 停止现有服务...${NC}"
systemctl stop "$SERVICE_NAME" 2>/dev/null
echo -e "${GREEN}✅ 服务已停止${NC}"

# 备份现有配置
echo -e "${BLUE}2. 备份现有配置...${NC}"
if [[ -f "$CONFIG_FILE" ]]; then
    cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${GREEN}✅ 配置已备份${NC}"
else
    echo -e "${YELLOW}⚠️  配置文件不存在，跳过备份${NC}"
fi

# 检查sing-box版本
echo -e "${BLUE}3. 检查sing-box版本...${NC}"
if [[ -f "$SING_BOX_BIN" ]]; then
    version=$("$SING_BOX_BIN" version 2>/dev/null | head -1)
    echo -e "${GREEN}✅ Sing-box版本: $version${NC}"
else
    echo -e "${RED}❌ Sing-box未安装或路径错误${NC}"
    echo -e "${YELLOW}请先运行sball.sh重新安装${NC}"
    exit 1
fi

# 重新运行sball.sh的配置生成部分
echo -e "${BLUE}4. 重新生成配置...${NC}"
echo -e "${YELLOW}请重新运行sball.sh并选择安装代理服务${NC}"
echo -e "${YELLOW}或者手动检查以下问题:${NC}"
echo
echo -e "${CYAN}常见问题检查清单:${NC}"
echo -e "${WHITE}□ 检查端口是否被占用${NC}"
echo -e "${WHITE}□ 检查证书文件是否存在${NC}"
echo -e "${WHITE}□ 检查配置文件JSON语法${NC}"
echo -e "${WHITE}□ 检查AnyTLS协议配置格式${NC}"
echo

# 提供诊断命令
echo -e "${BLUE}5. 诊断命令:${NC}"
echo -e "${WHITE}检查服务状态:${NC} systemctl status sball"
echo -e "${WHITE}查看服务日志:${NC} journalctl -u sball -f"
echo -e "${WHITE}检查配置语法:${NC} $SING_BOX_BIN check -c $CONFIG_FILE"
echo -e "${WHITE}运行诊断工具:${NC} bash test-config.sh"
echo

# 快速重启尝试
read -p "是否尝试重新启动服务? [y/N]: " restart_confirm
if [[ $restart_confirm =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}6. 尝试启动服务...${NC}"
    systemctl start "$SERVICE_NAME"
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}🎉 服务启动成功！${NC}"
        systemctl status "$SERVICE_NAME" --no-pager
    else
        echo -e "${RED}❌ 服务启动失败${NC}"
        echo -e "${YELLOW}请查看详细错误信息:${NC}"
        journalctl -u "$SERVICE_NAME" --no-pager -n 20
        echo
        echo -e "${CYAN}建议操作:${NC}"
        echo -e "${WHITE}1. 运行诊断工具: bash test-config.sh${NC}"
        echo -e "${WHITE}2. 重新安装: bash sball.sh${NC}"
        echo -e "${WHITE}3. 检查系统日志: journalctl -u sball -f${NC}"
    fi
else
    echo -e "${YELLOW}跳过服务启动${NC}"
fi

echo
echo -e "${CYAN}修复工具运行完成${NC}"
echo -e "${YELLOW}如果问题仍然存在，请运行: bash sball.sh 重新安装${NC}"
