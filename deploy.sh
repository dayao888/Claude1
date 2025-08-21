#!/bin/bash

# SBall 一键部署脚本
# 使用方法: curl -fsSL https://raw.githubusercontent.com/dayao888/Claude1/main/deploy.sh | bash
# 自动修复Windows换行符问题，确保脚本在Linux系统正常运行

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查系统
check_system() {
    log_info "检查系统环境..."
    
    # 检查是否为root用户
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        log_info "使用命令: sudo bash deploy.sh"
        exit 1
    fi
    
    # 检查系统类型
    if [[ ! -f /etc/os-release ]]; then
        log_error "不支持的操作系统"
        exit 1
    fi
    
    source /etc/os-release
    log_info "检测到系统: $PRETTY_NAME"
    
    # 检查系统架构
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64)
            log_info "系统架构: x86_64 (推荐)"
            ;;
        aarch64|arm64)
            log_info "系统架构: ARM64 (支持)"
            ;;
        *)
            log_warn "系统架构: $arch (未测试，可能不稳定)"
            ;;
    esac
}

# 下载脚本
download_script() {
    log_info "下载SBall脚本..."
    
    # 创建临时目录
    local temp_dir="/tmp/sball-install"
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    # 下载主脚本
    if command -v curl &> /dev/null; then
        curl -fsSL -o sball.sh "https://raw.githubusercontent.com/dayao888/Claude1/main/sball.sh"
    elif command -v wget &> /dev/null; then
        wget -O sball.sh "https://raw.githubusercontent.com/dayao888/Claude1/main/sball.sh"
    else
        log_error "请安装 curl 或 wget"
        exit 1
    fi
    
    # 检查下载是否成功
    if [[ ! -f "sball.sh" ]]; then
        log_error "下载脚本失败"
        exit 1
    fi
    
    # 修复Windows换行符问题
    log_info "修复换行符格式..."
    if command -v dos2unix >/dev/null 2>&1; then
        dos2unix "sball.sh" 2>/dev/null
    elif command -v sed >/dev/null 2>&1; then
        sed -i 's/\r$//' "sball.sh" 2>/dev/null
    else
        # 使用tr命令删除回车符
        tr -d '\r' < "sball.sh" > "sball.sh.tmp" && mv "sball.sh.tmp" "sball.sh"
    fi
    
    # 添加执行权限
    chmod +x sball.sh
    
    log_info "脚本下载完成"
}

# 安装脚本
install_script() {
    log_info "安装SBall脚本..."
    
    # 复制到系统目录
    cp sball.sh /usr/local/bin/sball
    chmod +x /usr/local/bin/sball
    
    # 创建符号链接
    ln -sf /usr/local/bin/sball /usr/bin/sball
    
    log_info "脚本安装完成"
    log_info "现在可以使用 'sball' 命令启动管理面板"
}

# 显示使用说明
show_usage() {
    echo
    log_info "=== SBall 安装完成 ==="
    echo
    echo -e "${BLUE}快速开始:${NC}"
    echo "  sball                    # 启动管理面板"
    echo
    echo -e "${BLUE}常用命令:${NC}"
    echo "  sball install            # 安装代理服务"
    echo "  sball status             # 查看服务状态"
    echo "  sball info               # 显示节点信息"
    echo "  sball restart            # 重启服务"
    echo "  sball uninstall          # 卸载服务"
    echo
    echo -e "${BLUE}技术支持:${NC}"
    echo "  GitHub: https://github.com/dayao888/Claude1"
echo "  文档: https://github.com/dayao888/Claude1/wiki"
    echo
    echo -e "${YELLOW}注意事项:${NC}"
    echo "  1. 请确保服务器防火墙已正确配置"
    echo "  2. 建议定期备份配置文件"
    echo "  3. 遇到问题请查看日志: journalctl -u sing-box"
    echo
}

# 主函数
main() {
    echo
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}         SBall 一键部署脚本           ${NC}"
    echo -e "${BLUE}    多协议科学上网代理工具安装器        ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
    
    check_system
    download_script
    install_script
    show_usage
    
    # 询问是否立即运行
    echo
    read -p "是否立即启动SBall管理面板? [y/N]: " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo
        log_info "启动SBall管理面板..."
        exec sball
    else
        echo
        log_info "稍后可使用 'sball' 命令启动管理面板"
    fi
}

# 错误处理
trap 'log_error "安装过程中发生错误，请检查网络连接和系统权限"' ERR

# 运行主函数
main "$@"
