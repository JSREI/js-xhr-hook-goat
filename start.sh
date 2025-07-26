#!/bin/bash

# XHR Hook Goat 前端启动脚本
# 功能：自动杀死之前的实例，保持单个实例启动

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目配置
PROJECT_NAME="js-xhr-hook-goat"
SERVER_FILE="server.js"
PORT=48159
PID_FILE=".server.pid"

# 打印带颜色的消息
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}"
}

# 检查Node.js是否安装
check_nodejs() {
    if ! command -v node &> /dev/null; then
        print_message $RED "错误: Node.js 未安装，请先安装 Node.js"
        exit 1
    fi
    
    local node_version=$(node --version)
    print_message $BLUE "Node.js 版本: $node_version"
}

# 检查npm依赖
check_dependencies() {
    if [ ! -d "node_modules" ]; then
        print_message $YELLOW "检测到缺少依赖，正在安装..."
        npm install
        if [ $? -eq 0 ]; then
            print_message $GREEN "依赖安装完成"
        else
            print_message $RED "依赖安装失败"
            exit 1
        fi
    fi
}

# 查找并杀死现有的服务器进程
kill_existing_processes() {
    print_message $YELLOW "检查现有的服务器进程..."
    
    # 方法1: 通过PID文件杀死进程
    if [ -f "$PID_FILE" ]; then
        local old_pid=$(cat "$PID_FILE")
        if ps -p $old_pid > /dev/null 2>&1; then
            print_message $YELLOW "发现PID文件中的进程 $old_pid，正在终止..."
            kill $old_pid 2>/dev/null || true
            sleep 2
            
            # 如果进程仍然存在，强制杀死
            if ps -p $old_pid > /dev/null 2>&1; then
                print_message $YELLOW "强制终止进程 $old_pid"
                kill -9 $old_pid 2>/dev/null || true
            fi
        fi
        rm -f "$PID_FILE"
    fi
    
    # 方法2: 通过端口杀死进程
    local port_pid=$(lsof -ti:$PORT 2>/dev/null || true)
    if [ ! -z "$port_pid" ]; then
        print_message $YELLOW "发现占用端口 $PORT 的进程 $port_pid，正在终止..."
        kill $port_pid 2>/dev/null || true
        sleep 2
        
        # 如果进程仍然存在，强制杀死
        port_pid=$(lsof -ti:$PORT 2>/dev/null || true)
        if [ ! -z "$port_pid" ]; then
            print_message $YELLOW "强制终止占用端口的进程 $port_pid"
            kill -9 $port_pid 2>/dev/null || true
        fi
    fi
    
    # 方法3: 通过进程名杀死相关进程
    local node_pids=$(pgrep -f "$SERVER_FILE" 2>/dev/null || true)
    if [ ! -z "$node_pids" ]; then
        print_message $YELLOW "发现相关Node.js进程，正在终止..."
        echo "$node_pids" | xargs kill 2>/dev/null || true
        sleep 2
        
        # 强制杀死仍然存在的进程
        node_pids=$(pgrep -f "$SERVER_FILE" 2>/dev/null || true)
        if [ ! -z "$node_pids" ]; then
            echo "$node_pids" | xargs kill -9 2>/dev/null || true
        fi
    fi
    
    print_message $GREEN "进程清理完成"
}

# 等待端口释放
wait_for_port_free() {
    local max_wait=10
    local count=0
    
    while [ $count -lt $max_wait ]; do
        if ! lsof -i:$PORT > /dev/null 2>&1; then
            print_message $GREEN "端口 $PORT 已释放"
            return 0
        fi
        
        print_message $YELLOW "等待端口 $PORT 释放... ($((count+1))/$max_wait)"
        sleep 1
        count=$((count+1))
    done
    
    print_message $RED "端口 $PORT 释放超时"
    return 1
}

# 启动服务器
start_server() {
    print_message $BLUE "启动 $PROJECT_NAME 服务器..."
    
    # 检查服务器文件是否存在
    if [ ! -f "$SERVER_FILE" ]; then
        print_message $RED "错误: 服务器文件 $SERVER_FILE 不存在"
        exit 1
    fi
    
    # 后台启动服务器并保存PID
    nohup node "$SERVER_FILE" > server.log 2>&1 &
    local server_pid=$!
    
    # 保存PID到文件
    echo $server_pid > "$PID_FILE"
    
    print_message $BLUE "服务器进程ID: $server_pid"
    print_message $BLUE "日志文件: server.log"
    
    # 等待服务器启动
    print_message $YELLOW "等待服务器启动..."
    sleep 3
    
    # 检查服务器是否成功启动
    if ps -p $server_pid > /dev/null 2>&1; then
        # 检查端口是否监听
        if lsof -i:$PORT > /dev/null 2>&1; then
            print_message $GREEN "✅ 服务器启动成功!"
            print_message $GREEN "🌐 访问地址: http://localhost:$PORT"
            print_message $BLUE "📝 查看日志: tail -f server.log"
            print_message $BLUE "🛑 停止服务: kill $server_pid 或删除 $PID_FILE"
        else
            print_message $RED "❌ 服务器启动失败: 端口未监听"
            print_message $YELLOW "请检查日志文件: server.log"
            exit 1
        fi
    else
        print_message $RED "❌ 服务器进程启动失败"
        print_message $YELLOW "请检查日志文件: server.log"
        exit 1
    fi
}

# 显示帮助信息
show_help() {
    echo "XHR Hook Goat 前端启动脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help     显示此帮助信息"
    echo "  -s, --status   显示服务器状态"
    echo "  -k, --kill     仅杀死现有进程，不启动新进程"
    echo "  -r, --restart  重启服务器（杀死现有进程并启动新进程）"
    echo ""
    echo "默认行为: 杀死现有进程并启动新的服务器实例"
}

# 显示服务器状态
show_status() {
    print_message $BLUE "检查服务器状态..."
    
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if ps -p $pid > /dev/null 2>&1; then
            print_message $GREEN "✅ 服务器正在运行 (PID: $pid)"
            if lsof -i:$PORT > /dev/null 2>&1; then
                print_message $GREEN "🌐 端口 $PORT 正在监听"
                print_message $GREEN "🔗 访问地址: http://localhost:$PORT"
            else
                print_message $YELLOW "⚠️  进程存在但端口未监听"
            fi
        else
            print_message $RED "❌ PID文件存在但进程不存在"
            rm -f "$PID_FILE"
        fi
    else
        print_message $YELLOW "📄 未找到PID文件"
    fi
    
    # 检查端口占用
    local port_pid=$(lsof -ti:$PORT 2>/dev/null || true)
    if [ ! -z "$port_pid" ]; then
        print_message $BLUE "端口 $PORT 被进程 $port_pid 占用"
    else
        print_message $YELLOW "端口 $PORT 未被占用"
    fi
}

# 主函数
main() {
    print_message $BLUE "🚀 XHR Hook Goat 前端启动脚本"
    print_message $BLUE "================================================"
    
    # 解析命令行参数
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -s|--status)
            show_status
            exit 0
            ;;
        -k|--kill)
            kill_existing_processes
            print_message $GREEN "✅ 进程清理完成"
            exit 0
            ;;
        -r|--restart)
            print_message $BLUE "重启模式"
            ;;
        "")
            print_message $BLUE "启动模式"
            ;;
        *)
            print_message $RED "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
    
    # 执行启动流程
    check_nodejs
    check_dependencies
    kill_existing_processes
    wait_for_port_free
    start_server
    
    print_message $GREEN "================================================"
    print_message $GREEN "🎉 启动完成! 服务器正在运行中..."
}

# 捕获中断信号，优雅退出
trap 'print_message $YELLOW "收到中断信号，正在清理..."; kill_existing_processes; exit 0' INT TERM

# 执行主函数
main "$@"
