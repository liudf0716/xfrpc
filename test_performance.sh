#!/bin/bash
# xfrpc 性能测试脚本

echo "=========================================="
echo "  xfrpc 穿透性能测试"
echo "=========================================="
echo ""

# 服务器地址
SERVER_IP="43.159.38.154"
HTTP_PORT="6008"
SSH_PORT="6002"

# 测试文件大小
SIZES=("1" "5" "10" "50" "100")

echo "测试环境:"
echo "  服务端: ${SERVER_IP}:7070"
echo "  HTTP 穿透: ${SERVER_IP}:${HTTP_PORT}"
echo "  SSH 穿透: ${SERVER_IP}:${SSH_PORT}"
echo ""

# 测试 1: 直连基准
echo "=========================================="
echo "  测试 1: 直连基准 (nginx :80)"
echo "=========================================="
for size in "${SIZES[@]}"; do
    file="/var/www/html/test_${size}mb.bin"
    if [ -f "$file" ]; then
        result=$(curl -o /dev/null -s -w "%{speed_download}" "http://${SERVER_IP}/test_${size}mb.bin" --connect-timeout 3 --max-time 30)
        echo "  ${size}MB: $(echo "scale=2; $result/1024/1024" | bc) MB/s"
    fi
done
echo ""

# 测试 2: 穿透测试
echo "=========================================="
echo "  测试 2: 穿透测试 (端口 ${HTTP_PORT})"
echo "=========================================="
for size in "${SIZES[@]}"; do
    file="/var/www/html/test_${size}mb.bin"
    if [ -f "$file" ]; then
        result=$(curl -o /dev/null -s -w "%{speed_download}" "http://${SERVER_IP}:${HTTP_PORT}/test_${size}mb.bin" --connect-timeout 3 --max-time 60)
        echo "  ${size}MB: $(echo "scale=2; $result/1024/1024" | bc) MB/s"
    fi
done
echo ""

# 测试 3: 连接稳定性
echo "=========================================="
echo "  测试 3: 连接稳定性 (100MB x 3 次)"
echo "=========================================="
for i in 1 2 3; do
    echo "  第 ${i} 次测试..."
    result=$(curl -o /dev/null -s -w "%{speed_download}|%{http_code}" "http://${SERVER_IP}:${HTTP_PORT}/test_100mb.bin" --connect-timeout 3 --max-time 120)
    speed=$(echo "$result" | cut -d'|' -f1)
    status=$(echo "$result" | cut -d'|' -f2)
    echo "    速度: $(echo "scale=2; $speed/1024/1024" | bc) MB/s, HTTP 状态: ${status}"
done
echo ""

# 测试 4: 并发测试
echo "=========================================="
echo "  测试 4: 并发下载 (3 个并发)"
echo "=========================================="
echo "  启动 3 个并发下载..."
for i in 1 2 3; do
    curl -o /dev/null -s -w "  进程 ${i}: %{speed_download} bytes/s\n" "http://${SERVER_IP}:${HTTP_PORT}/test_10mb.bin" --connect-timeout 3 --max-time 30 &
done
wait
echo "  并发测试完成"
echo ""

# 测试 5: SSH 穿透
echo "=========================================="
echo "  测试 5: SSH 穿透 (端口 ${SSH_PORT})"
echo "=========================================="
result=$(echo "" | timeout 3 nc -z ${SERVER_IP} ${SSH_PORT} 2>&1 && echo "连接成功" || echo "连接失败")
echo "  SSH 端口 ${SSH_PORT}: ${result}"
echo ""

echo "=========================================="
echo "  测试完成"
echo "=========================================="
