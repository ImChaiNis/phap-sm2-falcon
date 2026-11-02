import asyncio
import websockets
import json
import logging
import socket
from datetime import datetime

# 新增：自动获取本机局域网IP

def get_local_ip():
    """自动获取本机局域网IP（非虚拟网卡）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 存储所有连接的客户端
connected_clients = set()

def find_available_port(start_port=8080, max_port=8090):
    """查找可用端口"""
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    raise OSError("没有找到可用端口")

async def handle_client(websocket, path):
    try:
        # 添加新客户端
        connected_clients.add(websocket)
        logging.info(f"新客户端连接。当前连接数: {len(connected_clients)}")
        
        # 处理消息
        async for message in websocket:
            try:
                # 解析消息
                data = json.loads(message)
                logging.info(f"收到消息: {data}")
                
                # 广播消息给所有客户端
                for client in connected_clients:
                    if client != websocket:  # 不发送给发送者
                        await client.send(message)
                        logging.info(f"消息已转发给其他客户端")
                        
            except json.JSONDecodeError:
                logging.error("消息格式错误")
                continue
                
    except websockets.exceptions.ConnectionClosed:
        logging.info("客户端断开连接")
    finally:
        # 移除断开的客户端
        connected_clients.remove(websocket)
        logging.info(f"客户端已移除。当前连接数: {len(connected_clients)}")

async def main():
    # 查找可用端口
    port = find_available_port()
    logging.info(f"使用端口: {port}")

    # 新增：打印本机局域网IP
    local_ip = get_local_ip()
    logging.info(f"请在Android应用中填写服务器地址为：{local_ip}:{port}")

    # 启动WebSocket服务器
    server = await websockets.serve(
        handle_client,
        "0.0.0.0",  # 监听所有网络接口
        port,       # 使用找到的可用端口
        ping_interval=None  # 禁用ping以避免某些客户端的问题
    )
    
    logging.info(f"WebSocket服务器已启动在 ws://0.0.0.0:{port}")
    logging.info("请更新Android应用中的WebSocket URL为上述地址")
    
    # 保持服务器运行
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("服务器已停止")
    except OSError as e:
        logging.error(f"启动服务器失败: {e}") 