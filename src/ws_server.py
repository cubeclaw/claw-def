#!/usr/bin/env python3
"""
WebSocket 实时推送服务器 - ClawDef 核心组件

功能:
- WebSocket 服务器
- 安全事件推送
- 客户端连接管理
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, Set, Optional

LOG_PATH = os.path.expanduser("~/.openclaw/logs/clawdef.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)
logger = logging.getLogger("ClawDef.WSServer")

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    logger.warning("websockets 未安装，WebSocket 功能不可用")


class WSServer:
    """WebSocket 服务器"""
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.clients: Set = set()
        self.event_queue = asyncio.Queue()
    
    async def register(self, websocket):
        """注册客户端"""
        self.clients.add(websocket)
        logger.info(f"客户端连接，当前连接数：{len(self.clients)}")
    
    async def unregister(self, websocket):
        """注销客户端"""
        self.clients.discard(websocket)
        logger.info(f"客户端断开，当前连接数：{len(self.clients)}")
    
    async def push_event(self, event_type: str, data: Dict):
        """推送事件"""
        event = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat(),
        }
        
        if not self.clients:
            logger.debug(f"无客户端，事件已丢弃：{event_type}")
            return
        
        message = json.dumps(event, ensure_ascii=False)
        
        # 广播给所有客户端
        disconnected = set()
        for client in self.clients:
            try:
                await client.send(message)
            except Exception as e:
                logger.warning(f"推送失败：{e}")
                disconnected.add(client)
        
        # 清理断开的客户端
        for client in disconnected:
            await self.unregister(client)
        
        logger.info(f"事件已推送：{event_type} 到 {len(self.clients)} 个客户端")
    
    async def event_dispatcher(self):
        """事件分发器"""
        while True:
            event = await self.event_queue.get()
            await self.push_event(event['type'], event['data'])
    
    async def handler(self, websocket, path):
        """WebSocket 处理器"""
        await self.register(websocket)
        try:
            async for message in websocket:
                logger.debug(f"收到消息：{message}")
        finally:
            await self.unregister(websocket)
    
    def start(self):
        """启动服务器"""
        if not WEBSOCKETS_AVAILABLE:
            logger.error("无法启动 WebSocket 服务器：websockets 未安装")
            return
        
        logger.info(f"启动 WebSocket 服务器：ws://{self.host}:{self.port}")
        
        start_server = websockets.serve(self.handler, self.host, self.port)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()


class SecurityEventPusher:
    """安全事件推送器"""
    
    def __init__(self, ws_url: Optional[str] = None):
        self.ws_url = ws_url or "ws://localhost:8765"
        self.websocket = None
    
    async def connect(self):
        """连接 WebSocket 服务器"""
        if not WEBSOCKETS_AVAILABLE:
            return False
        
        try:
            import websockets
            self.websocket = await websockets.connect(self.ws_url)
            logger.info(f"已连接到 {self.ws_url}")
            return True
        except Exception as e:
            logger.warning(f"连接失败：{e}")
            return False
    
    async def disconnect(self):
        """断开连接"""
        if self.websocket:
            await self.websocket.close()
    
    async def push_threat_detected(self, threat: Dict):
        """推送威胁检测事件"""
        await self._send('threat_detected', {
            'threat_id': threat.get('pattern_id', 'unknown'),
            'threat_name': threat.get('pattern_name', 'unknown'),
            'severity': threat.get('severity', 'unknown'),
            'file': threat.get('file', ''),
            'line': threat.get('line', 0),
        })
    
    async def push_file_access_blocked(self, event: Dict):
        """推送文件访问阻止事件"""
        await self._send('file_access_blocked', {
            'skill': event.get('skill', ''),
            'file': event.get('file', ''),
            'operation': event.get('operation', ''),
            'level': event.get('level', ''),
        })
    
    async def push_install_alert(self, result: Dict):
        """推送安装告警事件"""
        await self._send('install_alert', {
            'skill': result.get('skill_name', ''),
            'risk_level': result.get('level', ''),
            'risk_score': result.get('score', 0),
            'action': result.get('action', ''),
        })
    
    async def _send(self, event_type: str, data: Dict):
        """发送事件"""
        if not self.websocket:
            logger.warning("WebSocket 未连接")
            return
        
        event = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat(),
        }
        
        try:
            await self.websocket.send(json.dumps(event, ensure_ascii=False))
            logger.info(f"事件已发送：{event_type}")
        except Exception as e:
            logger.error(f"发送失败：{e}")


# 简化版 - 无依赖实现
class SimpleEventLogger:
    """简单事件日志器（无需 WebSocket）"""
    
    def __init__(self, log_path: str = None):
        self.log_path = log_path or os.path.expanduser("~/.openclaw/logs/clawdef_events.log")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
    
    def log_event(self, event_type: str, data: Dict):
        """记录事件"""
        event = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat(),
        }
        
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
        
        logger.info(f"事件已记录：{event_type}")
    
    def get_recent_events(self, limit: int = 100) -> list:
        """获取最近事件"""
        events = []
        try:
            with open(self.log_path, 'r') as f:
                for line in f.readlines()[-limit:]:
                    events.append(json.loads(line.strip()))
        except FileNotFoundError:
            pass
        
        return events


def main():
    """CLI 入口"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法：python3 ws_server.py <command> [args]")
        print("命令:")
        print("  start [port]  - 启动 WebSocket 服务器")
        print("  log           - 查看最近事件")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'start':
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
        server = WSServer(port=port)
        server.start()
    
    elif command == 'log':
        logger = SimpleEventLogger()
        events = logger.get_recent_events(20)
        for event in events:
            print(f"{event['timestamp']} | {event['type']} | {json.dumps(event['data'])[:50]}")
    
    else:
        print(f"未知命令：{command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
