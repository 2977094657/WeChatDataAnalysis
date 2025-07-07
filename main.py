#!/usr/bin/env python3
"""
微信解密工具主启动脚本

使用方法:
    uv run main.py

默认在8000端口启动API服务
"""

import uvicorn

def main():
    """启动微信解密工具API服务"""
    print("=" * 60)
    print("微信解密工具 API 服务")
    print("=" * 60)
    print("正在启动服务...")
    print("API文档: http://localhost:8000/docs")
    print("健康检查: http://localhost:8000/api/health")
    print("按 Ctrl+C 停止服务")
    print("=" * 60)
    
    # 启动API服务
    uvicorn.run(
        "wechat_decrypt_tool.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()
