"""微信解密工具的FastAPI Web服务器"""

from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .wechat_decrypt import decrypt_wechat_databases


app = FastAPI(
    title="微信数据库解密工具",
    description="现代化的微信数据库解密工具，支持微信信息检测和数据库解密功能",
    version="0.1.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DecryptRequest(BaseModel):
    """解密请求模型"""
    key: str
    db_storage_path: Optional[str] = None  # 可选的数据库存储路径，如 ......\{微信id}\db_storage





@app.get("/", summary="根端点")
async def root():
    """根端点"""
    return {"message": "微信数据库解密工具 API"}





@app.get("/api/wechat-detection", summary="详细检测微信安装信息")
async def detect_wechat_detailed():
    """详细检测微信安装信息，包括版本、路径、消息目录等。"""
    try:
        from .wechat_detection import detect_wechat_installation
        info = detect_wechat_installation()
        
        # 添加一些统计信息
        stats = {
            'total_databases': len(info['databases']),
            'total_user_accounts': len(info['user_accounts']),
            'total_message_dirs': len(info['message_dirs']),
            'has_wechat_installed': info['wechat_install_path'] is not None,
            'detection_time': __import__('datetime').datetime.now().isoformat()
        }
        
        return {
            'status': 'success',
            'data': info,
            'statistics': stats
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'data': None,
            'statistics': None
        }





@app.post("/api/decrypt", summary="解密微信数据库")
async def decrypt_databases(request: DecryptRequest):
    """使用提供的密钥解密微信数据库

    参数:
    - key: 解密密钥（必选）
    - db_storage_path: 数据库存储路径（可选），如 ......\\{微信id}\\db_storage

    如果不提供db_storage_path，将自动检测所有微信数据库
    """
    try:
        # 验证密钥格式
        if not request.key or len(request.key) != 64:
            raise HTTPException(status_code=400, detail="密钥格式无效，必须是64位十六进制字符串")

        # 使用新的解密API
        results = decrypt_wechat_databases(
            db_storage_path=request.db_storage_path,
            key=request.key
        )

        if results["status"] == "error":
            raise HTTPException(status_code=400, detail=results["message"])

        return {
            "status": "completed" if results["status"] == "success" else "failed",
            "total_databases": results["total_databases"],
            "success_count": results["successful_count"],
            "failure_count": results["failed_count"],
            "output_directory": results["output_directory"],
            "message": results["message"],
            "processed_files": results["processed_files"],
            "failed_files": results["failed_files"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))





@app.get("/api/health", summary="健康检查端点")
async def health_check():
    """健康检查端点"""
    return {"status": "healthy", "service": "微信解密工具"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)