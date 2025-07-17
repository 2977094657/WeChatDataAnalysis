"""微信解密工具的FastAPI Web服务器"""

import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .logging_config import setup_logging, get_logger
from .wechat_decrypt import decrypt_wechat_databases

# 初始化日志系统
setup_logging()
logger = get_logger(__name__)


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


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """记录所有HTTP请求的中间件"""
    start_time = time.time()

    # 记录请求开始
    logger.info(f"请求开始: {request.method} {request.url}")

    # 处理请求
    response = await call_next(request)

    # 计算处理时间
    process_time = time.time() - start_time

    # 记录请求完成
    logger.info(f"请求完成: {request.method} {request.url} - 状态码: {response.status_code} - 耗时: {process_time:.3f}s")

    return response


class DecryptRequest(BaseModel):
    """解密请求模型"""
    key: str
    db_storage_path: Optional[str] = None  # 可选的数据库存储路径，如 ......\{微信id}\db_storage





@app.get("/", summary="根端点")
async def root():
    """根端点"""
    logger.info("访问根端点")
    return {"message": "微信数据库解密工具 API"}





@app.get("/api/wechat-detection", summary="详细检测微信安装信息")
async def detect_wechat_detailed():
    """详细检测微信安装信息，包括版本、路径、消息目录等。"""
    logger.info("开始执行微信检测")
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

        logger.info(f"微信检测完成: 检测到 {stats['total_user_accounts']} 个账户, {stats['total_databases']} 个数据库")

        return {
            'status': 'success',
            'data': info,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"微信检测失败: {str(e)}")
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
    logger.info(f"开始解密请求: db_storage_path={request.db_storage_path}")
    try:
        # 验证密钥格式
        if not request.key or len(request.key) != 64:
            logger.warning(f"密钥格式无效: 长度={len(request.key) if request.key else 0}")
            raise HTTPException(status_code=400, detail="密钥格式无效，必须是64位十六进制字符串")

        # 使用新的解密API
        results = decrypt_wechat_databases(
            db_storage_path=request.db_storage_path,
            key=request.key
        )

        if results["status"] == "error":
            logger.error(f"解密失败: {results['message']}")
            raise HTTPException(status_code=400, detail=results["message"])

        logger.info(f"解密完成: 成功 {results['successful_count']}/{results['total_databases']} 个数据库")

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
        logger.error(f"解密API异常: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))





@app.get("/api/health", summary="健康检查端点")
async def health_check():
    """健康检查端点"""
    logger.debug("健康检查请求")
    return {"status": "healthy", "service": "微信解密工具"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)