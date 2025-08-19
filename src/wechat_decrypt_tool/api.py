"""微信解密工具的FastAPI Web服务器"""

import time
import re
import json
import os
from typing import Optional, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .logging_config import setup_logging, get_logger
from .wechat_decrypt import decrypt_wechat_databases

# 初始化日志系统
setup_logging()
logger = get_logger(__name__)


class PathFixRequest(Request):
    """自定义Request类，自动修复JSON中的路径问题并检测相对路径"""

    def _is_absolute_path(self, path: str) -> bool:
        """检测是否为绝对路径，支持Windows、macOS、Linux"""
        if not path:
            return False

        # Windows绝对路径：以盘符开头 (C:\, D:\, etc.)
        if re.match(r'^[A-Za-z]:[/\\]', path):
            return True

        # Unix-like系统绝对路径：以 / 开头
        if path.startswith('/'):
            return True

        return False

    def _validate_paths_in_json(self, json_data: dict) -> Optional[str]:
        """验证JSON中的路径，返回错误信息（如果有）"""
        logger.info(f"开始验证路径，JSON数据: {json_data}")
        # 检查db_storage_path字段（现在是必需的）
        if 'db_storage_path' not in json_data:
            return "缺少必需的db_storage_path参数，请提供具体的数据库存储路径。"

        if 'db_storage_path' in json_data:
            path = json_data['db_storage_path']

            # 检查路径是否为空
            if not path or not path.strip():
                return "db_storage_path参数不能为空，请提供具体的数据库存储路径。"

            logger.info(f"检查路径: {path}")
            is_absolute = self._is_absolute_path(path)
            logger.info(f"是否为绝对路径: {is_absolute}")
            if not is_absolute:
                error_msg = f"请提供绝对路径，当前输入的是相对路径: {path}。\n" \
                           f"Windows绝对路径示例: D:\\wechatMSG\\xwechat_files\\wxid_xxx\\db_storage"
                return error_msg

            # 检查路径是否存在
            logger.info(f"检查路径是否存在: {path}")
            path_exists = os.path.exists(path)
            logger.info(f"路径存在性: {path_exists}")
            if not path_exists:
                # 检查父目录
                parent_path = os.path.dirname(path)
                logger.info(f"检查父目录: {parent_path}")
                parent_exists = os.path.exists(parent_path)
                logger.info(f"父目录存在性: {parent_exists}")
                if parent_exists:
                    try:
                        files = os.listdir(parent_path)
                        logger.info(f"父目录内容: {files}")
                        error_msg = f"指定的路径不存在: {path}\n" \
                                   f"父目录存在但不包含 'db_storage' 文件夹。\n" \
                                   f"请检查路径是否正确，或确保微信数据已生成。"
                    except PermissionError:
                        logger.info(f"无法访问父目录，权限不足")
                        error_msg = f"指定的路径不存在: {path}\n" \
                                   f"无法访问父目录，可能是权限问题。"
                else:
                    error_msg = f"指定的路径不存在: {path}\n" \
                               f"父目录也不存在，请检查路径是否正确。"
                logger.info(f"返回路径错误: {error_msg}")
                return error_msg
            else:
                logger.info(f"路径存在，使用递归方式检查数据库文件")
                try:
                    # 使用与自动检测相同的逻辑：递归查找.db文件
                    db_files = []
                    for root, dirs, files in os.walk(path):
                        # 只处理db_storage目录下的数据库文件（与自动检测逻辑一致）
                        if "db_storage" not in root:
                            continue
                        for file_name in files:
                            if not file_name.endswith(".db"):
                                continue
                            # 排除不需要解密的数据库（与自动检测逻辑一致）
                            if file_name in ["key_info.db"]:
                                continue
                            db_path = os.path.join(root, file_name)
                            db_files.append(db_path)

                    logger.info(f"递归查找到的数据库文件: {db_files}")
                    if not db_files:
                        error_msg = f"路径存在但没有找到有效的数据库文件: {path}\n" \
                                   f"请确保该目录或其子目录包含微信数据库文件(.db文件)。\n" \
                                   f"注意：key_info.db文件会被自动排除。"
                        logger.info(f"返回错误: 递归查找未找到有效.db文件")
                        return error_msg
                    logger.info(f"路径验证通过，递归找到{len(db_files)}个有效数据库文件")
                except PermissionError:
                    error_msg = f"无法访问路径: {path}\n" \
                               f"权限不足，请检查文件夹权限。"
                    return error_msg
                except Exception as e:
                    logger.warning(f"检查路径内容时出错: {e}")
                    # 如果无法检查内容，继续执行，让后续逻辑处理

        return None

    async def body(self) -> bytes:
        """重写body方法，预处理JSON中的路径问题"""
        body = await super().body()

        # 只处理JSON请求
        content_type = self.headers.get("content-type", "")
        if "application/json" not in content_type:
            return body

        try:
            # 将bytes转换为字符串
            body_str = body.decode('utf-8')

            # 首先尝试解析JSON以验证路径
            try:
                json_data = json.loads(body_str)
                path_error = self._validate_paths_in_json(json_data)
                if path_error:
                    logger.info(f"检测到路径错误: {path_error}")
                    # 我们将错误信息存储在请求中，稍后在路由处理器中检查
                    self.state.path_validation_error = path_error
                    return body
            except json.JSONDecodeError as e:
                # JSON格式错误，继续尝试修复
                logger.info(f"JSON解析失败，尝试修复: {e}")
                pass

            # 使用正则表达式安全地处理Windows路径中的反斜杠
            # 需要处理两种情况：
            # 1. 以盘符开头的绝对路径：D:\path\to\file
            # 2. 不以盘符开头的相对路径：wechatMSG\xwechat_files\...

            # 匹配引号内包含反斜杠的路径（不管是否以盘符开头）
            pattern = r'"([^"]*?\\[^"]*?)"'

            def fix_path(match):
                path = match.group(1)
                # 将单个反斜杠替换为双反斜杠，但避免替换已经转义的反斜杠
                fixed_path = re.sub(r'(?<!\\)\\(?!\\)', r'\\\\', path)
                return f'"{fixed_path}"'

            # 应用修复
            fixed_body_str = re.sub(pattern, fix_path, body_str)

            # 记录修复信息（仅在有修改时）
            if fixed_body_str != body_str:
                logger.info(f"自动修复JSON路径格式: {body_str[:100]}... -> {fixed_body_str[:100]}...")

            # 修复后重新验证路径
            try:
                json_data = json.loads(fixed_body_str)
                logger.info(f"修复后解析JSON成功，开始验证路径")
                path_error = self._validate_paths_in_json(json_data)
                if path_error:
                    logger.info(f"修复后检测到路径错误: {path_error}")
                    self.state.path_validation_error = path_error
                    return fixed_body_str.encode('utf-8')
                else:
                    logger.info(f"修复后路径验证通过")
            except json.JSONDecodeError as e:
                logger.warning(f"修复后JSON仍然解析失败: {e}")

            return fixed_body_str.encode('utf-8')

        except Exception as e:
            # 如果处理失败，返回原始body
            logger.warning(f"JSON路径修复失败，使用原始请求体: {e}")
            return body


class PathFixRoute(APIRoute):
    """自定义APIRoute类，使用PathFixRequest并处理路径验证错误"""

    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> any:
            # 将Request替换为我们的自定义Request
            custom_request = PathFixRequest(request.scope, request.receive)

            # 检查是否有路径验证错误
            if hasattr(custom_request.state, 'path_validation_error'):
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=400,
                    detail=custom_request.state.path_validation_error
                )

            return await original_route_handler(custom_request)

        return custom_route_handler


app = FastAPI(
    title="微信数据库解密工具",
    description="现代化的微信数据库解密工具，支持微信信息检测和数据库解密功能",
    version="0.1.0"
)

# 设置自定义路由类
app.router.route_class = PathFixRoute

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
    key: str = Field(..., description="解密密钥，64位十六进制字符串")
    db_storage_path: str = Field(..., description="数据库存储路径，必须是绝对路径")





@app.get("/", summary="根端点")
async def root():
    """根端点"""
    logger.info("访问根端点")
    return {"message": "微信数据库解密工具 API"}





@app.get("/api/wechat-detection", summary="详细检测微信安装信息")
async def detect_wechat_detailed(data_root_path: Optional[str] = None):
    """详细检测微信安装信息，包括版本、路径、消息目录等。"""
    logger.info("开始执行微信检测")
    try:
        from .wechat_detection import detect_wechat_installation, detect_current_logged_in_account
        info = detect_wechat_installation(data_root_path=data_root_path)
        
        # 检测当前登录账号
        current_account_info = detect_current_logged_in_account(data_root_path)
        info['current_account'] = current_account_info

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


@app.get("/api/current-account", summary="检测当前登录账号")
async def detect_current_account(data_root_path: Optional[str] = None):
    """检测当前登录的微信账号"""
    logger.info("开始检测当前登录账号")
    try:
        from .wechat_detection import detect_current_logged_in_account
        result = detect_current_logged_in_account(data_root_path)
        
        logger.info(f"当前账号检测完成: {result.get('message', '无结果')}")
        
        return {
            'status': 'success',
            'data': result
        }
    except Exception as e:
        logger.error(f"当前账号检测失败: {str(e)}")
        return {
            'status': 'error',
            'error': str(e),
            'data': None
        }





@app.post("/api/decrypt", summary="解密微信数据库")
async def decrypt_databases(request: DecryptRequest):
    """使用提供的密钥解密指定账户的微信数据库

    参数:
    - key: 解密密钥（必选）- 64位十六进制字符串
    - db_storage_path: 数据库存储路径（必选），如 D:\\wechatMSG\\xwechat_files\\{微信id}\\db_storage

    注意：
    - 一个密钥只能解密对应账户的数据库
    - 必须提供具体的db_storage_path，不支持自动检测多账户
    - 支持自动处理Windows路径中的反斜杠转义问题
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
            "failed_files": results["failed_files"],
            "account_results": results.get("account_results", {})
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