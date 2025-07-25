// API请求组合式函数
export const useApi = () => {
  const config = useRuntimeConfig()
  
  // 基础请求函数
  const request = async (url, options = {}) => {
    try {
      // 在客户端使用完整的API路径
      const baseURL = process.client ? 'http://localhost:8000/api' : '/api'
      
      const response = await $fetch(url, {
        baseURL,
        ...options,
        onResponseError({ response }) {
          if (response.status === 400) {
            throw new Error(response._data?.detail || '请求参数错误')
          } else if (response.status === 500) {
            throw new Error('服务器错误，请稍后重试')
          }
        }
      })
      return response
    } catch (error) {
      console.error('API请求错误:', error)
      throw error
    }
  }
  
  // 微信检测API
  const detectWechat = async () => {
    return await request('/wechat-detection')
  }
  
  // 数据库解密API
  const decryptDatabase = async (data) => {
    return await request('/decrypt', {
      method: 'POST',
      body: data
    })
  }
  
  // 健康检查API
  const healthCheck = async () => {
    return await request('/health')
  }
  
  return {
    detectWechat,
    decryptDatabase,
    healthCheck
  }
}