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
  const detectWechat = async (params = {}) => {
    const query = new URLSearchParams()
    if (params && params.data_root_path) {
      query.set('data_root_path', params.data_root_path)
    }
    const url = '/wechat-detection' + (query.toString() ? `?${query.toString()}` : '')
    return await request(url)
  }
  
  // 检测当前登录账号API
  const detectCurrentAccount = async (params = {}) => {
    const query = new URLSearchParams()
    if (params && params.data_root_path) {
      query.set('data_root_path', params.data_root_path)
    }
    const url = '/current-account' + (query.toString() ? `?${query.toString()}` : '')
    return await request(url)
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
    detectCurrentAccount,
    decryptDatabase,
    healthCheck
  }
}