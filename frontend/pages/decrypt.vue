<template>
  <div class="min-h-screen flex items-center justify-center">
    
    <div class="max-w-4xl mx-auto px-6 w-full">
      <!-- 解密表单 -->
      <div class="bg-white rounded-2xl border border-[#EDEDED]">
        <div class="p-8">
          <div class="flex items-center mb-6">
            <div class="w-12 h-12 bg-[#07C160] rounded-lg flex items-center justify-center mr-4">
              <svg class="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
              </svg>
            </div>
            <div>
              <h2 class="text-xl font-bold text-[#000000e6]">解密配置</h2>
              <p class="text-sm text-[#7F7F7F]">输入密钥和路径开始解密</p>
            </div>
          </div>
          
          <form @submit.prevent="handleDecrypt" class="space-y-6">
            <!-- 密钥输入 -->
            <div>
              <label for="key" class="block text-sm font-medium text-[#000000e6] mb-2">
                <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                </svg>
                解密密钥 <span class="text-red-500">*</span>
              </label>
              <div class="relative">
                <input
                  id="key"
                  v-model="formData.key"
                  type="text"
                  placeholder="请输入64位十六进制密钥"
                  class="w-full px-4 py-3 bg-white border border-[#EDEDED] rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[#07C160] focus:border-transparent transition-all duration-200"
                  :class="{ 'border-red-500': formErrors.key }"
                  required
                />
                <div v-if="formData.key" class="absolute right-3 top-1/2 transform -translate-y-1/2">
                  <span class="text-xs text-[#7F7F7F]">{{ formData.key.length }}/64</span>
                </div>
              </div>
              <p v-if="formErrors.key" class="mt-1 text-sm text-red-600 flex items-center">
                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                {{ formErrors.key }}
              </p>
              <p class="mt-2 text-xs text-[#7F7F7F] flex items-center">
                <svg class="w-4 h-4 mr-1 text-[#10AEEF]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                使用 <a href="https://github.com/gzygood/DbkeyHook" target="_blank" class="text-[#07C160] hover:text-[#06AD56]">DbkeyHook</a> 等工具获取的64位十六进制字符串
              </p>
            </div>
            
            <!-- 数据库路径输入 -->
            <div>
              <label for="dbPath" class="block text-sm font-medium text-[#000000e6] mb-2">
                <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                </svg>
                数据库存储路径 <span class="text-red-500">*</span>
              </label>
              <input
                id="dbPath"
                v-model="formData.db_storage_path"
                type="text"
                placeholder="例如: D:\wechatMSG\xwechat_files\wxid_xxx\db_storage"
                class="w-full px-4 py-3 bg-white border border-[#EDEDED] rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[#07C160] focus:border-transparent transition-all duration-200"
                :class="{ 'border-red-500': formErrors.db_storage_path }"
                required
              />
              <p v-if="formErrors.db_storage_path" class="mt-1 text-sm text-red-600 flex items-center">
                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                {{ formErrors.db_storage_path }}
              </p>
              <p class="mt-2 text-xs text-[#7F7F7F] flex items-center">
                <svg class="w-4 h-4 mr-1 text-[#10AEEF]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                请输入数据库文件所在的绝对路径
              </p>
            </div>
            
            <!-- 提交按钮 -->
            <div class="pt-4 border-t border-[#EDEDED]">
              <div class="flex items-center justify-center">
                <button
                  type="submit"
                  :disabled="loading"
                  class="inline-flex items-center px-8 py-3 bg-[#07C160] text-white rounded-lg text-base font-medium hover:bg-[#06AD56] transform hover:scale-105 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <svg v-if="!loading" class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"/>
                  </svg>
                  <svg v-if="loading" class="w-5 h-5 mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  {{ loading ? '解密中...' : '开始解密' }}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    
      <!-- 错误提示 -->
      <transition name="fade">
        <div v-if="error" class="bg-red-50 border border-red-200 rounded-lg p-4 mt-6 animate-shake flex items-start">
          <svg class="h-5 w-5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <div>
            <p class="font-semibold">解密失败</p>
            <p class="text-sm mt-1">{{ error }}</p>
          </div>
        </div>
      </transition>
    </div>
  </div>
</template>

<style scoped>
/* 动画效果 */
.fade-enter-active, .fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from, .fade-leave-to {
  opacity: 0;
}

@keyframes shake {
  0%, 100% { transform: translateX(0); }
  10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
  20%, 40%, 60%, 80% { transform: translateX(5px); }
}

.animate-shake {
  animation: shake 0.5s ease-in-out;
}
</style>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useApi } from '~/composables/useApi'

const { decryptDatabase } = useApi()

const loading = ref(false)
const error = ref('')

// 表单数据
const formData = reactive({
  key: '',
  db_storage_path: ''
})

// 表单错误
const formErrors = reactive({
  key: '',
  db_storage_path: ''
})

// 验证表单
const validateForm = () => {
  let isValid = true
  formErrors.key = ''
  formErrors.db_storage_path = ''
  
  // 验证密钥
  if (!formData.key) {
    formErrors.key = '请输入解密密钥'
    isValid = false
  } else if (formData.key.length !== 64) {
    formErrors.key = '密钥必须是64位十六进制字符串'
    isValid = false
  } else if (!/^[0-9a-fA-F]+$/.test(formData.key)) {
    formErrors.key = '密钥必须是有效的十六进制字符串'
    isValid = false
  }
  
  // 验证路径
  if (!formData.db_storage_path) {
    formErrors.db_storage_path = '请输入数据库存储路径'
    isValid = false
  }
  
  return isValid
}

// 处理解密
const handleDecrypt = async () => {
  if (!validateForm()) {
    return
  }
  
  loading.value = true
  error.value = ''
  
  try {
    const result = await decryptDatabase({
      key: formData.key,
      db_storage_path: formData.db_storage_path
    })
    
    if (result.status === 'completed') {
      // 解密成功，跳转到结果页面
      if (process.client && typeof window !== 'undefined') {
        sessionStorage.setItem('decryptResult', JSON.stringify(result))
      }
      navigateTo('/decrypt-result')
    } else if (result.status === 'failed') {
      if (result.failure_count > 0 && result.success_count === 0) {
        error.value = result.message || '所有文件解密失败'
      } else {
        error.value = '部分文件解密失败，请检查密钥是否正确'
      }
    } else {
      error.value = result.message || '解密失败，请检查输入信息'
    }
  } catch (err) {
    error.value = err.message || '解密过程中发生错误'
  } finally {
    loading.value = false
  }
}

// 页面加载时检查是否有选中的账户
onMounted(() => {
  if (process.client && typeof window !== 'undefined') {
    const selectedAccount = sessionStorage.getItem('selectedAccount')
    if (selectedAccount) {
      try {
        const account = JSON.parse(selectedAccount)
        // 填充数据路径
        if (account.data_dir) {
          formData.db_storage_path = account.data_dir + '\\db_storage'
        }
        // 清除sessionStorage
        sessionStorage.removeItem('selectedAccount')
      } catch (e) {
        console.error('解析账户信息失败:', e)
      }
    }
  }
})
</script>