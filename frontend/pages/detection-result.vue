<template>
  <div class="min-h-screen relative overflow-hidden flex items-center">
    <!-- 网格背景 -->
    <div class="absolute inset-0 bg-grid-pattern opacity-5 pointer-events-none"></div>
    
    <!-- 装饰元素 -->
    <div class="absolute top-20 left-20 w-72 h-72 bg-[#07C160] opacity-5 rounded-full blur-3xl pointer-events-none"></div>
    <div class="absolute top-40 right-20 w-96 h-96 bg-[#10AEEF] opacity-5 rounded-full blur-3xl pointer-events-none"></div>
    <div class="absolute -bottom-8 left-40 w-80 h-80 bg-[#91D300] opacity-5 rounded-full blur-3xl pointer-events-none"></div>
    
    <!-- 主要内容 -->
    <div class="relative z-10 w-full max-w-6xl mx-auto px-4 py-8 animate-fade-in">
      <!-- 顶部操作栏 -->
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold">
          <span class="bg-gradient-to-r from-[#07C160] to-[#10AEEF] bg-clip-text text-transparent">检测结果</span>
        </h2>
        <NuxtLink to="/" 
          class="inline-flex items-center px-3 py-1.5 text-sm text-[#07C160] hover:text-[#06AD56] font-medium transition-colors">
          <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
          </svg>
          返回首页
        </NuxtLink>
      </div>
      
      <!-- 主内容区域 -->
      <div>
        <!-- 检测中状态 -->
        <div v-if="loading" class="bg-white rounded-2xl p-12 text-center">
          <svg class="w-16 h-16 mx-auto animate-spin text-[#07C160]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p class="mt-4 text-lg text-[#7F7F7F]">正在检测微信数据...</p>
        </div>
        
        <!-- 检测结果内容 -->
        <div v-else-if="detectionResult">
          <!-- 错误信息 -->
          <div v-if="detectionResult.error" class="bg-white rounded-2xl border border-red-200 p-8">
            <div class="flex items-center">
              <svg class="w-8 h-8 text-red-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              <div>
                <p class="text-lg font-medium text-red-600">检测失败</p>
                <p class="text-red-500 mt-1">{{ detectionResult.error }}</p>
              </div>
            </div>
          </div>
          
          <!-- 成功结果 -->
          <div v-else class="space-y-4">
            <!-- 概览卡片 -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div class="bg-white rounded-xl p-4 border border-[#EDEDED]">
                <div class="flex items-center justify-between">
                <div>
                  <p class="text-sm text-[#7F7F7F]">微信版本</p>
                  <p class="text-xl font-bold text-[#000000e6] mt-1">{{ detectionResult.data?.wechat_version || '未知' }}</p>
                </div>
                <div class="w-12 h-12 bg-[#07C160]/10 rounded-lg flex items-center justify-center">
                  <svg class="w-6 h-6 text-[#07C160]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                </div>
                </div>
              </div>
            
              <div class="bg-white rounded-xl p-4 border border-[#EDEDED]">
                <div class="flex items-center justify-between">
                <div>
                  <p class="text-sm text-[#7F7F7F]">检测到的账户</p>
                  <p class="text-xl font-bold text-[#000000e6] mt-1">{{ detectionResult.data?.total_accounts || 0 }} 个</p>
                </div>
                <div class="w-12 h-12 bg-[#10AEEF]/10 rounded-lg flex items-center justify-center">
                  <svg class="w-6 h-6 text-[#10AEEF]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
                  </svg>
                </div>
                </div>
              </div>
            
              <div class="bg-white rounded-xl p-4 border border-[#EDEDED]">
                <div class="flex items-center justify-between">
                <div>
                  <p class="text-sm text-[#7F7F7F]">数据库文件</p>
                  <p class="text-xl font-bold text-[#000000e6] mt-1">{{ detectionResult.data?.total_databases || 0 }} 个</p>
                </div>
                <div class="w-12 h-12 bg-[#91D300]/10 rounded-lg flex items-center justify-center">
                  <svg class="w-6 h-6 text-[#91D300]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/>
                  </svg>
                </div>
                </div>
              </div>
            </div>
            
            <!-- 账户列表 -->
          <div v-if="detectionResult.data?.accounts && detectionResult.data.accounts.length > 0" 
            class="bg-white rounded-2xl border border-[#EDEDED] overflow-hidden">
            <div class="p-4 border-b border-[#EDEDED] bg-gray-50">
              <h3 class="text-base font-semibold text-[#000000e6]">微信账户详情</h3>
            </div>
            <div class="divide-y divide-[#EDEDED] max-h-64 overflow-y-auto">
              <div v-for="(account, index) in detectionResult.data.accounts" :key="index" 
                class="p-4 hover:bg-gray-50 transition-all duration-200">
                <div class="flex items-center justify-between">
                  <div class="flex-1">
                    <div class="flex items-center">
                      <div class="w-12 h-12 bg-gradient-to-br from-[#07C160]/10 to-[#91D300]/10 rounded-full flex items-center justify-center mr-4">
                        <span class="text-[#07C160] font-bold text-lg">{{ account.account_name?.charAt(0)?.toUpperCase() || 'U' }}</span>
                      </div>
                      <div>
                        <p class="text-lg font-medium text-[#000000e6]">{{ account.account_name || '未知账户' }}</p>
                        <div class="flex items-center mt-1 space-x-4 text-sm text-[#7F7F7F]">
                          <span class="flex items-center">
                            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/>
                            </svg>
                            {{ account.database_count }} 个数据库
                          </span>
                          <span v-if="account.data_dir" class="flex items-center">
                            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                            </svg>
                            数据目录已找到
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                  <button @click="goToDecrypt(account)" 
                    class="inline-flex items-center px-4 py-2 bg-[#07C160] text-white rounded-lg font-medium hover:bg-[#06AD56] transition-all duration-200 text-sm">
                    <svg class="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"/>
                    </svg>
                    解密
                  </button>
                </div>
                
                <!-- 展开更多信息 -->
                <div class="mt-4 text-sm text-[#7F7F7F]">
                  <p v-if="account.data_dir" class="font-mono text-xs truncate">
                    数据路径：{{ account.data_dir }}
                  </p>
                </div>
              </div>
            </div>
          </div>
          
          <!-- 无账户提示 -->
          <div v-else class="bg-white rounded-2xl p-12 text-center">
            <svg class="w-16 h-16 mx-auto text-[#7F7F7F] mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <p class="text-lg text-[#7F7F7F]">未检测到微信账户数据</p>
          </div>
          </div>
        </div>
        
        <!-- 未检测状态 -->
        <div v-else class="bg-white rounded-2xl p-12 text-center">
          <svg class="w-16 h-16 mx-auto text-[#7F7F7F] mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <p class="text-lg text-[#7F7F7F] mb-4">暂无检测结果</p>
          <NuxtLink to="/" 
            class="inline-flex items-center px-6 py-3 bg-[#07C160] text-white rounded-lg font-medium hover:bg-[#06AD56] transition-colors">
            返回首页开始检测
          </NuxtLink>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useApi } from '~/composables/useApi'

const { detectWechat } = useApi()
const loading = ref(false)
const detectionResult = ref(null)

// 开始检测
const startDetection = async () => {
  loading.value = true
  
  try {
    const result = await detectWechat()
    detectionResult.value = result
  } catch (err) {
    console.error('检测过程中发生错误:', err)
    detectionResult.value = {
      status: 'error',
      error: err.message || '检测过程中出现错误'
    }
  } finally {
    loading.value = false
  }
}

// 跳转到解密页面并传递账户信息
const goToDecrypt = (account) => {
  // 将选中的账户信息存储到sessionStorage
  if (process.client && typeof window !== 'undefined') {
    sessionStorage.setItem('selectedAccount', JSON.stringify({
      account_name: account.account_name,
      data_dir: account.data_dir,
      database_count: account.database_count,
      databases: account.databases
    }))
  }
  // 跳转到解密页面
  navigateTo('/decrypt')
}

// 页面加载时自动检测
onMounted(() => {
  startDetection()
  
  // 调试：检查各元素高度
  if (process.client) {
    setTimeout(() => {
      const mainContainer = document.querySelector('.min-h-screen')
      const contentContainer = document.querySelector('.max-w-6xl')
      
      console.log('=== 高度调试信息 ===')
      console.log('视口高度:', window.innerHeight)
      console.log('主容器高度:', mainContainer?.scrollHeight)
      console.log('内容容器高度:', contentContainer?.scrollHeight)
      console.log('body滚动高度:', document.body.scrollHeight)
      console.log('documentElement滚动高度:', document.documentElement.scrollHeight)
      
      // 检查是否有滚动条
      const hasVerticalScrollbar = document.documentElement.scrollHeight > window.innerHeight
      console.log('是否有垂直滚动条:', hasVerticalScrollbar)
    }, 1000)
  }
})
</script>

<style scoped>
@keyframes fade-in {
  from {
    opacity: 0;
    transform: translateY(-20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.animate-fade-in {
  animation: fade-in 0.8s ease-out;
}

/* 网格背景 */
.bg-grid-pattern {
  background-image: 
    linear-gradient(rgba(7, 193, 96, 0.1) 1px, transparent 1px),
    linear-gradient(90deg, rgba(7, 193, 96, 0.1) 1px, transparent 1px);
  background-size: 50px 50px;
}
</style>