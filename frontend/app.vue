<template>
  <div class="min-h-screen bg-gradient-to-br from-green-50 via-emerald-50 to-green-100">
    <NuxtPage />
  </div>
</template>

<style>
/* 页面过渡动画 - 渐显渐隐效果 */
.page-enter-active,
.page-leave-active {
  transition: opacity 0.3s ease;
}

.page-enter-from,
.page-leave-to {
  opacity: 0;
}
</style>