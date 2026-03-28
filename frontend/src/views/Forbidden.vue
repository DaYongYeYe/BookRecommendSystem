<template>
  <div class="forbidden-page">
    <el-result icon="warning" title="403" sub-title="当前账号没有访问该页面的权限">
      <template #extra>
        <el-button type="primary" @click="goBack">返回管理首页</el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()

const goBack = () => {
  router.push('/manage/dashboard')
}
</script>

<style scoped>
.forbidden-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f7fa;
  padding: 24px;
}
</style>
