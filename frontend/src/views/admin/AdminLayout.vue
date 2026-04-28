<template>
  <div class="admin-layout">
    <el-container class="admin-container">
      <el-aside width="220px" class="aside">
        <div class="brand">后台管理系统</div>
        <el-menu :default-active="activeMenu" router class="menu">
          <el-menu-item index="/manage/dashboard">
            <el-icon><House /></el-icon>
            <span>首页</span>
          </el-menu-item>
          <el-menu-item index="/manage/comments">
            <el-icon><ChatDotRound /></el-icon>
            <span>评论管理</span>
          </el-menu-item>
          <el-menu-item index="/manage/books">
            <el-icon><Reading /></el-icon>
            <span>书本管理</span>
          </el-menu-item>
          <el-menu-item index="/manage/works/review">
            <el-icon><Reading /></el-icon>
            <span>作品审核</span>
          </el-menu-item>
          <el-menu-item index="/manage/manuscripts/review">
            <el-icon><Document /></el-icon>
            <span>稿件审核</span>
          </el-menu-item>
          <el-menu-item index="/manage/chapters/review">
            <el-icon><Document /></el-icon>
            <span>章节审核</span>
          </el-menu-item>
          <el-menu-item index="/manage/users">
            <el-icon><User /></el-icon>
            <span>用户管理</span>
          </el-menu-item>
          <el-sub-menu v-if="showRbacMenu" index="/manage/rbac">
            <template #title>
              <el-icon><Lock /></el-icon>
              <span>权限管理</span>
            </template>
            <el-menu-item index="/manage/rbac/roles">角色管理</el-menu-item>
            <el-menu-item index="/manage/rbac/permissions">权限管理</el-menu-item>
            <el-menu-item index="/manage/rbac/role-permissions">角色权限分配</el-menu-item>
            <el-menu-item index="/manage/rbac/user-roles">用户角色分配</el-menu-item>
          </el-sub-menu>
        </el-menu>
      </el-aside>

      <el-container>
        <el-header class="header">
          <div class="header-title">{{ pageTitle }}</div>
          <el-button text type="danger" @click="onLogout">退出登录</el-button>
        </el-header>
        <el-main class="main">
          <router-view />
        </el-main>
      </el-container>
    </el-container>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ChatDotRound, Document, House, Lock, Reading, User } from '@element-plus/icons-vue'
import { clearToken } from '../../api/request'
import { isSuperAdminToken } from '../../utils/auth'

const route = useRoute()
const router = useRouter()

const activeMenu = computed(() => route.path)
const showRbacMenu = computed(() => isSuperAdminToken())

const pageTitle = computed(() => {
  if (route.path.startsWith('/manage/comments')) return '评论管理'
  if (route.path.startsWith('/manage/books')) return '书本管理'
  if (route.path.startsWith('/manage/works/review')) return '作品审核'
  if (route.path.startsWith('/manage/manuscripts/review')) return '稿件审核'
  if (route.path.startsWith('/manage/chapters/review')) return '章节审核'
  if (route.path.startsWith('/manage/users')) return '用户管理'
  if (route.path.startsWith('/manage/rbac/roles')) return '角色管理'
  if (route.path.startsWith('/manage/rbac/permissions')) return '权限管理'
  if (route.path.startsWith('/manage/rbac/role-permissions')) return '角色权限分配'
  if (route.path.startsWith('/manage/rbac/user-roles')) return '用户角色分配'
  return '首页'
})

const onLogout = () => {
  clearToken()
  router.push('/manage/login')
}
</script>

<style scoped>
.admin-layout {
  height: 100vh;
  background: #f4f6f8;
}

.admin-container {
  height: 100%;
}

.aside {
  background: #ffffff;
  border-right: 1px solid #ebeef5;
}

.brand {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  border-bottom: 1px solid #ebeef5;
}

.menu {
  border-right: none;
}

.header {
  background: #ffffff;
  border-bottom: 1px solid #ebeef5;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.header-title {
  font-size: 18px;
  font-weight: 600;
}

.main {
  padding: 0;
}
</style>
