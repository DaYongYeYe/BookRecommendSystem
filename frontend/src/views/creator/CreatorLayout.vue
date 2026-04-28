<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { USER_PROFILE_HUB_ROUTE_NAME } from '@/constants/routes'

const route = useRoute()
const router = useRouter()

const navItems = [
  {
    label: '我的作品',
    path: '/creator/works',
    matches: (path: string) => path.startsWith('/creator/works') || path.startsWith('/creator/books/'),
  },
  {
    label: '稿件与章节',
    path: '/creator/manuscripts',
    matches: (path: string) => path.startsWith('/creator/manuscripts'),
  },
  {
    label: '数据总览',
    path: '/creator/dashboard',
    matches: (path: string) => path.startsWith('/creator/dashboard'),
  },
]

const activePath = computed(() => {
  const current = navItems.find((item) => item.matches(route.path))
  return current?.path || '/creator/works'
})
</script>

<template>
  <div class="creator-shell">
    <aside class="creator-sidebar">
      <button class="brand" @click="router.push('/creator-center')">
        <span class="brand-mark">C</span>
        <span>
          <strong>创作中心</strong>
          <small>作品、章节、审核与创作数据统一管理</small>
        </span>
      </button>

      <nav class="creator-nav">
        <button
          v-for="item in navItems"
          :key="item.path"
          class="nav-item"
          :class="{ active: activePath === item.path }"
          @click="router.push(item.path)"
        >
          {{ item.label }}
        </button>
      </nav>

      <section class="boundary-card">
        <p class="boundary-label">创作者工作台</p>
        <p class="boundary-title">作品基础资料、章节草稿、审核流转和创作分析都在这里独立承载，不打断读者端浏览路径。</p>
      </section>

      <div class="utility-actions">
        <button class="utility-button" @click="router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })">账号资料</button>
        <button class="utility-button" @click="router.push('/')">返回阅读端</button>
      </div>
    </aside>

    <main class="creator-main">
      <router-view />
    </main>
  </div>
</template>

<style scoped>
.creator-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  background:
    radial-gradient(circle at top left, rgba(190, 242, 100, 0.18), transparent 28%),
    linear-gradient(180deg, #f5f5f4 0%, #fafaf9 100%);
}

.creator-sidebar {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 28px 20px;
  border-right: 1px solid #e7e5e4;
  background: rgba(255, 255, 255, 0.86);
  backdrop-filter: blur(12px);
}

.brand {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 0;
  border: 0;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.brand span {
  display: block;
}

.brand strong {
  display: block;
  font-size: 18px;
  color: #1c1917;
}

.brand small {
  color: #78716c;
}

.brand-mark {
  width: 44px;
  height: 44px;
  border-radius: 16px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: #1c1917;
  color: #d9f99d;
  font-weight: 700;
}

.creator-nav {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.nav-item {
  width: 100%;
  border: 1px solid #d6d3d1;
  border-radius: 16px;
  padding: 12px 14px;
  background: #fff;
  color: #44403c;
  text-align: left;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.nav-item.active {
  border-color: #1c1917;
  background: #1c1917;
  color: #fff;
}

.boundary-card {
  margin-top: auto;
  border-radius: 20px;
  padding: 16px;
  background: linear-gradient(135deg, #ecfccb 0%, #d9f99d 100%);
  color: #365314;
}

.boundary-label {
  margin: 0 0 8px;
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.boundary-title {
  margin: 0;
  line-height: 1.7;
  font-size: 13px;
}

.utility-actions {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.utility-button {
  width: 100%;
  border: 1px solid #d6d3d1;
  border-radius: 16px;
  padding: 12px 14px;
  background: #fafaf9;
  color: #57534e;
  text-align: left;
  cursor: pointer;
}

.creator-main {
  padding: 24px;
}

@media (max-width: 960px) {
  .creator-shell {
    grid-template-columns: 1fr;
  }

  .creator-sidebar {
    border-right: 0;
    border-bottom: 1px solid #e7e5e4;
  }
}
</style>
