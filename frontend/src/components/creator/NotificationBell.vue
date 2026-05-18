<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { getCreatorNotifications, markCreatorNotificationRead, type CreatorNotificationItem } from '@/api/creator'

const notifications = ref<CreatorNotificationItem[]>([])
const loading = ref(false)
const popoverVisible = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

const unreadCount = computed(() => notifications.value.filter((n) => !n.read).length)

async function loadNotifications() {
  try {
    const res = await getCreatorNotifications({ limit: 20 })
    notifications.value = res.items || []
  } catch {
    // Silent fail for polling
  }
}

async function onNotificationClick(item: CreatorNotificationItem) {
  if (!item.read) {
    try {
      await markCreatorNotificationRead(item.id)
      item.read = true
    } catch {
      // ignore
    }
  }
}

function formatTime(time: string) {
  if (!time) return ''
  const date = new Date(time)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return `${Math.floor(diff / 60000)} 分钟前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)} 小时前`
  return `${date.getMonth() + 1}/${date.getDate()}`
}

onMounted(() => {
  loadNotifications()
  pollTimer = setInterval(loadNotifications, 60000)
})

onBeforeUnmount(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<template>
  <el-popover
    v-model:visible="popoverVisible"
    placement="bottom-start"
    :width="360"
    trigger="click"
  >
    <template #reference>
      <button class="bell-btn" :class="{ 'has-unread': unreadCount > 0 }">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
        </svg>
        <span v-if="unreadCount > 0" class="bell-badge">{{ unreadCount > 9 ? '9+' : unreadCount }}</span>
      </button>
    </template>

    <div class="notification-panel">
      <div class="notification-header">
        <span class="notification-title">消息通知</span>
        <span v-if="unreadCount > 0" class="notification-count">{{ unreadCount }} 条未读</span>
      </div>

      <div v-if="loading" class="notification-empty">加载中...</div>
      <div v-else-if="!notifications.length" class="notification-empty">暂无通知</div>
      <div v-else class="notification-list">
        <div
          v-for="item in notifications"
          :key="item.id"
          class="notification-item"
          :class="{ unread: !item.read }"
          @click="onNotificationClick(item)"
        >
          <div class="notification-dot" v-if="!item.read" />
          <div class="notification-content">
            <div class="notification-msg">{{ item.message }}</div>
            <div class="notification-time">{{ formatTime(item.created_at) }}</div>
          </div>
        </div>
      </div>
    </div>
  </el-popover>
</template>

<style scoped>
.bell-btn {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: 12px;
  border: 1px solid #d6d3d1;
  background: #fff;
  color: #57534e;
  cursor: pointer;
  transition: all 0.2s;
}

.bell-btn:hover {
  background: #f5f5f4;
  color: #1c1917;
}

.bell-btn.has-unread {
  border-color: #f59e0b;
  color: #f59e0b;
}

.bell-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  min-width: 18px;
  height: 18px;
  border-radius: 9px;
  background: #ef4444;
  color: #fff;
  font-size: 11px;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 4px;
  line-height: 1;
}

.notification-panel {
  max-height: 400px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.notification-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: 12px;
  border-bottom: 1px solid #e7e5e4;
  margin-bottom: 8px;
}

.notification-title {
  font-weight: 600;
  font-size: 14px;
  color: #1c1917;
}

.notification-count {
  font-size: 12px;
  color: #f59e0b;
}

.notification-empty {
  padding: 24px 0;
  text-align: center;
  color: #a8a29e;
  font-size: 13px;
}

.notification-list {
  overflow-y: auto;
  max-height: 320px;
}

.notification-item {
  display: flex;
  gap: 10px;
  padding: 10px 8px;
  border-radius: 10px;
  cursor: pointer;
  transition: background 0.15s;
}

.notification-item:hover {
  background: #f5f5f4;
}

.notification-item.unread {
  background: #fffbeb;
}

.notification-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #f59e0b;
  flex-shrink: 0;
  margin-top: 6px;
}

.notification-content {
  flex: 1;
  min-width: 0;
}

.notification-msg {
  font-size: 13px;
  color: #1c1917;
  line-height: 1.5;
}

.notification-time {
  font-size: 11px;
  color: #a8a29e;
  margin-top: 4px;
}
</style>
