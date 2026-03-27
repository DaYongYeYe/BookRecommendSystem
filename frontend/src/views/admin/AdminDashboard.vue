<template>
  <div class="dashboard-page">
    <div class="card-grid">
      <el-card class="metric-card">
        <div class="metric-label">待审核稿件</div>
        <div class="metric-value">{{ cards.pending_manuscripts }}</div>
      </el-card>
      <el-card class="metric-card">
        <div class="metric-label">今日新增用户</div>
        <div class="metric-value">{{ cards.today_new_users }}</div>
      </el-card>
      <el-card class="metric-card">
        <div class="metric-label">违规评论总数</div>
        <div class="metric-value">{{ cards.violation_comments_total }}</div>
        <div class="metric-sub">今日新增违规：{{ cards.today_violation_comments }}</div>
      </el-card>
      <el-card class="metric-card">
        <div class="metric-label">今日发布图书</div>
        <div class="metric-value">{{ cards.today_published_books }}</div>
      </el-card>
      <el-card class="metric-card">
        <div class="metric-label">用户总量</div>
        <div class="metric-value">{{ cards.total_users }}</div>
      </el-card>
    </div>

    <el-card class="trend-card" v-loading="loading">
      <template #header>
        <div class="trend-header">
          <span>近 14 天发布与增长趋势</span>
          <el-button @click="loadOverview">刷新</el-button>
        </div>
      </template>

      <div class="trend-section">
        <h4>图书发布趋势</h4>
        <div class="bar-list">
          <div v-for="item in trend" :key="`pub-${item.date}`" class="bar-row">
            <div class="bar-date">{{ item.date.slice(5) }}</div>
            <div class="bar-track">
              <div class="bar-fill publish" :style="{ width: `${toPercent(item.published_books, maxPublished)}%` }"></div>
            </div>
            <div class="bar-value">{{ item.published_books }}</div>
          </div>
        </div>
      </div>

      <div class="trend-section">
        <h4>用户新增趋势</h4>
        <div class="bar-list">
          <div v-for="item in trend" :key="`user-${item.date}`" class="bar-row">
            <div class="bar-date">{{ item.date.slice(5) }}</div>
            <div class="bar-track">
              <div class="bar-fill users" :style="{ width: `${toPercent(item.new_users, maxNewUsers)}%` }"></div>
            </div>
            <div class="bar-value">{{ item.new_users }}</div>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getAdminDashboardOverview } from '../../api/admin'

type TrendItem = {
  date: string
  published_books: number
  new_users: number
}

const loading = ref(false)
const cards = ref({
  pending_manuscripts: 0,
  today_new_users: 0,
  violation_comments_total: 0,
  today_violation_comments: 0,
  today_published_books: 0,
  total_users: 0,
})
const trend = ref<TrendItem[]>([])

const maxPublished = computed(() => {
  const values = trend.value.map((item) => item.published_books)
  return Math.max(1, ...values, 1)
})

const maxNewUsers = computed(() => {
  const values = trend.value.map((item) => item.new_users)
  return Math.max(1, ...values, 1)
})

const toPercent = (value: number, max: number) => {
  if (max <= 0) return 0
  if (value <= 0) return 0
  return Math.min(100, Math.max(4, Math.round((value / max) * 100)))
}

const loadOverview = async () => {
  loading.value = true
  try {
    const res = await getAdminDashboardOverview()
    cards.value = res.cards || cards.value
    trend.value = res.trend?.series || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载仪表盘数据失败')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadOverview()
})
</script>

<style scoped>
.dashboard-page {
  padding: 20px;
}

.card-grid {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  margin-bottom: 16px;
}

.metric-card {
  min-height: 110px;
}

.metric-label {
  color: #606266;
  font-size: 13px;
}

.metric-value {
  margin-top: 12px;
  font-size: 30px;
  font-weight: 700;
  line-height: 1;
}

.metric-sub {
  margin-top: 10px;
  color: #909399;
  font-size: 12px;
}

.trend-card {
  margin-top: 4px;
}

.trend-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.trend-section + .trend-section {
  margin-top: 20px;
}

.trend-section h4 {
  margin: 0 0 10px 0;
  font-size: 14px;
  color: #303133;
}

.bar-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.bar-row {
  display: grid;
  grid-template-columns: 60px 1fr 40px;
  align-items: center;
  gap: 10px;
}

.bar-date {
  color: #909399;
  font-size: 12px;
}

.bar-track {
  height: 10px;
  border-radius: 999px;
  background: #f0f2f5;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  border-radius: 999px;
}

.bar-fill.publish {
  background: linear-gradient(90deg, #67c23a, #95d475);
}

.bar-fill.users {
  background: linear-gradient(90deg, #409eff, #79bbff);
}

.bar-value {
  text-align: right;
  font-size: 12px;
  color: #303133;
}
</style>
