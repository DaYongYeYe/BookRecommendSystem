<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getCreatorBookAnalytics, type CreatorBookAnalyticsItem } from '@/api/creator'
import { useCreatorPenName } from '@/composables/useCreatorPenName'
import { USER_PROFILE_HUB_ROUTE_NAME } from '@/constants/routes'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart, LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent, TitleComponent } from 'echarts/components'

use([CanvasRenderer, PieChart, BarChart, LineChart, GridComponent, TooltipComponent, LegendComponent, TitleComponent])

const router = useRouter()
const loading = ref(false)
const items = ref<CreatorBookAnalyticsItem[]>([])
const timeRange = ref<'7d' | '30d' | 'all'>('30d')
const { penNameDialogVisible, penNameForm, saving, loadCreatorProfile, savePenName, hasPenName } = useCreatorPenName()

const topBooks = computed(() => [...items.value].sort((a, b) => b.metrics.reads - a.metrics.reads).slice(0, 5))

const total = computed(() =>
  items.value.reduce(
    (acc, item) => {
      acc.impressions += item.metrics.impressions
      acc.reads += item.metrics.reads
      acc.readUsers += item.metrics.read_users
      return acc
    },
    { impressions: 0, reads: 0, readUsers: 0 }
  )
)

const conversionRate = computed(() => {
  if (!total.value.impressions) return 0
  return ((total.value.reads / total.value.impressions) * 100).toFixed(1)
})

// Aggregated geo distribution
const geoAgg = computed(() => {
  const map: Record<string, number> = {}
  for (const item of items.value) {
    for (const g of item.geo_distribution || []) {
      map[g.label] = (map[g.label] || 0) + g.count
    }
  }
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([label, value]) => ({ name: label, value }))
})

// Aggregated age distribution
const ageAgg = computed(() => {
  const map: Record<string, number> = {}
  for (const item of items.value) {
    for (const a of item.age_distribution || []) {
      map[a.label] = (map[a.label] || 0) + a.count
    }
  }
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([label, value]) => ({ name: label, value }))
})

// Top books chart
const topBooksChartOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 120, right: 20, top: 10, bottom: 20 },
  xAxis: { type: 'value' },
  yAxis: {
    type: 'category',
    data: topBooks.value.map((b) => b.title).reverse(),
    axisLabel: { width: 100, overflow: 'truncate' },
  },
  series: [
    {
      name: '阅读量',
      type: 'bar',
      data: topBooks.value.map((b) => b.metrics.reads).reverse(),
      itemStyle: { borderRadius: [0, 4, 4, 0], color: '#1c1917' },
    },
  ],
}))

// Geo pie chart
const geoChartOption = computed(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  series: [
    {
      type: 'pie',
      radius: ['40%', '70%'],
      avoidLabelOverlap: true,
      itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
      label: { show: true, fontSize: 12 },
      data: geoAgg.value,
    },
  ],
}))

// Age bar chart
const ageChartOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 60, right: 20, top: 10, bottom: 30 },
  xAxis: { type: 'category', data: ageAgg.value.map((a) => a.name) },
  yAxis: { type: 'value' },
  series: [
    {
      type: 'bar',
      data: ageAgg.value.map((a) => a.value),
      itemStyle: { borderRadius: [4, 4, 0, 0], color: '#84cc16' },
    },
  ],
}))

// Dynamic suggestions
const suggestions = computed(() => {
  const tips: { title: string; desc: string; level: 'info' | 'warning' | 'success' }[] = []

  if (total.value.impressions > 0 && total.value.reads / total.value.impressions < 0.05) {
    tips.push({
      title: '点击率偏低',
      desc: '曝光量高但阅读率低于 5%，建议优化封面图和作品简介，提升读者点击意愿。',
      level: 'warning',
    })
  }

  if (total.value.reads > 0 && total.value.readUsers / total.value.reads > 0.8) {
    tips.push({
      title: '回头读者较少',
      desc: '阅读用户占比高但重复阅读少，建议优化章节结尾悬念，提升读者追更意愿。',
      level: 'info',
    })
  }

  if (topBooks.value.length > 0) {
    tips.push({
      title: '头部作品',
      desc: `当前阅读量最高的作品是《${topBooks.value[0].title}》，建议保持稳定更新节奏。`,
      level: 'success',
    })
  }

  if (tips.length === 0) {
    tips.push({
      title: '持续创作',
      desc: '保持稳定的更新频率，完善作品资料，是提升阅读量的关键。',
      level: 'info',
    })
  }

  return tips
})

async function loadData() {
  loading.value = true
  try {
    const res = await getCreatorBookAnalytics({ limit: 100 })
    items.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载创作数据失败')
  } finally {
    loading.value = false
  }
}

async function bootstrap() {
  await loadCreatorProfile()
  await loadData()
}

onMounted(bootstrap)
</script>

<template>
  <div class="dashboard-page">
    <div class="topbar">
      <div>
        <h2>创作数据看板</h2>
        <p class="topbar-desc">追踪作品表现，优化创作策略。</p>
      </div>
      <div class="actions">
        <el-radio-group v-model="timeRange" size="small">
          <el-radio-button value="7d">近 7 天</el-radio-button>
          <el-radio-button value="30d">近 30 天</el-radio-button>
          <el-radio-button value="all">全部</el-radio-button>
        </el-radio-group>
        <el-button type="primary" :disabled="!hasPenName()" @click="router.push('/creator/works')">我的作品</el-button>
      </div>
    </div>

    <el-alert
      v-if="!hasPenName()"
      title="进入创作者端前需要先设置笔名，作品和章节会以该笔名展示作者身份。"
      type="warning"
      show-icon
      :closable="false"
      class="notice"
    />

    <!-- KPI cards -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">总曝光量</div>
        <div class="kpi-value">{{ total.impressions.toLocaleString() }}</div>
        <div class="kpi-sub">作品被推荐展示的次数</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">总阅读量</div>
        <div class="kpi-value">{{ total.reads.toLocaleString() }}</div>
        <div class="kpi-sub">读者实际打开阅读的次数</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">阅读用户数</div>
        <div class="kpi-value">{{ total.readUsers.toLocaleString() }}</div>
        <div class="kpi-sub">去重后的独立读者数量</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">点击转化率</div>
        <div class="kpi-value">{{ conversionRate }}%</div>
        <div class="kpi-sub">曝光到阅读的转化比例</div>
      </div>
    </div>

    <!-- Charts row -->
    <div class="charts-row">
      <el-card shadow="never" class="chart-card">
        <template #header>
          <div class="card-header">作品阅读排行</div>
        </template>
        <v-chart v-if="topBooks.length" :option="topBooksChartOption" style="height: 240px" autoresize />
        <div v-else class="empty-chart">暂无数据</div>
      </el-card>

      <el-card shadow="never" class="chart-card">
        <template #header>
          <div class="card-header">读者地域分布</div>
        </template>
        <v-chart v-if="geoAgg.length" :option="geoChartOption" style="height: 240px" autoresize />
        <div v-else class="empty-chart">暂无数据</div>
      </el-card>
    </div>

    <div class="charts-row">
      <el-card shadow="never" class="chart-card">
        <template #header>
          <div class="card-header">读者年龄分布</div>
        </template>
        <v-chart v-if="ageAgg.length" :option="ageChartOption" style="height: 240px" autoresize />
        <div v-else class="empty-chart">暂无数据</div>
      </el-card>

      <!-- Dynamic suggestions -->
      <el-card shadow="never" class="chart-card">
        <template #header>
          <div class="card-header">创作优化建议</div>
        </template>
        <div class="suggestions-list">
          <div v-for="(tip, i) in suggestions" :key="i" :class="['suggestion-item', tip.level]">
            <div class="suggestion-title">{{ tip.title }}</div>
            <div class="suggestion-desc">{{ tip.desc }}</div>
          </div>
        </div>
      </el-card>
    </div>

    <!-- Per-book table -->
    <el-card class="panel" shadow="never">
      <template #header>
        <div class="card-header">每本作品的阅读表现</div>
      </template>
      <el-table :data="items" v-loading="loading" border>
        <el-table-column prop="title" label="书名" min-width="200" />
        <el-table-column prop="metrics.impressions" label="曝光量" width="100" sortable />
        <el-table-column prop="metrics.reads" label="阅读量" width="100" sortable />
        <el-table-column prop="metrics.read_users" label="阅读用户数" width="120" sortable />
        <el-table-column prop="metrics.avg_read_duration_label" label="平均阅读时长" width="130" />
        <el-table-column label="地域 Top3" min-width="180">
          <template #default="{ row }">
            {{ (row.geo_distribution || []).slice(0, 3).map((g: any) => `${g.label} ${g.percent}%`).join(' / ') || '-' }}
          </template>
        </el-table-column>
        <el-table-column label="年龄 Top3" min-width="180">
          <template #default="{ row }">
            {{ (row.age_distribution || []).slice(0, 3).map((a: any) => `${a.label} ${a.percent}%`).join(' / ') || '-' }}
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog
      v-model="penNameDialogVisible"
      title="先设置创作者笔名"
      width="420px"
      :close-on-click-modal="false"
      :show-close="hasPenName()"
    >
      <el-form label-position="top">
        <el-form-item label="笔名">
          <el-input v-model="penNameForm.pen_name" maxlength="80" placeholder="例如：青山、北舟、林间夜雪" />
        </el-form-item>
        <div class="dialog-tip">笔名会显示在作品详情页与阅读页中，也会作为稿件和作品管理的默认作者名。</div>
      </el-form>
      <template #footer>
        <el-button @click="router.push({ name: USER_PROFILE_HUB_ROUTE_NAME })">去个人资料页</el-button>
        <el-button type="primary" :loading="saving" @click="savePenName">保存笔名</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.dashboard-page {
  padding: 20px;
}

.topbar {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 20px;
  gap: 12px;
}

.topbar-desc {
  margin-top: 4px;
  font-size: 13px;
  color: #78716c;
}

.actions {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
}

.notice {
  margin-bottom: 16px;
}

/* KPI */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 16px;
}

.kpi-card {
  background: #fff;
  border: 1px solid #e7e5e4;
  border-radius: 16px;
  padding: 20px;
}

.kpi-label {
  color: #78716c;
  font-size: 13px;
  margin-bottom: 8px;
}

.kpi-value {
  font-size: 28px;
  font-weight: 700;
  color: #1c1917;
  line-height: 1;
}

.kpi-sub {
  margin-top: 8px;
  font-size: 12px;
  color: #a8a29e;
}

/* Charts */
.charts-row {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
  margin-bottom: 16px;
}

.chart-card {
  min-height: 300px;
}

.card-header {
  font-weight: 600;
  font-size: 15px;
  color: #1c1917;
}

.empty-chart {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 200px;
  color: #a8a29e;
  font-size: 13px;
}

/* Suggestions */
.suggestions-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.suggestion-item {
  padding: 14px;
  border-radius: 12px;
  border: 1px solid #e7e5e4;
}

.suggestion-item.warning {
  border-color: #fbbf24;
  background: #fffbeb;
}

.suggestion-item.success {
  border-color: #34d399;
  background: #ecfdf5;
}

.suggestion-item.info {
  border-color: #93c5fd;
  background: #eff6ff;
}

.suggestion-title {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 4px;
}

.suggestion-desc {
  font-size: 13px;
  color: #57534e;
  line-height: 1.5;
}

.panel {
  margin-bottom: 16px;
}

.dialog-tip {
  color: #6b7280;
  font-size: 13px;
  line-height: 1.6;
}

@media (max-width: 960px) {
  .kpi-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .charts-row {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .kpi-grid {
    grid-template-columns: 1fr;
  }
}
</style>
