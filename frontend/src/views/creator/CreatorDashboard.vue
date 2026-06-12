<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  getCreatorBookAnalytics,
  getCreatorOperations,
  type CreatorBookAnalyticsItem,
  type CreatorBookAnalyticsTrendItem,
  type CreatorOperationsResponse,
  type CreatorOperationTrendItem,
} from '@/api/creator'
import { useCreatorPenName } from '@/composables/useCreatorPenName'
import { USER_PROFILE_HUB_ROUTE_NAME } from '@/constants/routes'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, LineChart, PieChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'

use([CanvasRenderer, BarChart, LineChart, PieChart, GridComponent, LegendComponent, TooltipComponent])

const router = useRouter()
const loading = ref(false)
const items = ref<CreatorBookAnalyticsItem[]>([])
const trend = ref<CreatorBookAnalyticsTrendItem[]>([])
const operationTrend = ref<CreatorOperationTrendItem[]>([])
const operations = ref<CreatorOperationsResponse | null>(null)
const timeRange = ref<'7d' | '30d' | '90d'>('30d')
const { penNameDialogVisible, penNameForm, saving, loadCreatorProfile, savePenName, hasPenName } = useCreatorPenName()

const rangeDays = computed(() => {
  if (timeRange.value === '7d') return 7
  if (timeRange.value === '90d') return 90
  return 30
})

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
  if (!total.value.impressions) return '0.0'
  return ((total.value.reads / total.value.impressions) * 100).toFixed(1)
})

const operationSummary = computed(() => operations.value?.summary)
const income = computed(() => operations.value?.income)
const fans = computed(() => operations.value?.fans)
const calendar = computed(() => operations.value?.calendar || [])
const assist = computed(() => operations.value?.assist)

const money = (value?: number | null) => `¥${Number(value || 0).toFixed(2)}`

const shortDate = (value?: string | null) => {
  if (!value) return '-'
  return value.slice(5, 10)
}

const geoAgg = computed(() => {
  const map: Record<string, number> = {}
  for (const item of items.value) {
    for (const geo of item.geo_distribution || []) {
      map[geo.label] = (map[geo.label] || 0) + geo.count
    }
  }
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }))
})

const ageAgg = computed(() => {
  const map: Record<string, number> = {}
  for (const item of items.value) {
    for (const age of item.age_distribution || []) {
      map[age.label] = (map[age.label] || 0) + age.count
    }
  }
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }))
})

const trendChartOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  legend: { top: 0 },
  grid: { left: 44, right: 24, top: 42, bottom: 32 },
  xAxis: { type: 'category', data: trend.value.map((item) => item.date.slice(5)) },
  yAxis: { type: 'value' },
  series: [
    {
      name: '曝光',
      type: 'line',
      smooth: true,
      data: trend.value.map((item) => item.impressions),
      color: '#2563eb',
    },
    {
      name: '阅读',
      type: 'line',
      smooth: true,
      data: trend.value.map((item) => item.reads),
      color: '#16a34a',
    },
    {
      name: '读者',
      type: 'bar',
      data: trend.value.map((item) => item.read_users),
      color: '#f59e0b',
    },
  ],
}))

const topBooksChartOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 120, right: 20, top: 10, bottom: 20 },
  xAxis: { type: 'value' },
  yAxis: {
    type: 'category',
    data: topBooks.value.map((book) => book.title).reverse(),
    axisLabel: { width: 100, overflow: 'truncate' },
  },
  series: [
    {
      name: '阅读量',
      type: 'bar',
      data: topBooks.value.map((book) => book.metrics.reads).reverse(),
      itemStyle: { borderRadius: [0, 4, 4, 0], color: '#1c1917' },
    },
  ],
}))

const geoChartOption = computed(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  series: [
    {
      type: 'pie',
      radius: ['42%', '70%'],
      itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
      data: geoAgg.value,
    },
  ],
}))

const ageChartOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 54, right: 20, top: 10, bottom: 30 },
  xAxis: { type: 'category', data: ageAgg.value.map((item) => item.name) },
  yAxis: { type: 'value' },
  series: [
    {
      type: 'bar',
      data: ageAgg.value.map((item) => item.value),
      itemStyle: { borderRadius: [4, 4, 0, 0], color: '#84cc16' },
    },
  ],
}))

const operationTrendOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  legend: { top: 0 },
  grid: { left: 46, right: 24, top: 42, bottom: 32 },
  xAxis: { type: 'category', data: operationTrend.value.map((item) => item.date.slice(5)) },
  yAxis: [
    { type: 'value', name: '互动' },
    { type: 'value', name: '完读率', axisLabel: { formatter: '{value}%' } },
  ],
  series: [
    {
      name: '追更收藏',
      type: 'bar',
      data: operationTrend.value.map((item) => item.favorites),
      color: '#0f766e',
    },
    {
      name: '读者反馈',
      type: 'bar',
      data: operationTrend.value.map((item) => item.comments),
      color: '#f97316',
    },
    {
      name: '完读率',
      type: 'line',
      yAxisIndex: 1,
      smooth: true,
      data: operationTrend.value.map((item) => item.completion_rate),
      color: '#7c3aed',
    },
  ],
}))

const suggestions = computed(() => {
  const tips: Array<{ title: string; desc: string; level: 'info' | 'warning' | 'success' }> = []
  if (total.value.impressions > 0 && total.value.reads / total.value.impressions < 0.05) {
    tips.push({
      title: '点击转化偏低',
      desc: '曝光较高但阅读转化低于 5%，可以优先优化封面、简介和推荐语。',
      level: 'warning',
    })
  }
  if (topBooks.value.length > 0) {
    tips.push({
      title: '头部作品稳定输出',
      desc: `当前阅读量最高的是《${topBooks.value[0].title}》，保持更新节奏能继续放大优势。`,
      level: 'success',
    })
  }
  if (!tips.length) {
    tips.push({
      title: '持续积累数据',
      desc: '保持稳定更新并完善作品资料，趋势数据会逐步给出更明确的优化方向。',
      level: 'info',
    })
  }
  return tips
})

async function loadData() {
  loading.value = true
  try {
    const [analyticsRes, operationsRes] = await Promise.all([
      getCreatorBookAnalytics({ limit: 100, days: rangeDays.value }),
      getCreatorOperations({ days: rangeDays.value }),
    ])
    items.value = analyticsRes.items || []
    trend.value = analyticsRes.trend?.series || []
    operations.value = operationsRes
    operationTrend.value = operationsRes.trend?.series || []
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

watch(timeRange, () => {
  loadData()
})

onMounted(bootstrap)
</script>

<template>
  <div class="dashboard-page">
    <div class="topbar">
      <div>
        <h2>创作数据看板</h2>
        <p class="topbar-desc">观察作品曝光、阅读和读者画像，判断下一步创作和运营重点。</p>
      </div>
      <div class="actions">
        <el-radio-group v-model="timeRange" size="small">
          <el-radio-button value="7d">近 7 天</el-radio-button>
          <el-radio-button value="30d">近 30 天</el-radio-button>
          <el-radio-button value="90d">近 90 天</el-radio-button>
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

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">总曝光量</div>
        <div class="kpi-value">{{ total.impressions.toLocaleString() }}</div>
        <div class="kpi-sub">作品被推荐展示的次数</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">总阅读量</div>
        <div class="kpi-value">{{ total.reads.toLocaleString() }}</div>
        <div class="kpi-sub">读者打开阅读的次数</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">阅读用户数</div>
        <div class="kpi-value">{{ total.readUsers.toLocaleString() }}</div>
        <div class="kpi-sub">去重后的独立读者数</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">点击转化率</div>
        <div class="kpi-value">{{ conversionRate }}%</div>
        <div class="kpi-sub">曝光到阅读的转化比例</div>
      </div>
    </div>

    <div class="kpi-grid operation-kpis">
      <div class="kpi-card accent">
        <div class="kpi-label">追更收藏</div>
        <div class="kpi-value">{{ (operationSummary?.favorites || 0).toLocaleString() }}</div>
        <div class="kpi-sub">读者加入书架形成的稳定关注</div>
      </div>
      <div class="kpi-card accent">
        <div class="kpi-label">读者反馈</div>
        <div class="kpi-value">{{ (operationSummary?.comments || 0).toLocaleString() }}</div>
        <div class="kpi-sub">评论与公开书评汇总</div>
      </div>
      <div class="kpi-card accent">
        <div class="kpi-label">完读率</div>
        <div class="kpi-value">{{ operationSummary?.completion_rate || 0 }}%</div>
        <div class="kpi-sub">阅读进度达到 80% 的读者占比</div>
      </div>
      <div class="kpi-card accent">
        <div class="kpi-label">收益模拟</div>
        <div class="kpi-value">{{ money(operationSummary?.simulated_income) }}</div>
        <div class="kpi-sub">广告、订阅与勤更奖励的估算</div>
      </div>
    </div>

    <el-card class="panel" shadow="never" v-loading="loading">
      <template #header>
        <div class="card-header">作品数据趋势</div>
      </template>
      <v-chart v-if="trend.length" :option="trendChartOption" style="height: 320px" autoresize />
      <div v-else class="empty-chart">暂无趋势数据</div>
    </el-card>

    <el-card class="panel" shadow="never" v-loading="loading">
      <template #header>
        <div class="card-header">经营互动趋势</div>
      </template>
      <v-chart v-if="operationTrend.length" :option="operationTrendOption" style="height: 300px" autoresize />
      <div v-else class="empty-chart">暂无互动趋势数据</div>
    </el-card>

    <div class="operation-grid">
      <el-card shadow="never" class="operation-card income-card">
        <template #header>
          <div class="card-header">收益模拟与激励规则</div>
        </template>
        <div class="income-summary">
          <div>
            <span>总模拟收益</span>
            <strong>{{ money(income?.total) }}</strong>
          </div>
          <div>
            <span>广告分成</span>
            <strong>{{ money(income?.ad_share) }}</strong>
          </div>
          <div>
            <span>订阅收入</span>
            <strong>{{ money(income?.subscription) }}</strong>
          </div>
          <div>
            <span>勤更奖励</span>
            <strong>{{ money(income?.bonus) }}</strong>
          </div>
        </div>
        <div class="rule-list">
          <div v-for="rule in income?.rules || []" :key="rule.title" class="rule-item">
            <div class="rule-title">{{ rule.title }}</div>
            <div class="rule-desc">{{ rule.desc }}</div>
          </div>
        </div>
      </el-card>

      <el-card shadow="never" class="operation-card">
        <template #header>
          <div class="card-header">章节发布日历</div>
        </template>
        <div v-if="calendar.length" class="calendar-list">
          <div v-for="item in calendar" :key="item.id" class="calendar-item">
            <div class="calendar-date">{{ shortDate(item.date) }}</div>
            <div class="calendar-main">
              <div class="calendar-title">{{ item.title }}</div>
              <div class="calendar-meta">
                <el-tag size="small" :type="item.status === 'published' ? 'success' : item.status === 'rejected' ? 'danger' : 'warning'">
                  {{ item.status_label }}
                </el-tag>
                <span>{{ item.source }}</span>
                <span v-if="item.note">{{ item.note }}</span>
              </div>
            </div>
          </div>
        </div>
        <div v-else class="empty-list">暂无稿件或章节计划</div>
      </el-card>
    </div>

    <div class="operation-grid">
      <el-card shadow="never" class="operation-card">
        <template #header>
          <div class="card-header">粉丝互动</div>
        </template>
        <div class="reader-list">
          <div v-for="reader in fans?.top_readers || []" :key="reader.user_id" class="reader-item">
            <div>
              <strong>{{ reader.username }}</strong>
              <span>阅读 {{ reader.book_count }} 本作品</span>
            </div>
            <el-progress :percentage="Math.min(reader.avg_progress, 100)" :stroke-width="6" />
          </div>
        </div>
        <div v-if="!(fans?.top_readers || []).length" class="empty-list">暂无高互动读者</div>
        <div class="feedback-list">
          <div v-for="item in fans?.recent_feedback || []" :key="`${item.type}-${item.book_id}-${item.created_at}`" class="feedback-item">
            <div class="feedback-meta">{{ item.type }} · {{ item.author }} · {{ shortDate(item.created_at) }}</div>
            <div class="feedback-content">{{ item.content }}</div>
          </div>
        </div>
      </el-card>

      <el-card shadow="never" class="operation-card">
        <template #header>
          <div class="card-header">创作辅助</div>
        </template>
        <div class="goal-card">
          <div>
            <span>章节字数目标</span>
            <strong>{{ assist?.word_goal.current || 0 }} / {{ assist?.word_goal.target || 4000 }}</strong>
          </div>
          <el-progress :percentage="assist?.word_goal.percent || 0" />
          <p>{{ assist?.word_goal.message || '保持稳定更新，系统会结合作品数据给出建议。' }}</p>
        </div>
        <div class="assist-list">
          <div v-for="item in assist?.outline_cards || []" :key="item.book_id" class="assist-item">
            <div class="assist-title">{{ item.title }}</div>
            <div class="assist-meta">章节 {{ item.sections }} · 阅读 {{ item.reads }}</div>
            <div class="assist-desc">{{ item.suggestion }}</div>
          </div>
        </div>
        <div v-if="assist?.sensitive_hits?.length" class="sensitive-list">
          <div v-for="hit in assist.sensitive_hits" :key="`${hit.book_id}-${hit.word}`" class="sensitive-item">
            《{{ hit.title }}》命中“{{ hit.word }}”：{{ hit.suggestion }}
          </div>
        </div>
      </el-card>
    </div>

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

      <el-card shadow="never" class="chart-card">
        <template #header>
          <div class="card-header">创作优化建议</div>
        </template>
        <div class="suggestions-list">
          <div v-for="(tip, index) in suggestions" :key="index" :class="['suggestion-item', tip.level]">
            <div class="suggestion-title">{{ tip.title }}</div>
            <div class="suggestion-desc">{{ tip.desc }}</div>
          </div>
        </div>
      </el-card>
    </div>

    <el-card class="panel" shadow="never">
      <template #header>
        <div class="card-header">单本作品表现</div>
      </template>
      <el-table :data="items" v-loading="loading" border>
        <el-table-column prop="title" label="书名" min-width="200" />
        <el-table-column prop="metrics.impressions" label="曝光量" width="100" sortable />
        <el-table-column prop="metrics.reads" label="阅读量" width="100" sortable />
        <el-table-column prop="metrics.read_users" label="阅读用户" width="110" sortable />
        <el-table-column prop="metrics.avg_read_duration_label" label="平均阅读时长" width="130" />
        <el-table-column label="地域 Top3" min-width="180">
          <template #default="{ row }">
            {{ (row.geo_distribution || []).slice(0, 3).map((item: any) => `${item.label} ${item.percent}%`).join(' / ') || '-' }}
          </template>
        </el-table-column>
        <el-table-column label="年龄 Top3" min-width="180">
          <template #default="{ row }">
            {{ (row.age_distribution || []).slice(0, 3).map((item: any) => `${item.label} ${item.percent}%`).join(' / ') || '-' }}
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
          <el-input v-model="penNameForm.pen_name" maxlength="80" placeholder="例如：青山、北舟、林间夜雨" />
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

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 16px;
}

.kpi-card {
  background: #fff;
  border: 1px solid #e7e5e4;
  border-radius: 12px;
  padding: 20px;
}

.kpi-card.accent {
  border-color: #d9f99d;
  background: #fcfff4;
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

.panel {
  margin-bottom: 16px;
}

.operation-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
  margin-bottom: 16px;
}

.operation-card {
  min-height: 320px;
}

.income-summary {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
  margin-bottom: 16px;
}

.income-summary div,
.goal-card {
  border: 1px solid #e7e5e4;
  border-radius: 10px;
  padding: 12px;
  background: #fafaf9;
}

.income-summary span,
.goal-card span {
  display: block;
  color: #78716c;
  font-size: 12px;
  margin-bottom: 4px;
}

.income-summary strong,
.goal-card strong {
  font-size: 20px;
  color: #1c1917;
}

.rule-list,
.calendar-list,
.reader-list,
.feedback-list,
.assist-list,
.sensitive-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.rule-item,
.calendar-item,
.reader-item,
.feedback-item,
.assist-item,
.sensitive-item {
  border: 1px solid #e7e5e4;
  border-radius: 10px;
  padding: 12px;
  background: #fff;
}

.rule-title,
.calendar-title,
.assist-title {
  font-weight: 600;
  color: #1c1917;
  margin-bottom: 4px;
}

.rule-desc,
.assist-desc,
.feedback-content,
.goal-card p {
  color: #57534e;
  font-size: 13px;
  line-height: 1.6;
  margin: 0;
}

.calendar-item {
  display: grid;
  grid-template-columns: 48px minmax(0, 1fr);
  gap: 12px;
  align-items: flex-start;
}

.calendar-date {
  font-weight: 700;
  color: #0f766e;
}

.calendar-meta,
.assist-meta,
.feedback-meta,
.reader-item span {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #78716c;
  font-size: 12px;
  line-height: 1.5;
  flex-wrap: wrap;
}

.reader-item {
  display: grid;
  gap: 8px;
}

.reader-item strong {
  display: block;
  color: #1c1917;
  margin-bottom: 2px;
}

.feedback-list {
  margin-top: 12px;
}

.goal-card {
  margin-bottom: 12px;
}

.goal-card > div {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: baseline;
  margin-bottom: 10px;
}

.sensitive-list {
  margin-top: 12px;
}

.sensitive-item {
  border-color: #fed7aa;
  background: #fff7ed;
  color: #9a3412;
  font-size: 13px;
}

.empty-list {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 140px;
  color: #a8a29e;
  font-size: 13px;
}

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
  height: 220px;
  color: #a8a29e;
  font-size: 13px;
}

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

  .operation-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .kpi-grid {
    grid-template-columns: 1fr;
  }
}
</style>
