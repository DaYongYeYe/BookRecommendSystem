<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getCreatorBookAnalytics, type CreatorBookAnalyticsItem } from '@/api/creator'
import { useCreatorPenName } from '@/composables/useCreatorPenName'

const router = useRouter()
const loading = ref(false)
const items = ref<CreatorBookAnalyticsItem[]>([])
const { penNameDialogVisible, penNameForm, saving, loadCreatorProfile, savePenName, hasPenName } = useCreatorPenName()

const topBooks = computed(() => [...items.value].sort((a, b) => b.metrics.reads - a.metrics.reads).slice(0, 3))

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

const formatDistribution = (rows: { label: string; percent: number; count: number }[]) => {
  if (!rows.length) return '暂无数据'
  return rows
    .slice(0, 3)
    .map((row) => `${row.label} ${row.percent}%`)
    .join(' / ')
}

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
      <h2>创作数据看板</h2>
      <div class="actions">
        <el-button type="primary" :disabled="!hasPenName()" @click="router.push('/creator/works')">我的作品</el-button>
        <el-button :disabled="!hasPenName()" @click="router.push('/creator/manuscripts')">稿件管理</el-button>
        <el-button @click="router.push('/user/profile')">个人资料</el-button>
        <el-button @click="router.push('/')">返回首页</el-button>
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

    <el-row :gutter="12" class="summary-row">
      <el-col :xs="24" :sm="8">
        <el-card shadow="hover"><div class="kpi-title">总曝光量</div><div class="kpi-value">{{ total.impressions }}</div></el-card>
      </el-col>
      <el-col :xs="24" :sm="8">
        <el-card shadow="hover"><div class="kpi-title">总阅读量</div><div class="kpi-value">{{ total.reads }}</div></el-card>
      </el-col>
      <el-col :xs="24" :sm="8">
        <el-card shadow="hover"><div class="kpi-title">阅读用户数</div><div class="kpi-value">{{ total.readUsers }}</div></el-card>
      </el-col>
    </el-row>

    <el-card class="panel" shadow="never">
      <template #header>
        <div class="panel-header">每本作品的阅读表现</div>
      </template>
      <el-table :data="items" v-loading="loading" border>
        <el-table-column prop="title" label="书名" min-width="220" />
        <el-table-column prop="metrics.impressions" label="曝光量" width="110" />
        <el-table-column prop="metrics.reads" label="阅读量" width="110" />
        <el-table-column prop="metrics.read_users" label="阅读用户数" width="130" />
        <el-table-column prop="metrics.avg_read_duration_label" label="平均阅读时长" width="140" />
        <el-table-column label="地域分布 Top3" min-width="220">
          <template #default="{ row }">{{ formatDistribution(row.geo_distribution || []) }}</template>
        </el-table-column>
        <el-table-column label="年龄分布 Top3" min-width="220">
          <template #default="{ row }">{{ formatDistribution(row.age_distribution || []) }}</template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="panel" shadow="never">
      <template #header>
        <div class="panel-header">创作优化建议</div>
      </template>
      <div class="tips-grid">
        <div class="tip-card">
          <div class="tip-title">1. 先补基础资料</div>
          <div class="tip-desc">书名、封面、简介、分类与标签会直接影响读者点击和推荐分发，建议优先在作品管理页补齐。</div>
        </div>
        <div class="tip-card">
          <div class="tip-title">2. 关注首章转化</div>
          <div class="tip-desc">如果曝光高但阅读低，优先回看封面和简介；如果阅读高但留存低，重点优化开篇节奏和前几章承接。</div>
        </div>
        <div class="tip-card">
          <div class="tip-title">3. 用数据安排更新</div>
          <div class="tip-desc">对阅读活跃高的作品保持稳定更新，对已完结或暂停作品及时同步状态，避免读者预期落差。</div>
        </div>
      </div>
      <div v-if="topBooks.length" class="top-books">当前阅读量最高：{{ topBooks.map((item) => item.title).join(' / ') }}</div>
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
        <el-button @click="router.push('/user/profile')">去个人资料页</el-button>
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
  align-items: center;
  margin-bottom: 16px;
  gap: 12px;
}

.actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.notice {
  margin-bottom: 16px;
}

.summary-row {
  margin-bottom: 16px;
}

.kpi-title {
  color: #6b7280;
  font-size: 13px;
}

.kpi-value {
  margin-top: 8px;
  font-size: 26px;
  font-weight: 700;
  color: #111827;
}

.panel {
  margin-bottom: 16px;
}

.panel-header {
  font-weight: 600;
}

.tips-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}

.tip-card {
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  padding: 12px;
}

.tip-title {
  font-weight: 600;
  margin-bottom: 6px;
}

.tip-desc {
  color: #4b5563;
  font-size: 13px;
  line-height: 1.5;
}

.top-books {
  margin-top: 12px;
  color: #374151;
  font-size: 13px;
}

.dialog-tip {
  color: #6b7280;
  font-size: 13px;
  line-height: 1.6;
}
</style>
