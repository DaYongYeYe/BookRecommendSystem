<template>
  <div class="admin-page">
    <div class="toolbar">
      <h2>章节审核</h2>
      <div class="actions">
        <el-input
          v-model="keyword"
          placeholder="搜索书名/章节名"
          clearable
          style="width: 220px"
          @keyup.enter="loadItems"
        />
        <el-select v-model="statusFilter" style="width: 160px" @change="loadItems">
          <el-option label="待审核" value="pending" />
          <el-option label="已驳回" value="rejected" />
        </el-select>
        <el-button
          type="success"
          :disabled="!selectedRows.length || statusFilter !== 'pending'"
          @click="batchApprove"
        >
          批量通过
        </el-button>
        <el-button
          type="danger"
          :disabled="!selectedRows.length || statusFilter !== 'pending'"
          @click="batchReject"
        >
          批量驳回
        </el-button>
        <el-button @click="loadItems">刷新</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="items" v-loading="loading" border @selection-change="onSelectionChange">
        <el-table-column type="selection" width="52" />
        <el-table-column label="书籍" min-width="220">
          <template #default="{ row }">
            <div class="book-title">{{ row.book.title }}</div>
            <div class="meta">章节：{{ row.chapter.chapter_no }} · {{ row.chapter.title }}</div>
          </template>
        </el-table-column>
        <el-table-column label="版本" width="90">
          <template #default="{ row }">v{{ row.latest_revision.version_no }}</template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.latest_revision.status)">
              {{ statusLabel(row.latest_revision.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="latest_revision.submitted_at" label="提交时间" width="180" />
        <el-table-column prop="latest_revision.reviewed_at" label="审核时间" width="180" />
        <el-table-column label="审核意见" min-width="220">
          <template #default="{ row }">{{ row.latest_revision.review_comment || '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="320" fixed="right">
          <template #default="{ row }">
            <el-button link @click="openDetail(row)">查看正文</el-button>
            <el-button link type="primary" @click="openDiffPreview(row)">差异预览</el-button>
            <el-button
              link
              type="success"
              :disabled="row.latest_revision.status !== 'pending'"
              @click="quickApprove(row)"
            >
              一键通过
            </el-button>
            <el-button link type="danger" @click="quickReject(row)">一键驳回</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="detailVisible" title="章节送审详情" size="52%">
      <div v-if="activeItem">
        <h3>{{ activeItem.book.title }} · 第{{ activeItem.chapter.chapter_no }}章 {{ activeItem.chapter.title }}</h3>
        <p><strong>版本：</strong>v{{ activeItem.latest_revision.version_no }}</p>
        <p><strong>状态：</strong>{{ statusLabel(activeItem.latest_revision.status) }}</p>
        <p><strong>审核意见：</strong>{{ activeItem.latest_revision.review_comment || '无' }}</p>
        <el-divider />
        <pre class="content">{{ activeItem.latest_revision.content_text }}</pre>
      </div>
    </el-drawer>

    <el-dialog v-model="diffVisible" title="快速预览差异（新版本 vs 上线版本）" width="80%">
      <div v-loading="diffLoading">
        <div class="diff-meta" v-if="diffCompare">
          <el-tag type="warning">新版本 v{{ diffCompare.latest_revision?.version_no || '-' }}</el-tag>
          <el-tag type="success">线上版本 v{{ diffCompare.published_revision?.version_no || '-' }}</el-tag>
          <span class="meta-text">{{ diffCompare.book.title }} · {{ diffCompare.chapter.title }}</span>
        </div>
        <div class="diff-panel">
          <div class="diff-header">
            <span>上线版本</span>
            <span>新版本</span>
          </div>
          <div v-if="!diffRows.length" class="no-diff">暂无差异内容</div>
          <div v-else class="diff-rows">
            <div v-for="row in diffRows" :key="row.index" class="diff-row">
              <div class="diff-cell" :class="row.type">{{ row.oldLine || '' }}</div>
              <div class="diff-cell" :class="row.type">{{ row.newLine || '' }}</div>
            </div>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  batchReviewAdminChapters,
  getAdminChapterCompare,
  getAdminChapterReviews,
  reviewAdminChapter,
  type AdminChapterCompareResponse,
  type AdminChapterReviewItem,
} from '@/api/admin'

const loading = ref(false)
const items = ref<AdminChapterReviewItem[]>([])
const keyword = ref('')
const statusFilter = ref<'pending' | 'rejected'>('pending')

const detailVisible = ref(false)
const activeItem = ref<AdminChapterReviewItem | null>(null)
const selectedRows = ref<AdminChapterReviewItem[]>([])
const diffVisible = ref(false)
const diffLoading = ref(false)
const diffRows = ref<Array<{ index: string; oldLine: string; newLine: string; type: 'same' | 'changed' | 'added' | 'removed' }>>([])
const diffCompare = ref<AdminChapterCompareResponse | null>(null)

const statusLabel = (status?: string) => {
  if (status === 'pending') return '待审核'
  if (status === 'rejected') return '已驳回'
  if (status === 'published') return '已发布'
  return status || '-'
}

const statusTagType = (status?: string) => {
  if (status === 'pending') return 'warning'
  if (status === 'rejected') return 'danger'
  if (status === 'published') return 'success'
  return ''
}

const loadItems = async () => {
  loading.value = true
  try {
    const res = await getAdminChapterReviews({
      status: statusFilter.value,
      keyword: keyword.value || undefined,
    })
    items.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载章节审核列表失败')
  } finally {
    loading.value = false
  }
}

const onSelectionChange = (rows: AdminChapterReviewItem[]) => {
  selectedRows.value = rows || []
}

const openDetail = (row: AdminChapterReviewItem) => {
  activeItem.value = row
  detailVisible.value = true
}

const buildDiffRows = (oldText: string, newText: string) => {
  const oldLines = (oldText || '').split('\n')
  const newLines = (newText || '').split('\n')
  const maxLen = Math.max(oldLines.length, newLines.length)
  const rows: Array<{ index: string; oldLine: string; newLine: string; type: 'same' | 'changed' | 'added' | 'removed' }> = []
  for (let i = 0; i < maxLen; i += 1) {
    const oldLine = oldLines[i] ?? ''
    const newLine = newLines[i] ?? ''
    let type: 'same' | 'changed' | 'added' | 'removed' = 'same'
    if (!oldLine && newLine) type = 'added'
    else if (oldLine && !newLine) type = 'removed'
    else if (oldLine !== newLine) type = 'changed'
    rows.push({ index: `line-${i + 1}`, oldLine, newLine, type })
  }
  return rows
}

const openDiffPreview = async (row: AdminChapterReviewItem) => {
  diffVisible.value = true
  diffLoading.value = true
  try {
    const res = await getAdminChapterCompare(row.chapter.id)
    diffCompare.value = res
    const oldText = res.published_revision?.content_text || ''
    const newText = res.latest_revision?.content_text || ''
    diffRows.value = buildDiffRows(oldText, newText)
  } catch (error: any) {
    diffRows.value = []
    diffCompare.value = null
    ElMessage.error(error?.response?.data?.error || '加载章节差异失败')
  } finally {
    diffLoading.value = false
  }
}

const quickApprove = async (row: AdminChapterReviewItem) => {
  try {
    await ElMessageBox.confirm(`确认通过章节《${row.chapter.title}》吗？`, '一键通过', { type: 'warning' })
    await reviewAdminChapter(row.chapter.id, { action: 'approve' })
    ElMessage.success('章节已通过并自动替换线上版本')
    await loadItems()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '操作失败')
    }
  }
}

const quickReject = async (row: AdminChapterReviewItem) => {
  try {
    const { value } = await ElMessageBox.prompt(`请填写驳回《${row.chapter.title}》的原因`, '一键驳回', {
      confirmButtonText: '确认驳回',
      cancelButtonText: '取消',
      inputPlaceholder: '可选，建议给出修改方向',
    })
    await reviewAdminChapter(row.chapter.id, { action: 'reject', review_comment: value || undefined })
    ElMessage.success('章节已驳回')
    await loadItems()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '操作失败')
    }
  }
}

const batchApprove = async () => {
  try {
    await ElMessageBox.confirm(`确认批量通过 ${selectedRows.value.length} 个章节吗？`, '批量通过', { type: 'warning' })
    const chapterIds = selectedRows.value.map((item) => item.chapter.id)
    const res = await batchReviewAdminChapters({ chapter_ids: chapterIds, action: 'approve' })
    const failedInfo = res.failed_count ? `，失败 ${res.failed_count} 条` : ''
    ElMessage.success(`批量通过完成：成功 ${res.success_count} 条${failedInfo}`)
    await loadItems()
    selectedRows.value = []
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '批量通过失败')
    }
  }
}

const batchReject = async () => {
  try {
    const { value } = await ElMessageBox.prompt(`请填写批量驳回 ${selectedRows.value.length} 个章节的原因`, '批量驳回', {
      confirmButtonText: '确认驳回',
      cancelButtonText: '取消',
      inputPlaceholder: '可选，建议给出统一修改方向',
    })
    const chapterIds = selectedRows.value.map((item) => item.chapter.id)
    const res = await batchReviewAdminChapters({
      chapter_ids: chapterIds,
      action: 'reject',
      review_comment: value || undefined,
    })
    const failedInfo = res.failed_count ? `，失败 ${res.failed_count} 条` : ''
    ElMessage.success(`批量驳回完成：成功 ${res.success_count} 条${failedInfo}`)
    await loadItems()
    selectedRows.value = []
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '批量驳回失败')
    }
  }
}

onMounted(loadItems)
</script>

<style scoped>
.admin-page {
  padding: 20px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.actions {
  display: flex;
  gap: 12px;
}

.book-title {
  font-weight: 600;
}

.meta {
  margin-top: 4px;
  color: #6b7280;
  font-size: 12px;
}

.content {
  white-space: pre-wrap;
  background: #f8f8f8;
  border-radius: 8px;
  padding: 12px;
  max-height: 65vh;
  overflow: auto;
}

.diff-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}

.meta-text {
  color: #4b5563;
  font-size: 13px;
}

.diff-panel {
  border: 1px solid #e5e7eb;
  border-radius: 8px;
}

.diff-header {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  background: #f9fafb;
  border-bottom: 1px solid #e5e7eb;
  padding: 8px 10px;
  font-weight: 600;
  color: #374151;
}

.diff-rows {
  max-height: 62vh;
  overflow: auto;
}

.diff-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
}

.diff-cell {
  white-space: pre-wrap;
  padding: 8px 10px;
  border-bottom: 1px solid #f1f5f9;
  font-size: 13px;
  line-height: 1.5;
}

.diff-cell.changed {
  background: #fff7ed;
}

.diff-cell.added {
  background: #ecfdf5;
}

.diff-cell.removed {
  background: #fef2f2;
}

.no-diff {
  padding: 14px;
  color: #6b7280;
}
</style>
