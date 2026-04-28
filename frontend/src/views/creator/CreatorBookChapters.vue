<template>
  <div class="page">
    <div class="toolbar">
      <div>
        <h2>章节工作台</h2>
        <p class="subtitle">{{ bookTitle }} · 在同一本书中直接新增、编辑、提审章节。</p>
      </div>
      <div class="actions">
        <el-button @click="goBack">返回作品</el-button>
        <el-button @click="reloadAll">刷新</el-button>
        <el-button @click="openSortDialog">章节排序</el-button>
        <el-button type="primary" :disabled="!hasPenName()" @click="openCreateDialog">新建章节</el-button>
      </div>
    </div>

    <el-alert
      v-if="bookShelfStatus !== 'up'"
      title="当前书籍未上架：章节审核通过后会自动替换线上版本，但读者端仍不可见。"
      type="warning"
      show-icon
      :closable="false"
      class="notice"
    />

    <el-card>
      <el-table :data="chapters" v-loading="loading" border>
        <el-table-column prop="order_no" label="序号" width="90" />
        <el-table-column label="章节" min-width="260">
          <template #default="{ row }">
            <div class="chapter-title">{{ row.title }}</div>
            <div class="meta">key: {{ row.section_key || '-' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="当前状态" width="140">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="线上版本" min-width="220">
          <template #default="{ row }">
            <span v-if="row.published_revision">
              v{{ row.published_revision.version_no }} · {{ row.published_revision.published_at || '已发布' }}
            </span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="待审/草稿" min-width="220">
          <template #default="{ row }">
            <span v-if="row.latest_revision">
              v{{ row.latest_revision.version_no }} · {{ statusLabel(row.latest_revision.status) }}
            </span>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="320" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :disabled="!row.can_edit" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="success" :disabled="!row.can_submit" @click="submitChapter(row)">提审</el-button>
            <el-button link @click="openTimeline(row)">审核时间线</el-button>
            <el-button link @click="openVersions(row)">版本记录</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="editorVisible" :title="editingChapterId ? '编辑章节' : '新建章节'" width="860px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="90px">
        <el-form-item label="章节标题" prop="title">
          <el-input v-model="form.title" maxlength="255" show-word-limit />
        </el-form-item>
        <el-form-item label="正文" prop="content_text">
          <el-input v-model="form.content_text" type="textarea" :rows="18" />
          <div class="hint">若该章节已发布，审核通过后会替换线上内容，旧版本保留在版本记录中。</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editorVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="saveChapter">保存草稿</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="versionsVisible" title="章节版本记录" width="920px">
      <el-table :data="versions" v-loading="versionsLoading" border>
        <el-table-column prop="version_no" label="版本" width="80" />
        <el-table-column prop="status" label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="标题" min-width="180" />
        <el-table-column prop="review_comment" label="审核意见" min-width="220" />
        <el-table-column prop="published_at" label="发布时间" width="180" />
        <el-table-column prop="updated_at" label="更新时间" width="180" />
      </el-table>
    </el-dialog>

    <el-dialog v-model="sortDialogVisible" title="章节拖拽排序" width="560px">
      <div class="hint">拖动列表项调整顺序，保存后会同步章节目录与阅读器章节顺序。</div>
      <ul class="sort-list">
        <li
          v-for="(item, index) in sortableChapters"
          :key="item.id"
          class="sort-item"
          draggable="true"
          @dragstart="onDragStart(index)"
          @dragover.prevent
          @drop="onDrop(index)"
        >
          <span class="drag-handle">☰</span>
          <span class="sort-index">{{ index + 1 }}</span>
          <span class="sort-title">{{ item.title }}</span>
        </li>
      </ul>
      <template #footer>
        <el-button @click="sortDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="sortSaving" @click="saveOrder">保存顺序</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="timelineVisible" title="审核结果时间线" size="42%">
      <div v-if="timelineChapterTitle" class="timeline-title">{{ timelineChapterTitle }}</div>
      <el-timeline>
        <el-timeline-item
          v-for="item in timelineItems"
          :key="item.key"
          :timestamp="item.time"
          :type="item.type"
        >
          <div class="timeline-row">
            <strong>{{ item.title }}</strong>
            <el-tag size="small" :type="statusTagType(item.status)">{{ statusLabel(item.status) }}</el-tag>
          </div>
          <div class="timeline-content">{{ item.content }}</div>
        </el-timeline-item>
      </el-timeline>
    </el-drawer>

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
      </el-form>
      <template #footer>
        <el-button @click="router.push('/user/profile')">去个人资料页</el-button>
        <el-button type="primary" :loading="saving" @click="savePenName">保存笔名</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import {
  createCreatorBookChapter,
  getCreatorBookChapterVersions,
  getCreatorBookChapters,
  getCreatorWorkDetail,
  reorderCreatorBookChapters,
  submitCreatorBookChapter,
  updateCreatorBookChapter,
  type CreatorBookChapterItem,
  type CreatorChapterRevisionItem,
} from '@/api/creator'
import { useCreatorPenName } from '@/composables/useCreatorPenName'

const route = useRoute()
const router = useRouter()
const loading = ref(false)
const submitLoading = ref(false)
const chapters = ref<CreatorBookChapterItem[]>([])
const bookTitle = ref('')
const bookShelfStatus = ref('')

const editorVisible = ref(false)
const editingChapterId = ref<number | null>(null)
const formRef = ref<FormInstance>()
const form = reactive({
  title: '',
  content_text: '',
})
const rules: FormRules = {
  title: [{ required: true, message: '请输入章节标题', trigger: 'blur' }],
  content_text: [{ required: true, message: '请输入章节正文', trigger: 'blur' }],
}

const versionsVisible = ref(false)
const versionsLoading = ref(false)
const versions = ref<CreatorChapterRevisionItem[]>([])
const timelineVisible = ref(false)
const timelineItems = ref<Array<{ key: string; time: string; title: string; status: string; content: string; type: 'success' | 'warning' | 'danger' | 'info' | 'primary' }>>([])
const timelineChapterTitle = ref('')
const sortDialogVisible = ref(false)
const sortSaving = ref(false)
const sortableChapters = ref<Array<{ id: number; title: string }>>([])
const draggingIndex = ref<number | null>(null)

const { penNameDialogVisible, penNameForm, saving, loadCreatorProfile, savePenName, hasPenName } = useCreatorPenName()
const bookId = computed(() => Number(route.params.bookId || 0))

const statusLabel = (value?: string) => {
  if (value === 'draft') return '草稿'
  if (value === 'pending') return '待审'
  if (value === 'approved') return '已通过'
  if (value === 'rejected') return '已驳回'
  if (value === 'published') return '已发布'
  if (value === 'superseded') return '历史版本'
  return value || '-'
}

const statusTagType = (value?: string) => {
  if (value === 'published' || value === 'approved') return 'success'
  if (value === 'pending') return 'warning'
  if (value === 'rejected') return 'danger'
  if (value === 'superseded') return 'info'
  return ''
}

const loadBook = async () => {
  if (!bookId.value) return
  try {
    const res = await getCreatorWorkDetail(bookId.value)
    bookTitle.value = res.item?.title || `书籍 #${bookId.value}`
    bookShelfStatus.value = res.item?.shelf_status || 'down'
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载书籍信息失败')
  }
}

const loadChapters = async () => {
  if (!bookId.value) return
  loading.value = true
  try {
    const res = await getCreatorBookChapters(bookId.value)
    chapters.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载章节失败')
  } finally {
    loading.value = false
  }
}

const reloadAll = async () => {
  await Promise.all([loadBook(), loadChapters()])
}

const openCreateDialog = () => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  editingChapterId.value = null
  form.title = ''
  form.content_text = ''
  editorVisible.value = true
}

const openEditDialog = (row: CreatorBookChapterItem) => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  editingChapterId.value = Number(row.id)
  form.title = row.latest_revision?.title || row.published_revision?.title || row.title || ''
  form.content_text = row.latest_revision?.content_text || row.published_revision?.content_text || row.content_text || ''
  editorVisible.value = true
}

const saveChapter = async () => {
  await formRef.value?.validate()
  submitLoading.value = true
  try {
    if (editingChapterId.value) {
      await updateCreatorBookChapter(bookId.value, editingChapterId.value, { title: form.title, content_text: form.content_text })
      ElMessage.success('章节草稿已更新')
    } else {
      await createCreatorBookChapter(bookId.value, { title: form.title, content_text: form.content_text })
      ElMessage.success('章节草稿已创建')
    }
    editorVisible.value = false
    await loadChapters()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存章节失败')
  } finally {
    submitLoading.value = false
  }
}

const submitChapter = async (row: CreatorBookChapterItem) => {
  try {
    await ElMessageBox.confirm(`确认提交《${row.title}》进入审核吗？`, '提交章节审核', { type: 'warning' })
    await submitCreatorBookChapter(bookId.value, Number(row.id))
    ElMessage.success('章节已提交审核')
    await loadChapters()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '提交失败')
    }
  }
}

const openVersions = async (row: CreatorBookChapterItem) => {
  versionsVisible.value = true
  versionsLoading.value = true
  try {
    const res = await getCreatorBookChapterVersions(bookId.value, Number(row.id))
    versions.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载版本记录失败')
  } finally {
    versionsLoading.value = false
  }
}

const openTimeline = async (row: CreatorBookChapterItem) => {
  timelineChapterTitle.value = `第${row.order_no || '-'}章 ${row.title}`
  timelineVisible.value = true
  try {
    const res = await getCreatorBookChapterVersions(bookId.value, Number(row.id))
    const entries = (res.items || [])
      .map((item) => {
        const time = item.reviewed_at || item.submitted_at || item.published_at || item.updated_at || item.created_at || ''
        const content = item.review_comment || (item.status === 'pending' ? '已提交审核，等待处理' : '无审核意见')
        const type =
          item.status === 'published'
            ? 'success'
            : item.status === 'pending'
              ? 'warning'
              : item.status === 'rejected'
                ? 'danger'
                : 'info'
        return {
          key: `${item.id}-${item.version_no}`,
          time,
          title: `版本 v${item.version_no}`,
          status: item.status,
          content,
          type,
        }
      })
      .sort((a, b) => String(b.time || '').localeCompare(String(a.time || '')))
    timelineItems.value = entries
  } catch (error: any) {
    timelineItems.value = []
    ElMessage.error(error?.response?.data?.error || '加载审核时间线失败')
  }
}

const openSortDialog = () => {
  sortableChapters.value = (chapters.value || [])
    .filter((item) => Number(item.id) > 0)
    .sort((a, b) => Number(a.order_no || 0) - Number(b.order_no || 0))
    .map((item) => ({ id: Number(item.id), title: item.title }))
  sortDialogVisible.value = true
}

const onDragStart = (index: number) => {
  draggingIndex.value = index
}

const onDrop = (targetIndex: number) => {
  const from = draggingIndex.value
  if (from === null || from === targetIndex) return
  const list = [...sortableChapters.value]
  const [moved] = list.splice(from, 1)
  if (!moved) return
  list.splice(targetIndex, 0, moved)
  sortableChapters.value = list
  draggingIndex.value = null
}

const saveOrder = async () => {
  if (!sortableChapters.value.length) {
    sortDialogVisible.value = false
    return
  }
  sortSaving.value = true
  try {
    const ids = sortableChapters.value.map((item) => item.id)
    const res = await reorderCreatorBookChapters(bookId.value, ids)
    chapters.value = res.items || chapters.value
    ElMessage.success('章节顺序已更新')
    sortDialogVisible.value = false
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存章节顺序失败')
  } finally {
    sortSaving.value = false
  }
}

const goBack = () => {
  router.push('/creator/works')
}

onMounted(async () => {
  await loadCreatorProfile()
  await reloadAll()
})
</script>

<style scoped>
.page {
  padding: 20px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 16px;
}

.subtitle {
  margin-top: 6px;
  color: #606266;
  font-size: 13px;
}

.actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.notice {
  margin-bottom: 16px;
}

.chapter-title {
  font-weight: 600;
  color: #111827;
}

.meta,
.hint {
  margin-top: 4px;
  color: #6b7280;
  font-size: 12px;
}

.sort-list {
  list-style: none;
  margin: 12px 0 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.sort-item {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 10px 12px;
  display: flex;
  align-items: center;
  gap: 10px;
  background: #fff;
  cursor: move;
}

.drag-handle {
  color: #9ca3af;
}

.sort-index {
  width: 22px;
  color: #6b7280;
  font-size: 13px;
}

.sort-title {
  color: #111827;
}

.timeline-title {
  margin-bottom: 14px;
  font-weight: 600;
  color: #111827;
}

.timeline-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.timeline-content {
  margin-top: 6px;
  color: #4b5563;
  white-space: pre-wrap;
}
</style>
