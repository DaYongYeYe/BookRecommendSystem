<template>
  <div class="page">
    <div class="toolbar">
      <div>
        <h2>创作者稿件</h2>
        <p class="subtitle">一本书可以按章节持续维护，支持单章改名、改内容、再提审。</p>
      </div>
      <div class="actions">
        <el-button @click="goHome">返回首页</el-button>
        <el-select v-model="statusFilter" style="width: 160px" @change="loadManuscripts">
          <el-option label="全部状态" value="" />
          <el-option label="草稿" value="draft" />
          <el-option label="已提交" value="submitted" />
          <el-option label="已通过" value="approved" />
          <el-option label="已驳回" value="rejected" />
          <el-option label="已发布" value="published" />
        </el-select>
        <el-button @click="reloadAll">刷新</el-button>
        <el-button type="primary" :disabled="!hasPenName()" @click="openCreateDialog">新建草稿</el-button>
      </div>
    </div>

    <el-alert
      v-if="!hasPenName()"
      title="进入创作者端前请先设置笔名，发布后的书籍会用该笔名展示作者。"
      type="warning"
      show-icon
      :closable="false"
      class="notice"
    />

    <el-card>
      <el-table :data="manuscripts" v-loading="loading" border>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="title" label="稿件标题" min-width="220" />
        <el-table-column label="稿件类型" width="150">
          <template #default="{ row }">
            <el-tag :type="updateModeTagType(row.update_mode)">{{ updateModeLabel(row.update_mode) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="章节数" width="100">
          <template #default="{ row }">{{ row.chapters?.length || 0 }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="120">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="updated_at" label="更新时间" width="200" />
        <el-table-column label="操作" width="240">
          <template #default="{ row }">
            <el-button link type="primary" @click="openEditDialog(row)">编辑</el-button>
            <el-button
              link
              type="success"
              :disabled="!hasPenName() || !['draft', 'rejected'].includes(row.status)"
              @click="onSubmit(row)"
            >
              提交审核
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingId ? '编辑章节稿件' : '新建章节稿件'" width="1180px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="110px">
        <el-form-item label="发布对象">
          <el-radio-group v-model="form.target_type" :disabled="!!editingId" @change="handleTargetTypeChange">
            <el-radio value="new">新书发布</el-radio>
            <el-radio value="existing">更新已有书籍</el-radio>
          </el-radio-group>
        </el-form-item>

        <el-form-item v-if="form.target_type === 'existing'" label="选择书籍" prop="selectedBookId">
          <el-select
            v-model="form.selectedBookId"
            filterable
            placeholder="选择要继续维护的书"
            style="width: 100%"
            :disabled="!!editingId"
            @change="handleTargetBookChange"
          >
            <el-option
              v-for="book in creatorBooks"
              :key="book.id"
              :label="`${book.title}（已发布章节 ${book.section_count || 0} / 版本 ${book.version_count || 0}）`"
              :value="book.id"
            />
          </el-select>
        </el-form-item>

        <el-form-item v-if="form.target_type === 'existing'" label="更新模式">
          <el-radio-group v-model="form.update_mode" @change="handleUpdateModeChange">
            <el-radio value="append">章节更新</el-radio>
            <el-radio value="full">整本覆盖</el-radio>
          </el-radio-group>
          <div class="hint">
            章节更新：只提交本次新增或修改的章节。整本覆盖：按当前草稿章节列表重新发布整本书。
          </div>
        </el-form-item>

        <el-form-item label="书名" prop="title">
          <el-input v-model="form.title" maxlength="255" show-word-limit />
        </el-form-item>

        <el-form-item label="简介">
          <el-input v-model="form.description" type="textarea" :rows="3" maxlength="2000" show-word-limit />
        </el-form-item>

        <el-form-item label="封面图">
          <input
            ref="coverInputRef"
            class="file-input"
            type="file"
            accept=".jpg,.jpeg,.png,.webp"
            @change="onCoverFileChange"
          />
          <el-button @click="triggerCoverUpload">选择文件</el-button>
          <div v-if="form.cover || coverFileName" class="hint">已选择：{{ coverFileName || form.cover }}</div>
        </el-form-item>
      </el-form>

      <div class="chapter-layout">
        <el-card v-if="form.target_type === 'existing'" class="published-panel" shadow="never">
          <template #header>
            <div class="panel-header">
              <span>已发布章节</span>
              <el-button link type="primary" @click="refreshPublishedChapters">刷新章节</el-button>
            </div>
          </template>
          <div v-if="loadingPublishedChapters" class="empty-text">正在加载章节...</div>
          <div v-else-if="!publishedChapters.length" class="empty-text">当前还没有已发布章节，可以直接新增章节。</div>
          <div v-else class="chapter-list">
            <div v-for="chapter in publishedChapters" :key="chapter.section_key || chapter.title" class="published-item">
              <div>
                <div class="published-title">{{ chapter.title }}</div>
                <div class="published-meta">
                  {{ chapter.section_key }} · {{ chapter.content_text.length }} 字
                </div>
              </div>
              <el-button size="small" @click="importPublishedChapter(chapter)">加入本次修改</el-button>
            </div>
          </div>
        </el-card>

        <el-card class="draft-panel" shadow="never">
          <template #header>
            <div class="panel-header">
              <span>{{ draftPanelTitle }}</span>
              <div class="panel-actions">
                <el-button size="small" @click="addBlankChapter">新增章节</el-button>
                <el-button
                  v-if="form.target_type === 'existing' && form.update_mode === 'full'"
                  size="small"
                  @click="usePublishedChaptersAsBase"
                >
                  导入已发布章节
                </el-button>
              </div>
            </div>
          </template>

          <div v-if="!chapterDrafts.length" class="empty-text">还没有章节，点击“新增章节”开始编辑。</div>

          <div v-else class="draft-list">
            <div v-for="(chapter, index) in chapterDrafts" :key="chapter.local_id" class="draft-item">
              <div class="draft-head">
                <div class="draft-title">
                  <span>章节 {{ index + 1 }}</span>
                  <el-tag v-if="chapter.section_key" type="info">修改已发布章节</el-tag>
                  <el-tag v-else type="success">新增章节</el-tag>
                </div>
                <div class="draft-actions">
                  <el-button link :disabled="index === 0" @click="moveChapter(index, -1)">上移</el-button>
                  <el-button link :disabled="index === chapterDrafts.length - 1" @click="moveChapter(index, 1)">下移</el-button>
                  <el-button link type="danger" @click="removeChapter(index)">删除</el-button>
                </div>
              </div>

              <el-input
                v-model="chapter.title"
                maxlength="255"
                placeholder="章节标题"
                class="chapter-input"
              />
              <el-input
                v-model="chapter.content_text"
                type="textarea"
                :rows="8"
                placeholder="请输入该章节正文内容"
              />
            </div>
          </div>
        </el-card>
      </div>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="onSaveDraft">保存草稿</el-button>
      </template>
    </el-dialog>

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
        <div class="hint block">笔名将作为作品作者名展示，也会用于你后续所有书籍更新。</div>
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
  CreatorBookChapterItem,
  CreatorBookItem,
  CreatorManuscriptItem,
  createCreatorManuscript,
  getCreatorBookChapters,
  getCreatorBooks,
  getCreatorManuscripts,
  submitCreatorManuscript,
  updateCreatorManuscript,
} from '@/api/creator'
import { useCreatorPenName } from '@/composables/useCreatorPenName'

type EditableChapter = {
  local_id: string
  section_key?: string | null
  title: string
  content_text: string
}

const loading = ref(false)
const loadingPublishedChapters = ref(false)
const submitLoading = ref(false)
const manuscripts = ref<CreatorManuscriptItem[]>([])
const creatorBooks = ref<CreatorBookItem[]>([])
const publishedChapters = ref<CreatorBookChapterItem[]>([])
const statusFilter = ref('')
const router = useRouter()
const route = useRoute()

const { penNameDialogVisible, penNameForm, saving, loadCreatorProfile, savePenName, hasPenName } = useCreatorPenName()

const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const formRef = ref<FormInstance>()
const coverInputRef = ref<HTMLInputElement | null>(null)
const form = reactive({
  target_type: 'new' as 'new' | 'existing',
  selectedBookId: undefined as number | undefined,
  update_mode: 'append' as 'append' | 'full',
  title: '',
  description: '',
  cover: '',
})
const chapterDrafts = ref<EditableChapter[]>([])
const coverFile = ref<File | null>(null)
const coverFileName = ref('')

const rules: FormRules = {
  title: [{ required: true, message: '请输入书名', trigger: 'blur' }],
  selectedBookId: [
    {
      validator: (_rule, value, callback) => {
        if (form.target_type === 'existing' && !value) {
          callback(new Error('请选择一本已有书籍'))
          return
        }
        callback()
      },
      trigger: 'change',
    },
  ],
}

const draftPanelTitle = computed(() => {
  if (form.target_type === 'existing' && form.update_mode === 'append') {
    return '本次送审章节'
  }
  return '草稿章节列表'
})

const statusTagType = (status: string) => {
  if (status === 'published') return 'success'
  if (status === 'approved') return 'warning'
  if (status === 'submitted') return 'info'
  if (status === 'rejected') return 'danger'
  return ''
}

const updateModeTagType = (mode: string) => {
  if (mode === 'append') return 'success'
  if (mode === 'full') return 'warning'
  return ''
}

const updateModeLabel = (mode: string) => {
  if (mode === 'append') return '章节更新'
  if (mode === 'full') return '整本覆盖'
  return '新书发布'
}

const createLocalId = () => `${Date.now()}-${Math.random().toString(16).slice(2)}`

const toEditableChapter = (chapter?: Partial<CreatorBookChapterItem>): EditableChapter => ({
  local_id: createLocalId(),
  section_key: chapter?.section_key || undefined,
  title: chapter?.title || '',
  content_text: chapter?.content_text || '',
})

const resetForm = () => {
  editingId.value = null
  form.target_type = 'new'
  form.selectedBookId = undefined
  form.update_mode = 'append'
  form.title = ''
  form.description = ''
  form.cover = ''
  chapterDrafts.value = [toEditableChapter({ title: '第一章' })]
  publishedChapters.value = []
  coverFile.value = null
  coverFileName.value = ''
}

const addBlankChapter = () => {
  chapterDrafts.value.push(toEditableChapter({ title: `第 ${chapterDrafts.value.length + 1} 章` }))
}

const removeChapter = (index: number) => {
  chapterDrafts.value.splice(index, 1)
}

const moveChapter = (index: number, offset: number) => {
  const nextIndex = index + offset
  if (nextIndex < 0 || nextIndex >= chapterDrafts.value.length) return
  const copy = [...chapterDrafts.value]
  const [item] = copy.splice(index, 1)
  copy.splice(nextIndex, 0, item)
  chapterDrafts.value = copy
}

const usePublishedChaptersAsBase = () => {
  if (!publishedChapters.value.length) {
    ElMessage.warning('这本书还没有已发布章节')
    return
  }
  chapterDrafts.value = publishedChapters.value.map((chapter) => toEditableChapter(chapter))
}

const importPublishedChapter = (chapter: CreatorBookChapterItem) => {
  if (chapter.section_key && chapterDrafts.value.some((item) => item.section_key === chapter.section_key)) {
    ElMessage.warning('该章节已经在本次草稿中')
    return
  }
  chapterDrafts.value.push(toEditableChapter(chapter))
}

const handleTargetTypeChange = async () => {
  if (form.target_type === 'new') {
    form.selectedBookId = undefined
    form.update_mode = 'append'
    publishedChapters.value = []
    if (!chapterDrafts.value.length) {
      chapterDrafts.value = [toEditableChapter({ title: '第一章' })]
    }
    return
  }
  if (creatorBooks.value.length && !form.selectedBookId) {
    form.selectedBookId = creatorBooks.value[0].id
  }
  await handleTargetBookChange(form.selectedBookId)
}

const handleUpdateModeChange = () => {
  if (form.update_mode === 'full' && form.target_type === 'existing' && !chapterDrafts.value.length) {
    usePublishedChaptersAsBase()
  }
}

const loadPublishedChapters = async (bookId?: number) => {
  if (!bookId) {
    publishedChapters.value = []
    return
  }
  loadingPublishedChapters.value = true
  try {
    const res = await getCreatorBookChapters(bookId)
    publishedChapters.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载已发布章节失败')
  } finally {
    loadingPublishedChapters.value = false
  }
}

const refreshPublishedChapters = async () => {
  await loadPublishedChapters(form.selectedBookId)
}

const handleTargetBookChange = async (bookId?: number) => {
  await loadPublishedChapters(bookId)
  const selectedBook = creatorBooks.value.find((book) => book.id === bookId)
  if (!selectedBook) return
  if (!form.title) form.title = selectedBook.title || ''
  if (!form.description) form.description = selectedBook.description || ''
  if (!form.cover) form.cover = selectedBook.cover || ''
  if (form.update_mode === 'full' && !chapterDrafts.value.length) {
    usePublishedChaptersAsBase()
  }
}

const openCreateDialog = () => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  resetForm()
  dialogVisible.value = true
}

const openCreateDialogForExistingBook = async (bookId?: number) => {
  if (!bookId) {
    openCreateDialog()
    return
  }
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  resetForm()
  form.target_type = 'existing'
  form.selectedBookId = bookId
  await handleTargetBookChange(bookId)
  dialogVisible.value = true
}

const openEditDialog = async (row: CreatorManuscriptItem) => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  editingId.value = row.id
  form.target_type = row.update_mode === 'create' ? 'new' : 'existing'
  form.selectedBookId = row.update_mode === 'create' ? undefined : row.book_id
  form.update_mode = row.update_mode === 'full' ? 'full' : 'append'
  form.title = row.title || ''
  form.description = row.description || ''
  form.cover = row.cover || ''
  coverFile.value = null
  coverFileName.value = ''
  chapterDrafts.value = (row.chapters || []).map((chapter) => toEditableChapter(chapter))
  if (!chapterDrafts.value.length) {
    chapterDrafts.value = [toEditableChapter({ title: '第一章' })]
  }
  if (form.target_type === 'existing' && form.selectedBookId) {
    await loadPublishedChapters(form.selectedBookId)
  } else {
    publishedChapters.value = []
  }
  dialogVisible.value = true
}

const onCoverFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0] || null
  coverFile.value = file
  coverFileName.value = file?.name || ''
}

const triggerCoverUpload = () => {
  coverInputRef.value?.click()
}

const goHome = () => {
  router.push('/')
}

const validateChapters = () => {
  const normalized = chapterDrafts.value
    .map((chapter) => ({
      section_key: chapter.section_key || undefined,
      title: chapter.title.trim(),
      content_text: chapter.content_text.trim(),
    }))
    .filter((chapter) => chapter.title || chapter.content_text)

  if (!normalized.length) {
    ElMessage.warning('请至少填写一个章节')
    return null
  }

  const invalidIndex = normalized.findIndex((chapter) => !chapter.title || !chapter.content_text)
  if (invalidIndex >= 0) {
    ElMessage.warning(`第 ${invalidIndex + 1} 个章节的标题和正文都需要填写`)
    return null
  }

  return normalized
}

const buildFormData = () => {
  const chapters = validateChapters()
  if (!chapters) return null

  const fd = new FormData()
  fd.append('title', form.title)
  fd.append('update_mode', form.target_type === 'existing' ? form.update_mode : 'create')
  fd.append('chapters_json', JSON.stringify(chapters))
  if (form.target_type === 'existing' && form.selectedBookId) {
    fd.append('book_id', String(form.selectedBookId))
  }
  if (form.description) fd.append('description', form.description)
  if (form.cover) fd.append('cover', form.cover)
  if (coverFile.value) fd.append('cover_file', coverFile.value)
  return fd
}

const loadBooks = async () => {
  try {
    const res = await getCreatorBooks()
    creatorBooks.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载作者书籍失败')
  }
}

const loadManuscripts = async () => {
  loading.value = true
  try {
    const res = await getCreatorManuscripts({ status: statusFilter.value || undefined })
    manuscripts.value = res.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载稿件失败')
  } finally {
    loading.value = false
  }
}

const reloadAll = async () => {
  await Promise.all([loadBooks(), loadManuscripts()])
}

const onSaveDraft = async () => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  if (!formRef.value) return
  formRef.value.validate(async (valid) => {
    if (!valid) return
    const fd = buildFormData()
    if (!fd) return
    submitLoading.value = true
    try {
      if (editingId.value) {
        await updateCreatorManuscript(editingId.value, fd)
        ElMessage.success('草稿已更新')
      } else {
        await createCreatorManuscript(fd)
        ElMessage.success('草稿已创建')
      }
      dialogVisible.value = false
      await reloadAll()
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '保存失败')
    } finally {
      submitLoading.value = false
    }
  })
}

const onSubmit = async (row: CreatorManuscriptItem) => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  try {
    await ElMessageBox.confirm(`确认提交《${row.title}》进入审核吗？`, '提交审核', { type: 'warning' })
    await submitCreatorManuscript(row.id)
    ElMessage.success('已提交审核')
    await loadManuscripts()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '提交失败')
    }
  }
}

const bootstrap = async () => {
  await loadCreatorProfile()
  await reloadAll()
  const routeBookId = Number(route.query.bookId || 0)
  if (route.query.create === '1' && routeBookId > 0) {
    await openCreateDialogForExistingBook(routeBookId)
  }
}

onMounted(bootstrap)
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

.hint {
  font-size: 12px;
  color: #606266;
  margin-top: 6px;
}

.hint.block {
  display: block;
}

.file-input {
  display: none;
}

.chapter-layout {
  display: grid;
  grid-template-columns: minmax(300px, 360px) minmax(0, 1fr);
  gap: 16px;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.panel-actions {
  display: flex;
  gap: 8px;
}

.chapter-list,
.draft-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.published-item,
.draft-item {
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  padding: 12px;
}

.published-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.published-title {
  font-weight: 600;
  color: #111827;
}

.published-meta,
.empty-text {
  color: #6b7280;
  font-size: 13px;
}

.draft-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.draft-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
}

.draft-actions {
  display: flex;
  gap: 6px;
}

.chapter-input {
  margin-bottom: 12px;
}

@media (max-width: 960px) {
  .chapter-layout {
    grid-template-columns: 1fr;
  }
}
</style>
