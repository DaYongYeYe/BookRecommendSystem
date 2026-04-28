<template>
  <div class="page">
    <div class="toolbar">
      <div>
        <h2>我的作品</h2>
        <p class="subtitle">管理作品基础资料、分类标签、封面、审核状态与上下架流程。</p>
      </div>
      <div class="actions">
        <el-button @click="reloadAll">刷新</el-button>
        <el-button @click="router.push('/creator/manuscripts')">历史稿件</el-button>
        <el-button type="primary" :disabled="!hasPenName()" @click="openCreateDrawer">新建作品</el-button>
      </div>
    </div>

    <el-alert
      v-if="!hasPenName()"
      title="进入创作者后台前请先设置笔名，作品展示将默认使用笔名作为作者名。"
      type="warning"
      show-icon
      :closable="false"
      class="notice"
    />

    <div class="summary-grid">
      <el-card shadow="hover">
        <div class="summary-label">作品总数</div>
        <div class="summary-value">{{ summary.total || 0 }}</div>
      </el-card>
      <el-card shadow="hover">
        <div class="summary-label">已上架</div>
        <div class="summary-value">{{ summary.up || 0 }}</div>
      </el-card>
      <el-card shadow="hover">
        <div class="summary-label">待审核</div>
        <div class="summary-value">{{ summary.pending || 0 }}</div>
      </el-card>
      <el-card shadow="hover">
        <div class="summary-label">已完结</div>
        <div class="summary-value">{{ summary.completed || 0 }}</div>
      </el-card>
    </div>

    <el-card class="filter-card" shadow="never">
      <div class="filters">
        <el-input v-model="filters.keyword" placeholder="搜索作品名" clearable style="width: 220px" @keyup.enter="loadWorks" />
        <el-select v-model="filters.audit_status" clearable placeholder="审核状态" style="width: 140px" @change="loadWorks">
          <el-option label="草稿" value="draft" />
          <el-option label="待审核" value="pending" />
          <el-option label="已通过" value="approved" />
          <el-option label="已驳回" value="rejected" />
        </el-select>
        <el-select v-model="filters.shelf_status" clearable placeholder="上架状态" style="width: 140px" @change="loadWorks">
          <el-option label="已上架" value="up" />
          <el-option label="已下架" value="down" />
          <el-option label="强制下架" value="forced_down" />
        </el-select>
        <el-select v-model="filters.completion_status" clearable placeholder="连载状态" style="width: 140px" @change="loadWorks">
          <el-option label="连载中" value="ongoing" />
          <el-option label="暂停" value="paused" />
          <el-option label="已完结" value="completed" />
        </el-select>
        <el-switch v-model="filters.recycle" active-text="回收站" inactive-text="作品列表" @change="loadWorks" />
        <el-button @click="loadWorks">查询</el-button>
      </div>
    </el-card>

    <el-card>
      <el-table :data="works" v-loading="loading" border>
        <el-table-column prop="title" label="作品" min-width="220">
          <template #default="{ row }">
            <div class="title-cell">
              <el-image v-if="row.cover" :src="row.cover" fit="cover" class="cover-thumb" />
              <div>
                <div class="work-title">{{ row.title }}</div>
                <div class="work-meta">{{ row.category_name || '未分类' }} / {{ completionStatusLabel(row.completion_status) }}</div>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="标签" min-width="180">
          <template #default="{ row }">
            <el-space wrap>
              <el-tag v-for="tag in row.tags || []" :key="tag.id" size="small">{{ tag.label }}</el-tag>
              <span v-if="!row.tags?.length">-</span>
            </el-space>
          </template>
        </el-table-column>
        <el-table-column label="审核状态" width="120">
          <template #default="{ row }">
            <el-tag :type="auditStatusTagType(row.audit_status)">{{ auditStatusLabel(row.audit_status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="上架状态" width="120">
          <template #default="{ row }">
            <el-tag :type="shelfStatusTagType(row.shelf_status)">{{ shelfStatusLabel(row.shelf_status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="章节数" width="100">
          <template #default="{ row }">{{ row.section_count || 0 }}</template>
        </el-table-column>
        <el-table-column label="准备度" width="140">
          <template #default="{ row }">
            <el-tag :type="row.ready_for_publish ? 'success' : row.ready_for_audit ? 'warning' : 'info'">
              {{ row.ready_for_publish ? '可上架' : row.ready_for_audit ? '可提审' : '待完善' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="updated_at" label="更新时间" width="180" />
        <el-table-column label="操作" width="320" fixed="right">
          <template #default="{ row }">
            <template v-if="filters.recycle">
              <el-button link type="success" @click="onRestoreWork(row)">恢复</el-button>
            </template>
            <template v-else>
              <el-button link type="primary" @click="openEditDrawer(row.id)">编辑</el-button>
              <el-button
                link
                type="success"
                :disabled="!['draft', 'rejected'].includes(row.audit_status || 'draft')"
                @click="submitAudit(row)"
              >
                提审
              </el-button>
              <el-button
                link
                :type="row.shelf_status === 'up' ? 'warning' : 'success'"
                :disabled="row.shelf_status === 'forced_down'"
                @click="toggleShelf(row)"
              >
                {{ row.shelf_status === 'up' ? '下架' : '上架' }}
              </el-button>
              <el-dropdown @command="(command) => changeCompletionStatus(row, command)">
                <el-button link>状态</el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="ongoing">设为连载中</el-dropdown-item>
                    <el-dropdown-item command="paused">设为暂停</el-dropdown-item>
                    <el-dropdown-item command="completed">设为完结</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
              <el-button link @click="goWriteChapters(row.id)">去写章节</el-button>
              <el-button link type="danger" @click="onDeleteWork(row)">删除</el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="drawerVisible" :title="editingId ? '编辑作品' : '新建作品'" size="720px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="110px">
        <el-form-item label="书名" prop="title">
          <el-input v-model="form.title" maxlength="255" show-word-limit />
        </el-form-item>
        <el-form-item label="副标题">
          <el-input v-model="form.subtitle" maxlength="255" show-word-limit />
        </el-form-item>
        <el-form-item label="作品简介">
          <el-input v-model="form.description" type="textarea" :rows="4" maxlength="2000" show-word-limit />
          <div class="hint">提审时简介不少于 {{ options.rules.description_min_length }} 字。</div>
        </el-form-item>
        <el-form-item label="主分类">
          <el-select v-model="form.category_id" placeholder="请选择主分类" style="width: 100%" @change="onCategoryChange">
            <el-option v-for="item in options.categories" :key="item.id" :label="item.name" :value="item.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="子分类">
          <el-select v-model="form.subcategory_code" clearable placeholder="可选" style="width: 100%">
            <el-option v-for="item in currentSubcategories" :key="item.code" :label="item.name" :value="item.code" />
          </el-select>
        </el-form-item>
        <el-form-item label="标签">
          <el-select
            v-model="form.tag_ids"
            multiple
            filterable
            clearable
            :multiple-limit="options.rules.tag_max_count"
            placeholder="请选择标签"
            style="width: 100%"
          >
            <el-option v-for="item in currentTagCandidates" :key="item.id" :label="item.label" :value="item.id" />
          </el-select>
          <div class="hint">建议选择 {{ options.rules.tag_min_count }}-{{ options.rules.tag_max_count }} 个标签。</div>
          <div class="recommended-tags" v-if="currentTagCandidates.length">
            <el-tag
              v-for="item in currentTagCandidates"
              :key="item.id"
              class="recommended-tag"
              :type="form.tag_ids.includes(item.id) ? 'success' : 'info'"
              @click="toggleRecommendedTag(item.id)"
            >
              {{ item.label }}
            </el-tag>
          </div>
        </el-form-item>
        <el-form-item label="封面">
          <input ref="coverInputRef" class="file-input" type="file" accept=".jpg,.jpeg,.png,.webp" @change="onCoverFileChange" />
          <div class="cover-row">
            <el-button @click="coverInputRef?.click()">选择文件</el-button>
            <span class="hint">支持 {{ options.rules.cover_formats.join(' / ').toUpperCase() }}，建议比例 {{ options.rules.cover_ratio_hint }}</span>
          </div>
          <div v-if="coverPreview" class="cover-preview-wrap">
            <el-image :src="coverPreview" fit="cover" class="cover-preview" />
            <el-button link type="danger" @click="clearCover">移除封面</el-button>
          </div>
        </el-form-item>
        <el-row :gutter="12">
          <el-col :span="12">
            <el-form-item label="连载状态">
              <el-select v-model="form.completion_status" style="width: 100%">
                <el-option label="连载中" value="ongoing" />
                <el-option label="暂停" value="paused" />
                <el-option label="已完结" value="completed" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="收费模式">
              <el-select v-model="form.price_type" style="width: 100%">
                <el-option label="免费" value="free" />
                <el-option label="付费" value="paid" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item label="作品属性">
          <el-radio-group v-model="form.creation_type">
            <el-radio value="original">原创</el-radio>
            <el-radio value="fanfic">同人</el-radio>
            <el-radio value="derivative">衍生</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="主角设定">
          <el-input v-model="form.protagonist" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="世界观设定">
          <el-input v-model="form.worldview" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="作者寄语">
          <el-input v-model="form.author_message" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="作者公告">
          <el-input v-model="form.author_notice" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="版权声明">
          <el-input v-model="form.copyright_notice" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="更新说明">
          <el-input v-model="form.update_note" type="textarea" :rows="2" />
        </el-form-item>
      </el-form>

      <el-card shadow="never" class="check-card">
        <template #header>
          <div class="panel-header">上架检查项</div>
        </template>
        <div class="check-grid">
          <div :class="['check-item', form.category_id ? 'ok' : 'todo']">主分类</div>
          <div :class="['check-item', (form.description || '').trim().length >= options.rules.description_min_length ? 'ok' : 'todo']">
            简介
          </div>
          <div :class="['check-item', !!coverPreview ? 'ok' : 'todo']">封面</div>
          <div :class="['check-item', form.tag_ids.length >= options.rules.tag_min_count ? 'ok' : 'todo']">标签</div>
        </div>
      </el-card>

      <template #footer>
        <div class="drawer-footer">
          <el-button @click="drawerVisible = false">取消</el-button>
          <el-button :loading="submitLoading" @click="saveWork(false)">保存草稿</el-button>
          <el-button type="primary" :loading="submitLoading" @click="saveWork(true)">保存并提审</el-button>
        </div>
      </template>
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
        <div class="hint">笔名会用于作品作者展示，也会同步到章节与作品管理模块。</div>
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
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import {
  createCreatorWork,
  deleteCreatorWork,
  getCreatorWorkDetail,
  getCreatorWorkOptions,
  getCreatorWorks,
  restoreCreatorWork,
  submitCreatorWorkAudit,
  updateCreatorWork,
  updateCreatorWorkCompletionStatus,
  updateCreatorWorkShelf,
  type CreatorWorkCategoryItem,
  type CreatorWorkItem,
} from '@/api/creator'
import { useCreatorPenName } from '@/composables/useCreatorPenName'

const router = useRouter()
const loading = ref(false)
const submitLoading = ref(false)
const works = ref<CreatorWorkItem[]>([])
const summary = reactive<Record<string, number>>({
  total: 0,
  up: 0,
  pending: 0,
  completed: 0,
})

const options = reactive<{
  categories: CreatorWorkCategoryItem[]
  rules: {
    description_min_length: number
    tag_min_count: number
    tag_max_count: number
    cover_formats: string[]
    cover_max_size: number
    cover_ratio_hint: string
  }
}>({
  categories: [],
  rules: {
    description_min_length: 20,
    tag_min_count: 3,
    tag_max_count: 8,
    cover_formats: ['jpg', 'png', 'webp'],
    cover_max_size: 5 * 1024 * 1024,
    cover_ratio_hint: '3:4',
  },
})

const filters = reactive({
  keyword: '',
  audit_status: '',
  shelf_status: '',
  completion_status: '',
  recycle: false,
})

const drawerVisible = ref(false)
const editingId = ref<number | null>(null)
const formRef = ref<FormInstance>()
const coverInputRef = ref<HTMLInputElement | null>(null)
const coverFile = ref<File | null>(null)
const coverPreview = ref('')
const originalSnapshot = ref<Record<string, any> | null>(null)

const form = reactive({
  title: '',
  subtitle: '',
  description: '',
  category_id: undefined as number | undefined,
  subcategory_code: '',
  tag_ids: [] as number[],
  completion_status: 'ongoing' as 'ongoing' | 'paused' | 'completed',
  price_type: 'free' as 'free' | 'paid',
  creation_type: 'original' as 'original' | 'fanfic' | 'derivative',
  protagonist: '',
  worldview: '',
  author_message: '',
  author_notice: '',
  copyright_notice: '',
  update_note: '',
  cover: '',
})

const rules: FormRules = {
  title: [{ required: true, message: '请输入书名', trigger: 'blur' }],
}

const { penNameDialogVisible, penNameForm, saving, loadCreatorProfile, savePenName, hasPenName } = useCreatorPenName()

const currentCategory = computed(() => options.categories.find((item) => item.id === form.category_id))
const currentSubcategories = computed(() => currentCategory.value?.subcategories || [])
const currentTagCandidates = computed(() => currentCategory.value?.tag_candidates || [])

const resetForm = () => {
  editingId.value = null
  originalSnapshot.value = null
  form.title = ''
  form.subtitle = ''
  form.description = ''
  form.category_id = undefined
  form.subcategory_code = ''
  form.tag_ids = []
  form.completion_status = 'ongoing'
  form.price_type = 'free'
  form.creation_type = 'original'
  form.protagonist = ''
  form.worldview = ''
  form.author_message = ''
  form.author_notice = ''
  form.copyright_notice = ''
  form.update_note = ''
  form.cover = ''
  coverFile.value = null
  coverPreview.value = ''
}

const auditStatusLabel = (value?: string) => {
  if (value === 'pending') return '待审核'
  if (value === 'approved') return '已通过'
  if (value === 'rejected') return '已驳回'
  if (value === 'draft') return '草稿'
  return value || '-'
}

const auditStatusTagType = (value?: string) => {
  if (value === 'approved') return 'success'
  if (value === 'pending') return 'warning'
  if (value === 'rejected') return 'danger'
  return 'info'
}

const shelfStatusLabel = (value?: string) => {
  if (value === 'up') return '已上架'
  if (value === 'forced_down') return '强制下架'
  return '已下架'
}

const shelfStatusTagType = (value?: string) => {
  if (value === 'up') return 'success'
  if (value === 'forced_down') return 'danger'
  return 'info'
}

const completionStatusLabel = (value?: string) => {
  if (value === 'completed') return '已完结'
  if (value === 'paused') return '暂停'
  return '连载中'
}

const loadOptions = async () => {
  const res = await getCreatorWorkOptions()
  options.categories = res.categories || []
  options.rules = res.rules || options.rules
}

const loadWorks = async () => {
  loading.value = true
  try {
    const res = await getCreatorWorks({
      keyword: filters.keyword || undefined,
      audit_status: filters.audit_status || undefined,
      shelf_status: filters.shelf_status || undefined,
      completion_status: filters.completion_status || undefined,
      recycle: filters.recycle ? true : undefined,
    })
    works.value = res.items || []
    Object.assign(summary, res.summary || {})
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载作品列表失败')
  } finally {
    loading.value = false
  }
}

const reloadAll = async () => {
  await Promise.all([loadOptions(), loadWorks()])
}

const fillForm = (item: CreatorWorkItem) => {
  form.title = item.title || ''
  form.subtitle = item.subtitle || ''
  form.description = item.description || ''
  form.category_id = item.category_id || undefined
  form.subcategory_code = item.subcategory_code || ''
  form.tag_ids = [...(item.tag_ids || [])]
  form.completion_status = (item.completion_status as 'ongoing' | 'paused' | 'completed') || 'ongoing'
  form.price_type = (item.price_type as 'free' | 'paid') || 'free'
  form.creation_type = (item.creation_type as 'original' | 'fanfic' | 'derivative') || 'original'
  form.protagonist = item.protagonist || ''
  form.worldview = item.worldview || ''
  form.author_message = item.author_message || ''
  form.author_notice = item.author_notice || ''
  form.copyright_notice = item.copyright_notice || ''
  form.update_note = item.update_note || ''
  form.cover = item.cover || ''
  coverPreview.value = item.cover || ''
  coverFile.value = null
  originalSnapshot.value = {
    title: item.title || '',
    category_id: item.category_id || undefined,
  }
}

const openCreateDrawer = () => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  resetForm()
  drawerVisible.value = true
}

const openEditDrawer = async (bookId: number) => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  try {
    const res = await getCreatorWorkDetail(bookId)
    editingId.value = bookId
    fillForm(res.item)
    drawerVisible.value = true
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载作品详情失败')
  }
}

const onCategoryChange = () => {
  form.subcategory_code = ''
  form.tag_ids = form.tag_ids.filter((id) => currentTagCandidates.value.some((item) => item.id === id))
}

const toggleRecommendedTag = (tagId: number) => {
  if (form.tag_ids.includes(tagId)) {
    form.tag_ids = form.tag_ids.filter((item) => item !== tagId)
    return
  }
  if (form.tag_ids.length >= options.rules.tag_max_count) {
    ElMessage.warning(`最多选择 ${options.rules.tag_max_count} 个标签`)
    return
  }
  form.tag_ids = [...form.tag_ids, tagId]
}

const onCoverFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0] || null
  if (!file) return
  if (file.size > options.rules.cover_max_size) {
    ElMessage.warning('封面文件过大，请重新选择')
    target.value = ''
    return
  }
  coverFile.value = file
  coverPreview.value = URL.createObjectURL(file)
}

const clearCover = () => {
  coverFile.value = null
  form.cover = ''
  coverPreview.value = ''
  if (coverInputRef.value) {
    coverInputRef.value.value = ''
  }
}

const buildFormData = () => {
  const fd = new FormData()
  fd.append('title', form.title)
  if (form.subtitle) fd.append('subtitle', form.subtitle)
  if (form.description) fd.append('description', form.description)
  if (form.category_id) fd.append('category_id', String(form.category_id))
  if (form.subcategory_code) fd.append('subcategory_code', form.subcategory_code)
  fd.append('tag_ids_json', JSON.stringify(form.tag_ids))
  fd.append('completion_status', form.completion_status)
  fd.append('price_type', form.price_type)
  fd.append('creation_type', form.creation_type)
  if (form.protagonist) fd.append('protagonist', form.protagonist)
  if (form.worldview) fd.append('worldview', form.worldview)
  if (form.author_message) fd.append('author_message', form.author_message)
  if (form.author_notice) fd.append('author_notice', form.author_notice)
  if (form.copyright_notice) fd.append('copyright_notice', form.copyright_notice)
  if (form.update_note) fd.append('update_note', form.update_note)
  if (form.cover) fd.append('cover', form.cover)
  if (coverFile.value) fd.append('cover_file', coverFile.value)
  return fd
}

const maybeConfirmCriticalChanges = async () => {
  if (!editingId.value || !originalSnapshot.value) return true
  const changedTitle = originalSnapshot.value.title !== form.title
  const changedCategory = originalSnapshot.value.category_id !== form.category_id
  if (!changedTitle && !changedCategory) return true
  try {
    await ElMessageBox.confirm('修改书名或主分类可能影响推荐结果，并可能触发重新审核，是否继续？', '二次确认', {
      type: 'warning',
    })
    return true
  } catch {
    return false
  }
}

const saveWork = async (submitAuditAfterSave: boolean) => {
  if (!hasPenName()) {
    penNameDialogVisible.value = true
    return
  }
  if (!(await maybeConfirmCriticalChanges())) return
  await formRef.value?.validate()
  submitLoading.value = true
  try {
    const data = buildFormData()
    let bookId = editingId.value
    let reAuditRequired = false
    if (editingId.value) {
      const res = await updateCreatorWork(editingId.value, data)
      bookId = editingId.value
      reAuditRequired = Boolean(res.re_audit_required)
      ElMessage.success(reAuditRequired ? '作品已保存，核心信息变更后将重新进入审核流转' : '作品已保存')
    } else {
      const res = await createCreatorWork(data)
      bookId = res.item?.id
      ElMessage.success('作品已创建')
    }

    if (submitAuditAfterSave && bookId) {
      await submitCreatorWorkAudit(bookId)
      ElMessage.success('作品已提交审核')
    }

    drawerVisible.value = false
    await loadWorks()
    if (!editingId.value && bookId) {
      await ElMessageBox.confirm('作品已创建，是否现在去发布首章？', '下一步建议', {
        confirmButtonText: '去写首章',
        cancelButtonText: '稍后再说',
        type: 'success',
      }).then(() => {
        goWriteChapters(bookId!)
      }).catch(() => {})
    }
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存失败')
  } finally {
    submitLoading.value = false
  }
}

const submitAudit = async (row: CreatorWorkItem) => {
  try {
    await ElMessageBox.confirm(`确认提交《${row.title}》进入审核吗？`, '提交审核', { type: 'warning' })
    await submitCreatorWorkAudit(row.id)
    ElMessage.success('已提交审核')
    await loadWorks()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '提交审核失败')
    }
  }
}

const toggleShelf = async (row: CreatorWorkItem) => {
  const isUp = row.shelf_status === 'up'
  try {
    if (isUp) {
      const { value } = await ElMessageBox.prompt('下架原因可选填写，便于后续恢复时回顾。', '下架作品', {
        confirmButtonText: '确认下架',
        cancelButtonText: '取消',
        inputPlaceholder: '例如：封面整改、资料完善中',
      })
      await updateCreatorWorkShelf(row.id, { action: 'down', reason: value || undefined })
      ElMessage.success('作品已下架')
    } else {
      await ElMessageBox.confirm(`确认上架《${row.title}》吗？`, '上架作品', { type: 'warning' })
      await updateCreatorWorkShelf(row.id, { action: 'up' })
      ElMessage.success('作品已上架')
    }
    await loadWorks()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      const detail = error?.response?.data?.details
      const detailMessage = Array.isArray(detail) && detail.length ? `：${detail.join('；')}` : ''
      ElMessage.error((error?.response?.data?.error || '状态更新失败') + detailMessage)
    }
  }
}

const onDeleteWork = async (row: CreatorWorkItem) => {
  try {
    await ElMessageBox.confirm(`确认将《${row.title}》移入回收站吗？`, '删除作品', { type: 'warning' })
    await deleteCreatorWork(row.id)
    ElMessage.success('作品已移入回收站')
    await loadWorks()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '删除作品失败')
    }
  }
}

const onRestoreWork = async (row: CreatorWorkItem) => {
  try {
    await restoreCreatorWork(row.id)
    ElMessage.success('作品已恢复')
    await loadWorks()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '恢复作品失败')
  }
}

const changeCompletionStatus = async (row: CreatorWorkItem, nextStatus: 'ongoing' | 'paused' | 'completed') => {
  try {
    if (nextStatus === 'completed') {
      await ElMessageBox.confirm('作品将被标记为已完结，后续继续发布章节时建议改回“连载中”，是否确认？', '完结确认', {
        type: 'warning',
      })
    }
    await updateCreatorWorkCompletionStatus(row.id, {
      completion_status: nextStatus,
      confirm: nextStatus === 'completed' ? true : undefined,
    })
    ElMessage.success('作品状态已更新')
    await loadWorks()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '更新作品状态失败')
    }
  }
}

const goWriteChapters = (bookId: number) => {
  router.push({ path: `/creator/books/${bookId}/chapters` })
}

const bootstrap = async () => {
  await loadCreatorProfile()
  await reloadAll()
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

.actions,
.filters {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.notice,
.filter-card,
.summary-grid {
  margin-bottom: 16px;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.summary-label {
  color: #6b7280;
  font-size: 13px;
}

.summary-value {
  margin-top: 8px;
  font-size: 28px;
  font-weight: 700;
  color: #111827;
}

.title-cell {
  display: flex;
  align-items: center;
  gap: 12px;
}

.cover-thumb {
  width: 44px;
  height: 58px;
  border-radius: 8px;
  overflow: hidden;
  background: #f3f4f6;
}

.work-title {
  font-weight: 600;
  color: #111827;
}

.work-meta,
.hint {
  color: #6b7280;
  font-size: 12px;
  margin-top: 4px;
}

.recommended-tags {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 10px;
}

.recommended-tag {
  cursor: pointer;
}

.file-input {
  display: none;
}

.cover-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.cover-preview-wrap {
  margin-top: 12px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.cover-preview {
  width: 120px;
  height: 160px;
  border-radius: 14px;
  overflow: hidden;
  background: #f3f4f6;
}

.check-card {
  margin-top: 20px;
}

.panel-header {
  font-weight: 600;
}

.check-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.check-item {
  border-radius: 12px;
  padding: 12px;
  text-align: center;
  font-size: 13px;
}

.check-item.ok {
  background: #ecfdf5;
  color: #047857;
}

.check-item.todo {
  background: #fef3c7;
  color: #92400e;
}

.drawer-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  width: 100%;
}

@media (max-width: 960px) {
  .summary-grid,
  .check-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 640px) {
  .summary-grid,
  .check-grid {
    grid-template-columns: 1fr;
  }
}
</style>
