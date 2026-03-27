<template>
  <div class="admin-page">
    <div class="toolbar">
      <h2>书本管理</h2>
      <div class="actions">
        <el-input v-model="keyword" placeholder="搜索书名或作者" clearable style="width: 260px" @keyup.enter="loadBooks" />
        <el-button @click="loadBooks">查询</el-button>
        <el-button type="primary" @click="openCreateDialog">新增图书</el-button>
      </div>
    </div>

    <div class="batch-bar">
      <span>已选择 {{ selectedRows.length }} 本图书</span>
      <div class="batch-actions">
        <el-button :disabled="selectedRows.length === 0" @click="onBatchSetStatus('published')">批量上架</el-button>
        <el-button :disabled="selectedRows.length === 0" @click="onBatchSetStatus('draft')">批量下架</el-button>
        <el-button type="primary" :disabled="selectedRows.length === 0" @click="batchDialogVisible = true">批量编辑</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="books" v-loading="loading" border @selection-change="onSelectionChange">
        <el-table-column type="selection" width="48" />
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="title" label="书名" min-width="180" />
        <el-table-column prop="author" label="作者" width="160" />
        <el-table-column label="分类" width="120">
          <template #default="{ row }">{{ row.category_name || '-' }}</template>
        </el-table-column>
        <el-table-column label="标签" min-width="180">
          <template #default="{ row }">
            <el-space wrap>
              <el-tag v-for="tag in row.tags || []" :key="tag.id" size="small">{{ tag.label }}</el-tag>
              <span v-if="!row.tags || row.tags.length === 0">-</span>
            </el-space>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusTagType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rating" label="评分" width="90" />
        <el-table-column prop="rating_count" label="评分人数" width="110" />
        <el-table-column prop="recent_reads" label="近期阅读" width="110" />
        <el-table-column label="推荐" width="90">
          <template #default="{ row }">
            <el-tag :type="row.is_featured ? 'success' : 'info'">{{ row.is_featured ? '是' : '否' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="260" fixed="right">
          <template #default="{ row }">
            <el-button link type="info" @click="onPreview(row)">预览</el-button>
            <el-button link type="primary" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="danger" @click="onDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          :current-page="page"
          :page-size="pageSize"
          :total="total"
          layout="total, sizes, prev, pager, next"
          :page-sizes="[10, 20, 50]"
          @current-change="onCurrentPageChange"
          @size-change="onPageSizeChange"
        />
      </div>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="isEditMode ? '编辑图书' : '新增图书'" width="720px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="100px">
        <el-form-item label="书名" prop="title"><el-input v-model="form.title" /></el-form-item>
        <el-form-item label="副标题"><el-input v-model="form.subtitle" /></el-form-item>
        <el-form-item label="作者"><el-input v-model="form.author" /></el-form-item>
        <el-form-item label="封面 URL"><el-input v-model="form.cover" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="form.description" type="textarea" :rows="3" /></el-form-item>
        <el-row :gutter="12">
          <el-col :span="12">
            <el-form-item label="分类">
              <el-select v-model="form.category_id" style="width: 100%" clearable placeholder="请选择分类">
                <el-option v-for="item in categories" :key="item.id" :label="item.name" :value="item.id" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="状态" prop="status">
              <el-select v-model="form.status" style="width: 100%">
                <el-option v-for="item in statuses" :key="item.value" :label="statusLabel(item.value)" :value="item.value" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item label="标签">
          <el-select v-model="form.tag_ids" multiple filterable clearable style="width: 100%" placeholder="请选择标签">
            <el-option v-for="item in tags" :key="item.id" :label="item.label" :value="item.id" />
          </el-select>
        </el-form-item>
        <el-row :gutter="12">
          <el-col :span="12"><el-form-item label="评分"><el-input-number v-model="form.rating" :min="0" :max="10" :step="0.1" style="width: 100%" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="综合分"><el-input-number v-model="form.score" :min="0" :max="10" :step="0.1" style="width: 100%" /></el-form-item></el-col>
        </el-row>
        <el-row :gutter="12">
          <el-col :span="12"><el-form-item label="评分人数"><el-input-number v-model="form.rating_count" :min="0" style="width: 100%" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="近期阅读"><el-input-number v-model="form.recent_reads" :min="0" style="width: 100%" /></el-form-item></el-col>
        </el-row>
        <el-form-item label="首页推荐">
          <el-switch v-model="form.is_featured" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="onSubmit">{{ isEditMode ? '保存' : '创建' }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="batchDialogVisible" title="批量编辑图书" width="620px">
      <el-form label-width="110px">
        <el-alert type="info" :closable="false" style="margin-bottom: 12px">
          将对已选中的 {{ selectedRows.length }} 本图书进行更新。
        </el-alert>
        <el-form-item label="批量状态">
          <el-select v-model="batchForm.status" clearable style="width: 100%" placeholder="不修改">
            <el-option v-for="item in statuses" :key="item.value" :label="statusLabel(item.value)" :value="item.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="批量分类">
          <el-select v-model="batchForm.category_id" clearable style="width: 100%" placeholder="不修改">
            <el-option label="清空分类" :value="0" />
            <el-option v-for="item in categories" :key="item.id" :label="item.name" :value="item.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="首页推荐">
          <el-radio-group v-model="batchForm.is_featured">
            <el-radio :label="null">不修改</el-radio>
            <el-radio :label="true">设为推荐</el-radio>
            <el-radio :label="false">取消推荐</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="批量标签">
          <el-select v-model="batchForm.tag_ids" multiple filterable clearable style="width: 100%" placeholder="不修改">
            <el-option v-for="item in tags" :key="item.id" :label="item.label" :value="item.id" />
          </el-select>
          <div class="tip">留空表示不修改；选择后会覆盖原有标签。</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="batchDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="batchLoading" @click="onBatchSubmit">确认批量更新</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import {
  AdminBookItem,
  batchUpdateAdminBooks,
  createAdminBook,
  deleteAdminBook,
  getAdminBookOptions,
  getAdminBooks,
  updateAdminBook,
} from '../../api/admin'

type BookStatus = 'published' | 'draft' | 'archived'
type BookTag = { id: number; label: string }
type BookCategory = { id: number; name: string }

const books = ref<AdminBookItem[]>([])
const loading = ref(false)
const keyword = ref('')
const page = ref(1)
const pageSize = ref(10)
const total = ref(0)
const selectedRows = ref<AdminBookItem[]>([])

const categories = ref<BookCategory[]>([])
const tags = ref<BookTag[]>([])
const statuses = ref<Array<{ value: BookStatus; label: string }>>([
  { value: 'published', label: 'published' },
  { value: 'draft', label: 'draft' },
  { value: 'archived', label: 'archived' },
])

const dialogVisible = ref(false)
const isEditMode = ref(false)
const submitLoading = ref(false)
const editingBookId = ref<number | null>(null)
const formRef = ref<FormInstance>()
const form = reactive({
  title: '',
  subtitle: '',
  author: '',
  description: '',
  cover: '',
  score: null as number | null,
  rating: null as number | null,
  rating_count: 0,
  recent_reads: 0,
  is_featured: false,
  category_id: null as number | null,
  status: 'published' as BookStatus,
  tag_ids: [] as number[],
})

const batchDialogVisible = ref(false)
const batchLoading = ref(false)
const batchForm = reactive({
  status: null as BookStatus | null,
  category_id: null as number | null,
  is_featured: null as boolean | null,
  tag_ids: null as number[] | null,
})

const rules: FormRules = {
  title: [{ required: true, message: '请输入书名', trigger: 'blur' }],
  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
}

const statusLabel = (status: string) => {
  if (status === 'published') return '上架'
  if (status === 'draft') return '下架'
  if (status === 'archived') return '归档'
  return status
}

const statusTagType = (status: string) => {
  if (status === 'published') return 'success'
  if (status === 'draft') return 'warning'
  if (status === 'archived') return 'info'
  return ''
}

const loadBookOptions = async () => {
  try {
    const res = await getAdminBookOptions()
    categories.value = res.categories || []
    tags.value = res.tags || []
    if (res.statuses?.length) {
      statuses.value = res.statuses
    }
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载图书选项失败')
  }
}

const loadBooks = async () => {
  loading.value = true
  try {
    const res = await getAdminBooks({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
    })
    books.value = res.books || []
    total.value = res.pagination?.total || 0
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载图书列表失败')
  } finally {
    loading.value = false
  }
}

const onCurrentPageChange = (value: number) => {
  page.value = value
  loadBooks()
}

const onPageSizeChange = (value: number) => {
  pageSize.value = value
  page.value = 1
  loadBooks()
}

const onSelectionChange = (rows: AdminBookItem[]) => {
  selectedRows.value = rows
}

const resetForm = () => {
  form.title = ''
  form.subtitle = ''
  form.author = ''
  form.description = ''
  form.cover = ''
  form.score = null
  form.rating = null
  form.rating_count = 0
  form.recent_reads = 0
  form.is_featured = false
  form.category_id = null
  form.status = 'published'
  form.tag_ids = []
}

const openCreateDialog = () => {
  isEditMode.value = false
  editingBookId.value = null
  resetForm()
  dialogVisible.value = true
}

const openEditDialog = (row: AdminBookItem) => {
  isEditMode.value = true
  editingBookId.value = row.id
  form.title = row.title || ''
  form.subtitle = row.subtitle || ''
  form.author = row.author || ''
  form.description = row.description || ''
  form.cover = row.cover || ''
  form.score = row.score ?? null
  form.rating = row.rating ?? null
  form.rating_count = row.rating_count || 0
  form.recent_reads = row.recent_reads || 0
  form.is_featured = !!row.is_featured
  form.category_id = row.category_id ?? null
  form.status = row.status || 'published'
  form.tag_ids = row.tag_ids || []
  dialogVisible.value = true
}

const onPreview = (row: AdminBookItem) => {
  window.open(`/books/${row.id}`, '_blank')
}

const onSubmit = async () => {
  if (!formRef.value) return
  formRef.value.validate(async (valid) => {
    if (!valid) return
    submitLoading.value = true
    try {
      const payload = {
        title: form.title,
        subtitle: form.subtitle || undefined,
        author: form.author || undefined,
        description: form.description || undefined,
        cover: form.cover || undefined,
        score: form.score,
        rating: form.rating,
        rating_count: form.rating_count,
        recent_reads: form.recent_reads,
        is_featured: form.is_featured,
        category_id: form.category_id,
        status: form.status,
        tag_ids: form.tag_ids,
      }
      if (isEditMode.value && editingBookId.value != null) {
        await updateAdminBook(editingBookId.value, payload)
        ElMessage.success('图书更新成功')
      } else {
        await createAdminBook(payload)
        ElMessage.success('图书创建成功')
      }
      dialogVisible.value = false
      loadBooks()
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '提交失败')
    } finally {
      submitLoading.value = false
    }
  })
}

const onDelete = async (row: AdminBookItem) => {
  try {
    await ElMessageBox.confirm(`确认删除图书 "${row.title}" 吗？`, '提示', { type: 'warning' })
    await deleteAdminBook(row.id)
    ElMessage.success('删除成功')
    loadBooks()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '删除失败')
    }
  }
}

const onBatchSetStatus = async (status: BookStatus) => {
  if (!selectedRows.value.length) return
  const ids = selectedRows.value.map((item) => item.id)
  try {
    await batchUpdateAdminBooks({
      book_ids: ids,
      changes: { status },
    })
    ElMessage.success(`已批量${status === 'published' ? '上架' : '下架'} ${ids.length} 本图书`)
    await loadBooks()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '批量操作失败')
  }
}

const onBatchSubmit = async () => {
  if (!selectedRows.value.length) return
  const changes: Record<string, any> = {}
  if (batchForm.status) changes.status = batchForm.status
  if (batchForm.category_id !== null) changes.category_id = batchForm.category_id === 0 ? null : batchForm.category_id
  if (batchForm.is_featured !== null) changes.is_featured = batchForm.is_featured
  if (batchForm.tag_ids !== null) changes.tag_ids = batchForm.tag_ids

  if (!Object.keys(changes).length) {
    ElMessage.warning('请至少选择一个批量修改项')
    return
  }

  batchLoading.value = true
  try {
    await batchUpdateAdminBooks({
      book_ids: selectedRows.value.map((item) => item.id),
      changes,
    })
    ElMessage.success('批量更新成功')
    batchDialogVisible.value = false
    batchForm.status = null
    batchForm.category_id = null
    batchForm.is_featured = null
    batchForm.tag_ids = null
    await loadBooks()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '批量更新失败')
  } finally {
    batchLoading.value = false
  }
}

onMounted(async () => {
  await loadBookOptions()
  await loadBooks()
})
</script>

<style scoped>
.admin-page {
  padding: 20px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.actions {
  display: flex;
  gap: 12px;
}

.batch-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  padding: 10px 12px;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  background: #fafafa;
}

.batch-actions {
  display: flex;
  gap: 10px;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}

.tip {
  margin-top: 8px;
  color: #909399;
  font-size: 12px;
}
</style>
