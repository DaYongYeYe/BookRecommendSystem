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

    <el-card>
      <el-table :data="books" v-loading="loading" border>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="title" label="书名" min-width="180" />
        <el-table-column prop="author" label="作者" width="160" />
        <el-table-column prop="status" label="状态" width="100" />
        <el-table-column prop="rating" label="评分" width="90" />
        <el-table-column prop="rating_count" label="评分人数" width="110" />
        <el-table-column prop="recent_reads" label="近期阅读" width="110" />
        <el-table-column label="推荐" width="90">
          <template #default="{ row }">
            <el-tag :type="row.is_featured ? 'success' : 'info'">{{ row.is_featured ? '是' : '否' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180">
          <template #default="{ row }">
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

    <el-dialog v-model="dialogVisible" :title="isEditMode ? '编辑图书' : '新增图书'" width="640px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="100px">
        <el-form-item label="书名" prop="title"><el-input v-model="form.title" /></el-form-item>
        <el-form-item label="副标题"><el-input v-model="form.subtitle" /></el-form-item>
        <el-form-item label="作者"><el-input v-model="form.author" /></el-form-item>
        <el-form-item label="封面 URL"><el-input v-model="form.cover" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="form.description" type="textarea" :rows="3" /></el-form-item>
        <el-row :gutter="12">
          <el-col :span="12"><el-form-item label="评分"><el-input-number v-model="form.rating" :min="0" :max="10" :step="0.1" style="width: 100%" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="综合分"><el-input-number v-model="form.score" :min="0" :max="10" :step="0.1" style="width: 100%" /></el-form-item></el-col>
        </el-row>
        <el-row :gutter="12">
          <el-col :span="12"><el-form-item label="评分人数"><el-input-number v-model="form.rating_count" :min="0" style="width: 100%" /></el-form-item></el-col>
          <el-col :span="12"><el-form-item label="近期阅读"><el-input-number v-model="form.recent_reads" :min="0" style="width: 100%" /></el-form-item></el-col>
        </el-row>
        <el-form-item label="分类 ID"><el-input-number v-model="form.category_id" :min="1" style="width: 100%" /></el-form-item>
        <el-form-item label="首页推荐">
          <el-switch v-model="form.is_featured" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="onSubmit">{{ isEditMode ? '保存' : '创建' }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import { AdminBookItem, createAdminBook, deleteAdminBook, getAdminBooks, updateAdminBook } from '../../api/admin'

const books = ref<AdminBookItem[]>([])
const loading = ref(false)
const keyword = ref('')
const page = ref(1)
const pageSize = ref(10)
const total = ref(0)

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
})

const rules: FormRules = {
  title: [{ required: true, message: '请输入书名', trigger: 'blur' }],
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
  dialogVisible.value = true
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

onMounted(() => {
  loadBooks()
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
  margin-bottom: 16px;
}

.actions {
  display: flex;
  gap: 12px;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
