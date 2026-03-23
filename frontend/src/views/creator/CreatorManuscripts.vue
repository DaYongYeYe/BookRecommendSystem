<template>
  <div class="page">
    <div class="toolbar">
      <h2>创作者稿件</h2>
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
        <el-button @click="loadManuscripts">刷新</el-button>
        <el-button type="primary" @click="openCreateDialog">新建草稿</el-button>
      </div>
    </div>

    <el-card>
      <el-table :data="manuscripts" v-loading="loading" border>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="title" label="书名" min-width="220" />
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
              :disabled="!['draft', 'rejected'].includes(row.status)"
              @click="onSubmit(row)"
            >
              提交审核
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="editingId ? '编辑草稿' : '新建草稿'" width="760px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="90px">
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
          <div v-if="form.cover || coverFileName" class="hint">
            已选: {{ coverFileName || form.cover }}
          </div>
        </el-form-item>
        <el-form-item label="正文 txt">
          <input
            ref="contentInputRef"
            class="file-input"
            type="file"
            accept=".txt"
            @change="onContentFileChange"
          />
          <el-button @click="triggerContentUpload">选择文件</el-button>
          <div v-if="contentFileName" class="hint">已选: {{ contentFileName }}</div>
        </el-form-item>
        <el-form-item label="正文内容" prop="content_text">
          <el-input
            v-model="form.content_text"
            type="textarea"
            :rows="12"
            placeholder="可直接粘贴正文；或上传 txt 文件。"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitLoading" @click="onSaveDraft">保存草稿</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus'
import {
  CreatorManuscriptItem,
  createCreatorManuscript,
  getCreatorManuscripts,
  submitCreatorManuscript,
  updateCreatorManuscript,
} from '@/api/creator'

const loading = ref(false)
const submitLoading = ref(false)
const manuscripts = ref<CreatorManuscriptItem[]>([])
const statusFilter = ref('')
const router = useRouter()

const dialogVisible = ref(false)
const editingId = ref<number | null>(null)
const formRef = ref<FormInstance>()
const coverInputRef = ref<HTMLInputElement | null>(null)
const contentInputRef = ref<HTMLInputElement | null>(null)
const form = reactive({
  title: '',
  description: '',
  content_text: '',
  cover: '',
})
const coverFile = ref<File | null>(null)
const contentFile = ref<File | null>(null)
const coverFileName = ref('')
const contentFileName = ref('')

const rules: FormRules = {
  title: [{ required: true, message: '请输入书名', trigger: 'blur' }],
}

const statusTagType = (status: string) => {
  if (status === 'published') return 'success'
  if (status === 'approved') return 'warning'
  if (status === 'submitted') return 'info'
  if (status === 'rejected') return 'danger'
  return ''
}

const resetForm = () => {
  editingId.value = null
  form.title = ''
  form.description = ''
  form.content_text = ''
  form.cover = ''
  coverFile.value = null
  contentFile.value = null
  coverFileName.value = ''
  contentFileName.value = ''
}

const openCreateDialog = () => {
  resetForm()
  dialogVisible.value = true
}

const openEditDialog = (row: CreatorManuscriptItem) => {
  editingId.value = row.id
  form.title = row.title || ''
  form.description = row.description || ''
  form.content_text = row.content_text || ''
  form.cover = row.cover || ''
  coverFile.value = null
  contentFile.value = null
  coverFileName.value = ''
  contentFileName.value = ''
  dialogVisible.value = true
}

const onCoverFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0] || null
  coverFile.value = file
  coverFileName.value = file?.name || ''
}

const onContentFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0] || null
  contentFile.value = file
  contentFileName.value = file?.name || ''
}

const triggerCoverUpload = () => {
  coverInputRef.value?.click()
}

const triggerContentUpload = () => {
  contentInputRef.value?.click()
}

const goHome = () => {
  router.push('/')
}

const buildFormData = () => {
  const fd = new FormData()
  fd.append('title', form.title)
  if (form.description) fd.append('description', form.description)
  if (form.content_text) fd.append('content_text', form.content_text)
  if (form.cover) fd.append('cover', form.cover)
  if (coverFile.value) fd.append('cover_file', coverFile.value)
  if (contentFile.value) fd.append('content_file', contentFile.value)
  return fd
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

const onSaveDraft = async () => {
  if (!formRef.value) return
  formRef.value.validate(async (valid) => {
    if (!valid) return
    submitLoading.value = true
    try {
      const fd = buildFormData()
      if (editingId.value) {
        await updateCreatorManuscript(editingId.value, fd)
        ElMessage.success('草稿已更新')
      } else {
        await createCreatorManuscript(fd)
        ElMessage.success('草稿已创建')
      }
      dialogVisible.value = false
      await loadManuscripts()
    } catch (error: any) {
      ElMessage.error(error?.response?.data?.error || '保存失败')
    } finally {
      submitLoading.value = false
    }
  })
}

const onSubmit = async (row: CreatorManuscriptItem) => {
  try {
    await ElMessageBox.confirm(`确认提交《${row.title}》进行审核吗？`, '提交审核', { type: 'warning' })
    await submitCreatorManuscript(row.id)
    ElMessage.success('已提交审核')
    await loadManuscripts()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.error || '提交失败')
    }
  }
}

onMounted(() => {
  loadManuscripts()
})
</script>

<style scoped>
.page {
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

.hint {
  font-size: 12px;
  color: #606266;
  margin-top: 6px;
}

.file-input {
  display: none;
}
</style>
