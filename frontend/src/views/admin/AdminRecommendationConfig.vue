<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  createAdminRecommendationPlacement,
  deleteAdminRecommendationPlacement,
  getAdminBooks,
  getAdminRankingConfigs,
  getAdminRecommendationPlacements,
  saveAdminRankingConfig,
  updateAdminRecommendationPlacement,
  type AdminBookItem,
  type AdminRankingConfigItem,
  type AdminRankingTypeOption,
  type AdminRecommendationPlacementItem,
} from '@/api/admin'

const placementLoading = ref(false)
const rankingLoading = ref(false)
const savingPlacement = ref(false)
const savingRanking = ref(false)

const placements = ref<AdminRecommendationPlacementItem[]>([])
const books = ref<AdminBookItem[]>([])
const rankingItems = ref<AdminRankingConfigItem[]>([])
const placementPage = ref(1)
const placementPageSize = ref(10)
const placementTotal = ref(0)
const rankingTypes = ref<AdminRankingTypeOption[]>([
  { key: 'hot', label: '热门榜' },
  { key: 'new_book', label: '新书榜' },
  { key: 'surging', label: '飙升榜' },
  { key: 'completed', label: '完结榜' },
  { key: 'collection', label: '收藏榜' },
  { key: 'following', label: '追更榜' },
])

const placementDialogVisible = ref(false)
const editingPlacementId = ref<number | null>(null)
const placementForm = reactive({
  code: '',
  name: '',
  description: '',
  scene: 'home',
  strategy: 'manual',
  max_items: 6,
  is_active: true,
  sort_order: 0,
})

const today = new Date().toISOString().slice(0, 10)
const rankingForm = reactive({
  type: 'hot',
  snapshot_date: today,
  book_ids: [] as number[],
})

const isEditingPlacement = computed(() => editingPlacementId.value !== null)
const bookOptions = computed(() =>
  books.value.map((book) => ({
    value: book.id,
    label: `${book.title}${book.author ? ` / ${book.author}` : ''}`,
  }))
)

function resetPlacementForm() {
  editingPlacementId.value = null
  placementForm.code = ''
  placementForm.name = ''
  placementForm.description = ''
  placementForm.scene = 'home'
  placementForm.strategy = 'manual'
  placementForm.max_items = 6
  placementForm.is_active = true
  placementForm.sort_order = 0
}

function openCreatePlacement() {
  resetPlacementForm()
  placementDialogVisible.value = true
}

function openEditPlacement(row: AdminRecommendationPlacementItem) {
  editingPlacementId.value = row.id
  placementForm.code = row.code
  placementForm.name = row.name
  placementForm.description = row.description || ''
  placementForm.scene = row.scene || 'home'
  placementForm.strategy = row.strategy || 'manual'
  placementForm.max_items = row.max_items || 6
  placementForm.is_active = !!row.is_active
  placementForm.sort_order = row.sort_order || 0
  placementDialogVisible.value = true
}

async function loadPlacements() {
  placementLoading.value = true
  try {
    const res = await getAdminRecommendationPlacements({
      page: placementPage.value,
      page_size: placementPageSize.value,
    })
    placements.value = res.items || []
    placementTotal.value = res.pagination?.total || 0
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '加载推荐位失败')
  } finally {
    placementLoading.value = false
  }
}

function onPlacementCurrentPageChange(value: number) {
  placementPage.value = value
  loadPlacements()
}

function onPlacementPageSizeChange(value: number) {
  placementPageSize.value = value
  placementPage.value = 1
  loadPlacements()
}

async function submitPlacement() {
  if (!placementForm.code.trim() || !placementForm.name.trim()) {
    ElMessage.warning('请填写推荐位编码和名称')
    return
  }
  savingPlacement.value = true
  try {
    const payload = {
      code: placementForm.code.trim(),
      name: placementForm.name.trim(),
      description: placementForm.description.trim() || null,
      scene: placementForm.scene.trim() || 'home',
      strategy: placementForm.strategy.trim() || 'manual',
      max_items: placementForm.max_items,
      is_active: placementForm.is_active,
      sort_order: placementForm.sort_order,
    }
    if (isEditingPlacement.value && editingPlacementId.value != null) {
      await updateAdminRecommendationPlacement(editingPlacementId.value, payload)
      ElMessage.success('推荐位已更新')
    } else {
      await createAdminRecommendationPlacement(payload)
      ElMessage.success('推荐位已创建')
    }
    placementDialogVisible.value = false
    await loadPlacements()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存推荐位失败')
  } finally {
    savingPlacement.value = false
  }
}

async function removePlacement(row: AdminRecommendationPlacementItem) {
  try {
    await ElMessageBox.confirm(`确定删除推荐位「${row.name}」吗？`, '删除确认', { type: 'warning' })
    await deleteAdminRecommendationPlacement(row.id)
    ElMessage.success('推荐位已删除')
    await loadPlacements()
  } catch (error: any) {
    if (error === 'cancel') return
    ElMessage.error(error?.response?.data?.error || '删除推荐位失败')
  }
}

async function loadBooks() {
  try {
    const res = await getAdminBooks({ page: 1, page_size: 100 })
    books.value = res.books || []
  } catch {
    books.value = []
  }
}

async function loadRankingConfig() {
  rankingLoading.value = true
  try {
    const res = await getAdminRankingConfigs({
      type: rankingForm.type,
      snapshot_date: rankingForm.snapshot_date,
    })
    rankingTypes.value = res.available_types || rankingTypes.value
    rankingItems.value = res.items || []
    rankingForm.book_ids = rankingItems.value.map((item) => item.book_id)
  } catch (error: any) {
    rankingItems.value = []
    rankingForm.book_ids = []
    ElMessage.error(error?.response?.data?.error || '加载榜单配置失败')
  } finally {
    rankingLoading.value = false
  }
}

async function submitRankingConfig() {
  savingRanking.value = true
  try {
    const res = await saveAdminRankingConfig({
      type: rankingForm.type,
      snapshot_date: rankingForm.snapshot_date,
      book_ids: rankingForm.book_ids,
    })
    rankingItems.value = res.items || []
    ElMessage.success('榜单配置已保存')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || '保存榜单配置失败')
  } finally {
    savingRanking.value = false
  }
}

onMounted(async () => {
  await Promise.all([loadPlacements(), loadBooks()])
  await loadRankingConfig()
})
</script>

<template>
  <div class="admin-page">
    <el-tabs>
      <el-tab-pane label="推荐位配置">
        <el-card shadow="never">
          <template #header>
            <div class="panel-header">
              <span>推荐位</span>
              <div class="panel-actions">
                <el-button @click="loadPlacements">刷新</el-button>
                <el-button type="primary" @click="openCreatePlacement">新增推荐位</el-button>
              </div>
            </div>
          </template>

          <el-table :data="placements" v-loading="placementLoading" border>
            <el-table-column prop="code" label="编码" min-width="140" />
            <el-table-column prop="name" label="名称" min-width="140" />
            <el-table-column prop="scene" label="场景" width="110" />
            <el-table-column prop="strategy" label="策略" width="120" />
            <el-table-column prop="max_items" label="数量" width="80" />
            <el-table-column prop="sort_order" label="排序" width="80" />
            <el-table-column label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.is_active ? 'success' : 'info'">{{ row.is_active ? '启用' : '停用' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="说明" min-width="200" show-overflow-tooltip />
            <el-table-column label="操作" width="170" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" @click="openEditPlacement(row)">编辑</el-button>
                <el-button link type="danger" @click="removePlacement(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div class="pagination">
            <el-pagination
              :current-page="placementPage"
              :page-size="placementPageSize"
              :total="placementTotal"
              layout="total, sizes, prev, pager, next"
              :page-sizes="[10, 20, 50]"
              @current-change="onPlacementCurrentPageChange"
              @size-change="onPlacementPageSizeChange"
            />
          </div>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="榜单配置">
        <el-card shadow="never">
          <template #header>
            <div class="panel-header">
              <span>手动榜单</span>
              <el-button @click="loadRankingConfig">刷新</el-button>
            </div>
          </template>

          <el-form class="ranking-form" label-width="90px">
            <el-form-item label="榜单类型">
              <el-select v-model="rankingForm.type" style="width: 220px" @change="loadRankingConfig">
                <el-option v-for="item in rankingTypes" :key="item.key" :label="item.label" :value="item.key" />
              </el-select>
            </el-form-item>
            <el-form-item label="快照日期">
              <el-date-picker
                v-model="rankingForm.snapshot_date"
                type="date"
                value-format="YYYY-MM-DD"
                style="width: 220px"
                @change="loadRankingConfig"
              />
            </el-form-item>
            <el-form-item label="榜单书籍">
              <el-select
                v-model="rankingForm.book_ids"
                multiple
                filterable
                clearable
                collapse-tags
                collapse-tags-tooltip
                placeholder="按顺序选择要进入榜单的书籍"
                style="width: min(720px, 100%)"
              >
                <el-option v-for="item in bookOptions" :key="item.value" :label="item.label" :value="item.value" />
              </el-select>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="savingRanking" @click="submitRankingConfig">保存榜单</el-button>
            </el-form-item>
          </el-form>

          <el-table :data="rankingItems" v-loading="rankingLoading" border>
            <el-table-column prop="rank_no" label="名次" width="80" />
            <el-table-column label="作品" min-width="220">
              <template #default="{ row }">
                <span>{{ row.book?.title || `作品 #${row.book_id}` }}</span>
              </template>
            </el-table-column>
            <el-table-column label="作者" min-width="140">
              <template #default="{ row }">
                <span>{{ row.book?.author || '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="snapshot_date" label="快照日期" width="130" />
            <el-table-column label="状态" width="150">
              <template #default="{ row }">
                <el-tag type="info">{{ row.book?.status || '-' }}</el-tag>
                <el-tag class="shelf-tag" :type="row.book?.shelf_status === 'up' ? 'success' : 'warning'">
                  {{ row.book?.shelf_status || '-' }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="placementDialogVisible" :title="isEditingPlacement ? '编辑推荐位' : '新增推荐位'" width="560px">
      <el-form label-width="90px">
        <el-form-item label="编码" required>
          <el-input v-model="placementForm.code" placeholder="例如 home_hot_books" />
        </el-form-item>
        <el-form-item label="名称" required>
          <el-input v-model="placementForm.name" placeholder="例如 首页热门推荐" />
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="placementForm.description" type="textarea" :rows="3" />
        </el-form-item>
        <el-form-item label="场景">
          <el-input v-model="placementForm.scene" />
        </el-form-item>
        <el-form-item label="策略">
          <el-select v-model="placementForm.strategy" style="width: 100%">
            <el-option label="手动" value="manual" />
            <el-option label="热门" value="hot" />
            <el-option label="个性化" value="personalized" />
            <el-option label="新书" value="new_book" />
          </el-select>
        </el-form-item>
        <el-form-item label="展示数量">
          <el-input-number v-model="placementForm.max_items" :min="1" :max="50" />
        </el-form-item>
        <el-form-item label="排序">
          <el-input-number v-model="placementForm.sort_order" :min="0" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="placementForm.is_active" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="placementDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="savingPlacement" @click="submitPlacement">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.admin-page {
  padding: 20px;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-weight: 600;
}

.panel-actions {
  display: flex;
  gap: 8px;
}

.ranking-form {
  max-width: 860px;
  margin-bottom: 16px;
}

.shelf-tag {
  margin-left: 6px;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
