<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import { getUserProfile, updateUserProfile, uploadUserAvatar, type UserProfile } from '@/api/user'
import { isCreatorToken } from '@/utils/auth'

const router = useRouter()
const loading = ref(false)
const saving = ref(false)
const uploadingAvatar = ref(false)
const profile = ref<UserProfile | null>(null)

const form = reactive({
  name: '',
  pen_name: '',
  avatar_url: '',
  age: null as number | null,
  province: '',
  city: '',
})

const defaultAvatar =
  'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=240&q=80'

const canOpenCreator = computed(() => isCreatorToken())

async function loadProfile() {
  loading.value = true
  try {
    const res = await getUserProfile()
    profile.value = res.user
    form.name = res.user.name || ''
    form.pen_name = res.user.pen_name || ''
    form.avatar_url = res.user.avatar_url || ''
    form.age = typeof res.user.age === 'number' ? res.user.age : null
    form.province = res.user.province || ''
    form.city = res.user.city || ''
  } catch (_error) {
    ElMessage.error('用户信息加载失败')
  } finally {
    loading.value = false
  }
}

async function saveProfile() {
  if (!profile.value) return
  saving.value = true
  try {
    const res = await updateUserProfile({
      name: form.name,
      pen_name: form.pen_name,
      avatar_url: form.avatar_url,
      age: form.age,
      province: form.province,
      city: form.city,
    })
    profile.value = res.user
    form.pen_name = res.user.pen_name || ''
    form.age = typeof res.user.age === 'number' ? res.user.age : null
    ElMessage.success('资料保存成功')
  } catch (_error: any) {
    ElMessage.error(_error?.response?.data?.error || '资料保存失败')
  } finally {
    saving.value = false
  }
}

async function handleAvatarChange(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  uploadingAvatar.value = true
  try {
    const res = await uploadUserAvatar(file)
    form.avatar_url = res.avatar_url || ''
    profile.value = res.user
    ElMessage.success('头像上传成功')
  } catch (_error: any) {
    ElMessage.error(_error?.response?.data?.error || '头像上传失败')
  } finally {
    uploadingAvatar.value = false
    input.value = ''
  }
}

onMounted(loadProfile)
</script>

<template>
  <div class="min-h-screen bg-stone-100 px-4 py-10 text-stone-900">
    <div class="mx-auto max-w-4xl">
      <div class="mb-4 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <button class="rounded-full border border-stone-300 px-4 py-2 text-sm" @click="router.push('/')">返回首页</button>
          <button
            v-if="canOpenCreator"
            class="rounded-full border border-emerald-300 bg-emerald-50 px-4 py-2 text-sm text-emerald-700"
            @click="router.push('/creator/dashboard')"
          >
            创作者工作台
          </button>
        </div>
        <button class="rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="router.push('/user/library')">
          我的阅读
        </button>
      </div>

      <div class="rounded-3xl bg-white p-6 shadow-sm md:p-8">
        <h1 class="text-2xl font-semibold">用户详情</h1>
        <p class="mt-2 text-sm text-stone-500">你可以在这里设置头像、昵称、创作者笔名与地区</p>

        <div v-if="loading" class="mt-8 text-sm text-stone-500">正在加载...</div>

        <template v-else-if="profile">
          <div class="mt-8 grid gap-8 md:grid-cols-[220px_minmax(0,1fr)]">
            <div class="flex flex-col items-center rounded-3xl bg-stone-50 p-5">
              <img
                :src="form.avatar_url || profile.avatar_url || defaultAvatar"
                alt="avatar"
                class="h-32 w-32 rounded-full object-cover"
              />
              <p class="mt-3 text-sm text-stone-500">用户名：{{ profile.username }}</p>
              <p class="mt-1 text-sm text-stone-500">年龄：{{ profile.age ?? '未填写' }}</p>
              <p class="mt-1 text-sm text-stone-500">当前笔名：{{ profile.pen_name || '未设置' }}</p>
            </div>

            <div class="space-y-5">
              <label class="block">
                <span class="mb-2 block text-sm text-stone-600">名称</span>
                <input
                  v-model="form.name"
                  class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                  placeholder="请输入名称"
                />
              </label>

              <label class="block">
                <span class="mb-2 block text-sm text-stone-600">创作者笔名</span>
                <input
                  v-model="form.pen_name"
                  class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                  maxlength="80"
                  placeholder="进入创作者端前需要先设置笔名"
                />
                <p class="mt-2 text-xs text-stone-500">如果你有创作者权限，这个笔名会显示为书籍作者名，并用于创作者端发布内容。</p>
              </label>

              <label class="block">
                <span class="mb-2 block text-sm text-stone-600">年龄</span>
                <input
                  v-model.number="form.age"
                  type="number"
                  min="1"
                  max="120"
                  class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                  placeholder="请输入年龄（1-120）"
                />
              </label>

              <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
                <label class="block">
                  <span class="mb-2 block text-sm text-stone-600">省份</span>
                  <input
                    v-model="form.province"
                    class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                    placeholder="自动识别后可手动修改"
                  />
                </label>
                <label class="block">
                  <span class="mb-2 block text-sm text-stone-600">城市</span>
                  <input
                    v-model="form.city"
                    class="w-full rounded-2xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-500"
                    placeholder="自动识别后可手动修改"
                  />
                </label>
              </div>

              <label class="block">
                <span class="mb-2 block text-sm text-stone-600">上传头像</span>
                <input
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  class="block w-full text-sm text-stone-600 file:mr-4 file:rounded-full file:border-0 file:bg-stone-900 file:px-4 file:py-2 file:text-sm file:text-white"
                  :disabled="uploadingAvatar"
                  @change="handleAvatarChange"
                />
                <p class="mt-2 text-xs text-stone-500">支持 JPG/PNG/WEBP，最大 2MB</p>
              </label>

              <p class="text-sm text-stone-500">邮箱：{{ profile.email }}</p>

              <button
                class="rounded-full bg-stone-900 px-6 py-3 text-sm font-medium text-white disabled:opacity-60"
                :disabled="saving"
                @click="saveProfile"
              >
                {{ saving ? '保存中...' : '保存资料' }}
              </button>
            </div>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>
