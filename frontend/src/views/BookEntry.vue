<script setup lang="ts">
import { onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getReadingProgress } from '@/api/reader'
import { getToken } from '@/api/request'

const route = useRoute()
const router = useRouter()

async function resolveEntry() {
  const bookId = String(route.params.bookId || '1')
  const token = getToken()
  if (!token) {
    router.replace(`/books/${bookId}`)
    return
  }

  try {
    const response = await getReadingProgress(bookId)
    if (response.has_progress && response.progress?.section_id) {
      router.replace({ path: `/reader/${bookId}`, query: { resume: '1' } })
      return
    }
  } catch (_error) {
    // Fall back to intro page for any progress lookup failure.
  }

  router.replace(`/books/${bookId}`)
}

onMounted(resolveEntry)
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-stone-100">
    <div class="rounded-3xl bg-white px-8 py-6 text-stone-600 shadow-sm">正在加载图书入口...</div>
  </div>
</template>
