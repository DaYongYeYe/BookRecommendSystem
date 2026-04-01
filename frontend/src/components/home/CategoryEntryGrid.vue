<script setup lang="ts">
import { useRouter } from 'vue-router'
import { CATEGORY_NAVIGATION_ENTRIES } from '@/constants/categoryNavigation'

const router = useRouter()

const coreEntries = CATEGORY_NAVIGATION_ENTRIES.slice(0, 8)

function goCategory(entryKey: string) {
  router.push({
    path: '/categories',
    query: { entry: entryKey },
  })
}

function goAllCategories() {
  router.push('/categories')
}
</script>

<template>
  <section class="mt-10 rounded-[2rem] bg-white p-6 shadow-sm">
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <p class="text-sm font-medium text-stone-500">分类入口</p>
        <h2 class="mt-1 text-2xl font-semibold text-stone-900">按偏好快速找书</h2>
        <p class="mt-2 text-sm text-stone-500">从题材、风格和更新状态切入，快速进入你真正想看的作品池。</p>
      </div>

      <button
        class="rounded-full border border-stone-300 px-4 py-2 text-sm font-medium text-stone-700 transition hover:border-stone-500 hover:bg-stone-50"
        @click="goAllCategories"
      >
        查看更多分类
      </button>
    </div>

    <div class="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <button
        v-for="item in coreEntries"
        :key="item.key"
        class="group rounded-[1.5rem] border border-stone-200 bg-stone-50 p-4 text-left transition hover:-translate-y-0.5 hover:border-stone-300 hover:bg-white hover:shadow-sm"
        @click="goCategory(item.key)"
      >
        <div :class="['flex h-12 w-12 items-center justify-center rounded-2xl transition group-hover:scale-105', item.iconClass]">
          <component :is="item.icon" class="h-6 w-6" />
        </div>
        <div class="mt-4 flex items-center justify-between gap-3">
          <span class="text-lg font-semibold text-stone-900">{{ item.label }}</span>
          <span class="text-xs text-stone-400 transition group-hover:text-stone-600">进入</span>
        </div>
        <p class="mt-2 text-sm text-stone-500">{{ item.description }}</p>
      </button>
    </div>
  </section>
</template>
