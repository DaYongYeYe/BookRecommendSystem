<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'
import {
  addBookToShelf,
  createBookComment,
  createHighlight,
  createHighlightComment,
  getReader,
  getReaderPreferences,
  saveReaderPreferences,
  type ReaderHighlight,
  type ReaderPayload,
} from '@/api/reader'
import { getToken } from '@/api/request'
import { getUserFavorites } from '@/api/user'
import { useReaderPreferences } from '@/composables/useReaderPreferences'
import { useReadingProgress } from '@/composables/useReadingProgress'

type SelectionDraft = {
  paragraphId: string
  startOffset: number
  endOffset: number
  selectedText: string
}

type PanelType = 'none' | 'outline' | 'settings' | 'highlight' | 'book-comments'

const route = useRoute()
const router = useRouter()
const bookId = computed(() => String(route.params.bookId || '1'))

const reader = ref<ReaderPayload | null>(null)
const loading = ref(false)
const addingToShelf = ref(false)
const isInShelf = ref(false)

const selectionDraft = ref<SelectionDraft | null>(null)
const draftNote = ref('')
const draftColor = ref('amber')
const activeHighlightId = ref<number | null>(null)
const highlightCommentDraft = ref('')
const bookCommentDraft = ref('')
const activeSectionId = ref<string>('')

const activePanel = ref<PanelType>('none')
const highlightModeEnabled = ref(false)
const showComments = ref(true)
const preferenceLoaded = ref(false)

const { readerTheme, readerFontSize, setTheme, setFontSize } = useReaderPreferences()
const { resumeIfNeeded, syncReadingProgress, getAnalyticsContext } = useReadingProgress(bookId, activeSectionId)

const colorMap: Record<string, string> = {
  amber: 'bg-amber-200/80 decoration-amber-500',
  sky: 'bg-sky-200/80 decoration-sky-500',
  rose: 'bg-rose-200/80 decoration-rose-500',
}

const rootClass = computed(() =>
  readerTheme.value === 'dark'
    ? 'min-h-screen bg-[#0f1720] text-stone-100'
    : 'min-h-screen bg-stone-100 text-stone-900'
)

const cardClass = computed(() =>
  readerTheme.value === 'dark' ? 'rounded-[1.5rem] bg-[#111b28] shadow-sm' : 'rounded-[1.5rem] bg-white shadow-sm'
)

const panelCardClass = computed(() =>
  readerTheme.value === 'dark'
    ? 'border border-white/10 bg-[#1a2533] text-stone-100'
    : 'border border-stone-200 bg-white text-stone-800'
)

const activeHighlight = computed(() => {
  if (!reader.value || activeHighlightId.value == null) {
    return null
  }
  return reader.value.highlights.find((item) => item.id === activeHighlightId.value) || null
})

async function loadReader() {
  loading.value = true
  try {
    const payload = await getReader(bookId.value, getAnalyticsContext())
    reader.value = payload
    activeSectionId.value = payload.sections[0]?.id || ''
    activeHighlightId.value = payload.highlights[0]?.id ?? null
    await resumeIfNeeded(route.query.resume === '1')
  } catch (_error) {
    ElMessage.error('阅读内容加载失败')
  } finally {
    loading.value = false
  }
}

async function loadShelfState() {
  if (!getToken()) {
    isInShelf.value = false
    return
  }
  try {
    const favorites = await getUserFavorites()
    const currentBookId = Number(bookId.value)
    isInShelf.value = favorites.items.some((item) => item.id === currentBookId)
  } catch (_error) {
    // Ignore shelf status failures; keep default state.
    isInShelf.value = false
  }
}

async function loadReaderPreferences() {
  try {
    const data = await getReaderPreferences()
    setTheme(data.theme === 'dark' ? 'dark' : 'light')
    setFontSize(Number(data.font_size) || 20)
    showComments.value = data.show_comments !== false
  } catch (_error) {
    // Keep defaults when preference loading fails.
  } finally {
    preferenceLoaded.value = true
  }
}

async function persistReaderPreferences() {
  if (!preferenceLoaded.value || !getToken()) {
    return
  }
  try {
    await saveReaderPreferences({
      theme: readerTheme.value,
      font_size: readerFontSize.value,
      show_highlights: true,
      show_comments: showComments.value,
    })
  } catch (_error) {
    // Do not block reading flow on preference save failures.
  }
}

function clearSelectionDraft() {
  selectionDraft.value = null
  draftNote.value = ''
  draftColor.value = 'amber'
  const selection = window.getSelection()
  selection?.removeAllRanges()
}

function togglePanel(panel: PanelType) {
  activePanel.value = activePanel.value === panel ? 'none' : panel
}

function toggleHighlightMode() {
  highlightModeEnabled.value = !highlightModeEnabled.value
  if (!highlightModeEnabled.value) {
    clearSelectionDraft()
  } else {
    ElMessage.info('已开启划线模式，请在正文中选中单段文本')
  }
}

function toggleCommentVisibility() {
  showComments.value = !showComments.value
  if (!showComments.value && (activePanel.value === 'highlight' || activePanel.value === 'book-comments')) {
    activePanel.value = 'none'
  }
}

function scrollToSection(sectionId: string) {
  activeSectionId.value = sectionId
  document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function handleSelection() {
  if (!highlightModeEnabled.value) {
    return
  }

  const selection = window.getSelection()
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) {
    return
  }

  const range = selection.getRangeAt(0)
  const startParagraph = (range.startContainer.nodeType === Node.TEXT_NODE
    ? range.startContainer.parentElement
    : (range.startContainer as Element)
  )?.closest?.('[data-paragraph-id]') as HTMLElement | null
  const endParagraph = (range.endContainer.nodeType === Node.TEXT_NODE
    ? range.endContainer.parentElement
    : (range.endContainer as Element)
  )?.closest?.('[data-paragraph-id]') as HTMLElement | null

  if (!startParagraph || !endParagraph || startParagraph !== endParagraph) {
    ElMessage.info('当前仅支持单段落内划线')
    clearSelectionDraft()
    return
  }

  const paragraphId = startParagraph.dataset.paragraphId
  if (!paragraphId) {
    clearSelectionDraft()
    return
  }

  const preSelectionRange = range.cloneRange()
  preSelectionRange.selectNodeContents(startParagraph)
  preSelectionRange.setEnd(range.startContainer, range.startOffset)

  const startOffset = preSelectionRange.toString().length
  const selectedText = range.toString().trim()
  const endOffset = startOffset + selectedText.length
  if (!selectedText) {
    clearSelectionDraft()
    return
  }

  selectionDraft.value = { paragraphId, startOffset, endOffset, selectedText }
  activeHighlightId.value = null
}

async function submitHighlight() {
  if (!selectionDraft.value) {
    return
  }

  try {
    const response = await createHighlight(bookId.value, {
      paragraph_id: selectionDraft.value.paragraphId,
      start_offset: selectionDraft.value.startOffset,
      end_offset: selectionDraft.value.endOffset,
      selected_text: selectionDraft.value.selectedText,
      note: draftNote.value,
      color: draftColor.value,
    })
    reader.value?.highlights.push(response.highlight)
    activeHighlightId.value = response.highlight.id
    activePanel.value = 'highlight'
    clearSelectionDraft()
    ElMessage.success('划线已保存')
  } catch (_error) {
    ElMessage.error('划线保存失败')
  }
}

async function submitHighlightComment() {
  if (!activeHighlight.value || !highlightCommentDraft.value.trim()) {
    return
  }

  try {
    const response = await createHighlightComment(bookId.value, activeHighlight.value.id, {
      content: highlightCommentDraft.value,
    })
    activeHighlight.value.comments.push(response.comment)
    highlightCommentDraft.value = ''
    ElMessage.success('评论已发布')
  } catch (_error) {
    ElMessage.error('评论发布失败')
  }
}

async function submitBookComment() {
  if (!bookCommentDraft.value.trim() || !reader.value) {
    return
  }
  try {
    const response = await createBookComment(bookId.value, { content: bookCommentDraft.value })
    reader.value.book_comments.unshift(response.comment)
    bookCommentDraft.value = ''
    ElMessage.success('书评发布成功')
  } catch (_error) {
    ElMessage.error('书评发布失败')
  }
}

async function handleAddToShelf() {
  if (isInShelf.value) {
    return
  }
  addingToShelf.value = true
  try {
    await addBookToShelf(bookId.value)
    isInShelf.value = true
    ElMessage.success('已加入书架')
  } catch (_error) {
    ElMessage.error('加入书架失败，请先登录')
  } finally {
    addingToShelf.value = false
  }
}

function handleScroll() {
  if (!reader.value) {
    return
  }

  let currentSection = reader.value.sections[0]?.id || ''
  reader.value.sections.forEach((section) => {
    const element = document.getElementById(section.id)
    if (element && element.getBoundingClientRect().top <= 140) {
      currentSection = section.id
    }
  })

  if (currentSection !== activeSectionId.value) {
    activeSectionId.value = currentSection
  }
  syncReadingProgress(false)
}

onMounted(async () => {
  await loadReaderPreferences()
  await loadShelfState()
  await loadReader()
  window.addEventListener('scroll', handleScroll, { passive: true })
  document.addEventListener('mouseup', handleSelection)
})

onBeforeUnmount(() => {
  syncReadingProgress(true)
  window.removeEventListener('scroll', handleScroll)
  document.removeEventListener('mouseup', handleSelection)
})

watch(
  () => route.params.bookId,
  async () => {
    clearSelectionDraft()
    activePanel.value = 'none'
    await nextTick()
    await loadShelfState()
    await loadReader()
  }
)

watch([readerTheme, readerFontSize, showComments], () => {
  persistReaderPreferences()
})
</script>

<template>
  <div :class="rootClass" class="pb-14">
    <main class="mx-auto max-w-[1100px] px-4 py-6 md:px-8">
      <div v-if="loading" :class="cardClass" class="p-10 text-center text-stone-500">正在加载正文...</div>

      <template v-else-if="reader">
        <section
          class="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-[1.25rem] px-5 py-4"
          :class="readerTheme === 'dark' ? 'bg-[#111b28]' : 'bg-white'"
        >
          <div class="min-w-0">
            <h1 class="truncate text-xl font-semibold">{{ reader.book.title }}</h1>
            <p class="text-sm" :class="readerTheme === 'dark' ? 'text-stone-300' : 'text-stone-500'">{{ reader.book.author }}</p>
          </div>
          <div class="flex items-center gap-2">
            <button class="rounded-full border px-4 py-2 text-sm" @click="router.push('/')">返回首页</button>
            <button class="rounded-full border px-4 py-2 text-sm" @click="router.push('/user/library')">我的书架</button>
            <button
              class="rounded-full bg-emerald-500 px-4 py-2 text-sm font-medium text-white disabled:opacity-60"
              :disabled="addingToShelf || isInShelf"
              @click="handleAddToShelf"
            >
              {{ addingToShelf ? '加入中...' : isInShelf ? '已在书架' : '加入书架' }}
            </button>
          </div>
        </section>

        <article :class="cardClass" class="p-6 md:p-8">
          <div
            v-if="selectionDraft"
            class="mb-8 rounded-[1.2rem] border border-amber-200 bg-amber-50 p-5 text-stone-900"
          >
            <p class="text-xs uppercase tracking-[0.3em] text-amber-700">新建划线</p>
            <p class="mt-3 rounded-2xl bg-white px-4 py-4 text-lg leading-8 shadow-sm">“{{ selectionDraft.selectedText }}”</p>
            <div class="mt-4 flex flex-wrap gap-2">
              <button
                v-for="option in ['amber', 'sky', 'rose']"
                :key="option"
                :class="[
                  'rounded-full px-3 py-2 text-xs font-medium uppercase tracking-[0.25em]',
                  draftColor === option ? 'bg-stone-900 text-white' : 'bg-white text-stone-500',
                ]"
                @click="draftColor = option"
              >
                {{ option }}
              </button>
            </div>
            <textarea
              v-model="draftNote"
              class="mt-4 min-h-24 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 outline-none focus:border-stone-400"
              placeholder="写下这段文字的批注..."
            />
            <div class="mt-4 flex flex-wrap gap-3">
              <button class="rounded-full bg-stone-900 px-5 py-2.5 text-sm font-medium text-white" @click="submitHighlight">
                保存划线
              </button>
              <button class="rounded-full bg-white px-5 py-2.5 text-sm font-medium text-stone-500" @click="clearSelectionDraft">
                取消
              </button>
            </div>
          </div>

          <section
            v-for="section in reader.sections"
            :id="section.id"
            :key="section.id"
            class="scroll-mt-24 border-b py-7 first:pt-0 last:border-b-0"
            :class="readerTheme === 'dark' ? 'border-white/10' : 'border-stone-100'"
          >
            <p class="text-xs uppercase tracking-[0.35em]" :class="readerTheme === 'dark' ? 'text-stone-400' : 'text-stone-400'">
              Section
            </p>
            <h3 class="mt-3 text-3xl font-semibold">{{ section.title }}</h3>
            <p class="mt-3 max-w-2xl text-sm leading-7" :class="readerTheme === 'dark' ? 'text-stone-300' : 'text-stone-500'">
              {{ section.summary }}
            </p>

            <div class="mt-6 space-y-6">
              <p
                v-for="paragraph in section.paragraphs"
                :key="paragraph.id"
                :data-paragraph-id="paragraph.id"
                class="rounded-3xl px-3 py-3 transition"
                :class="readerTheme === 'dark' ? 'text-stone-100 hover:bg-white/5' : 'text-stone-700 hover:bg-stone-50'"
                :style="{ fontSize: `${readerFontSize}px`, lineHeight: '2.1' }"
              >
                {{ paragraph.text }}
              </p>
            </div>
          </section>
        </article>
      </template>
    </main>

    <div class="fixed right-3 top-1/2 z-40 -translate-y-1/2 md:right-5">
      <div class="rounded-[1.2rem] bg-[#1b1f28] p-2 shadow-2xl">
        <div class="flex flex-col gap-2">
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'outline' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            @click="togglePanel('outline')"
          >
            目录
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'settings' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            @click="togglePanel('settings')"
          >
            字体
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="highlightModeEnabled ? 'bg-amber-500 text-white' : 'bg-[#101319] text-stone-200'"
            @click="toggleHighlightMode"
          >
            划线
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="showComments ? 'bg-[#101319] text-stone-200' : 'bg-rose-500 text-white'"
            @click="toggleCommentVisibility"
          >
            {{ showComments ? '显评' : '隐评' }}
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'highlight' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            @click="togglePanel('highlight')"
          >
            批注
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="activePanel === 'book-comments' ? 'bg-emerald-500 text-white' : 'bg-[#101319] text-stone-200'"
            @click="togglePanel('book-comments')"
          >
            书评
          </button>
          <button
            class="h-11 w-11 rounded-full text-xs font-medium"
            :class="readerTheme === 'dark' ? 'bg-[#101319] text-stone-200' : 'bg-amber-400 text-stone-900'"
            @click="setTheme(readerTheme === 'dark' ? 'light' : 'dark')"
          >
            {{ readerTheme === 'dark' ? '浅色' : '深色' }}
          </button>
        </div>
      </div>
    </div>

    <div
      v-if="activePanel !== 'none' && reader"
      class="fixed right-20 top-1/2 z-40 w-[310px] -translate-y-1/2 rounded-[1.2rem] p-4 shadow-2xl md:w-[360px]"
      :class="panelCardClass"
    >
      <template v-if="activePanel === 'outline'">
        <h3 class="mb-3 text-lg font-semibold">目录</h3>
        <div class="max-h-[55vh] space-y-2 overflow-y-auto pr-1">
          <button
            v-for="item in reader.outline"
            :key="item.id"
            :class="[
              'block w-full rounded-xl px-3 py-2 text-left text-sm transition',
              item.level === 2 ? 'ml-3 w-[calc(100%-0.75rem)]' : 'font-medium',
              activeSectionId === item.id ? 'bg-emerald-500 text-white' : 'bg-black/10 hover:bg-black/20',
            ]"
            @click="scrollToSection(item.id)"
          >
            {{ item.title }}
          </button>
        </div>
      </template>

      <template v-else-if="activePanel === 'settings'">
        <h3 class="mb-3 text-lg font-semibold">字体设置</h3>
        <div class="space-y-4">
          <div>
            <p class="mb-2 text-sm">字号大小：{{ readerFontSize }}px</p>
            <input
              class="w-full accent-emerald-500"
              type="range"
              min="16"
              max="30"
              :value="readerFontSize"
              @input="setFontSize(Number(($event.target as HTMLInputElement).value))"
            />
          </div>
          <div>
            <p class="mb-2 text-sm">阅读模式</p>
            <div class="flex gap-2">
              <button
                class="rounded-full px-4 py-2 text-sm"
                :class="readerTheme === 'light' ? 'bg-stone-900 text-white' : 'bg-stone-200 text-stone-700'"
                @click="setTheme('light')"
              >
                浅色
              </button>
              <button
                class="rounded-full px-4 py-2 text-sm"
                :class="readerTheme === 'dark' ? 'bg-stone-900 text-white' : 'bg-stone-200 text-stone-700'"
                @click="setTheme('dark')"
              >
                深色
              </button>
            </div>
          </div>
        </div>
      </template>

      <template v-else-if="activePanel === 'highlight'">
        <h3 class="mb-3 text-lg font-semibold">划线批注</h3>
        <div v-if="!showComments" class="text-sm text-stone-400">评论已隐藏，请先点击右侧“显评”。</div>
        <div v-else-if="activeHighlight">
          <p
            :class="[
              'rounded-2xl px-3 py-3 text-base leading-7 underline decoration-2 underline-offset-4',
              colorMap[activeHighlight.color] || colorMap.amber,
            ]"
          >
            {{ activeHighlight.selected_text }}
          </p>
          <p class="mt-3 text-sm leading-7">{{ activeHighlight.note || '这条划线暂时没有批注。' }}</p>

          <div class="mt-4 max-h-[28vh] space-y-2 overflow-y-auto pr-1">
            <div
              v-for="comment in activeHighlight.comments"
              :key="comment.id"
              class="rounded-2xl bg-black/10 px-3 py-3 text-sm"
            >
              <div class="flex items-center justify-between text-xs opacity-70">
                <span>{{ comment.author }}</span>
                <span>{{ comment.created_at }}</span>
              </div>
              <p class="mt-1 leading-6">{{ comment.content }}</p>
            </div>
          </div>

          <textarea
            v-model="highlightCommentDraft"
            class="mt-4 min-h-20 w-full rounded-2xl border border-stone-300 bg-transparent px-3 py-2 text-sm outline-none"
            placeholder="发表评论..."
          />
          <button class="mt-3 rounded-full bg-stone-900 px-4 py-2 text-sm text-white" @click="submitHighlightComment">
            发布评论
          </button>
        </div>
        <div v-else class="text-sm text-stone-400">当前没有选中的划线；保存新划线后会自动显示在这里。</div>
      </template>

      <template v-else-if="activePanel === 'book-comments'">
        <h3 class="mb-3 text-lg font-semibold">书本评论</h3>
        <div v-if="!showComments" class="text-sm text-stone-400">评论已隐藏，请先点击右侧“显评”。</div>
        <template v-else>
          <textarea
            v-model="bookCommentDraft"
            class="min-h-24 w-full rounded-2xl border border-stone-300 bg-transparent px-3 py-2 text-sm outline-none"
            placeholder="写下你对这本书的看法..."
          />
          <button class="mt-3 rounded-full bg-emerald-500 px-4 py-2 text-sm font-medium text-white" @click="submitBookComment">
            发表评论
          </button>

          <div class="mt-4 max-h-[35vh] space-y-2 overflow-y-auto pr-1">
            <div
              v-for="comment in reader.book_comments"
              :key="comment.id"
              class="rounded-2xl bg-black/10 px-3 py-3 text-sm"
            >
              <div class="flex items-center justify-between text-xs opacity-70">
                <span>{{ comment.author }}</span>
                <span>{{ comment.created_at }}</span>
              </div>
              <p class="mt-1 leading-6">{{ comment.content }}</p>
            </div>
          </div>
        </template>
      </template>
    </div>
  </div>
</template>
