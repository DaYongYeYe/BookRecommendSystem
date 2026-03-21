<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRoute } from 'vue-router'
import {
  createBookComment,
  createHighlight,
  createHighlightComment,
  getReader,
  type ReaderHighlight,
  type ReaderPayload,
} from '@/api/reader'
import { useReaderPreferences } from '@/composables/useReaderPreferences'
import { useReadingProgress } from '@/composables/useReadingProgress'

type SelectionDraft = {
  paragraphId: string
  startOffset: number
  endOffset: number
  selectedText: string
}

type HighlightSegment =
  | { kind: 'text'; text: string }
  | { kind: 'highlight'; text: string; highlight: ReaderHighlight }

const route = useRoute()
const bookId = computed(() => String(route.params.bookId || '1'))

const reader = ref<ReaderPayload | null>(null)
const loading = ref(false)
const selectionDraft = ref<SelectionDraft | null>(null)
const draftNote = ref('')
const draftColor = ref('amber')
const activeHighlightId = ref<number | null>(null)
const highlightCommentDraft = ref('')
const bookCommentDraft = ref('')
const activeSectionId = ref<string>('')

const { readerTheme, readerFontSize, setTheme, increaseFont, decreaseFont } = useReaderPreferences()
const { resumeIfNeeded, syncReadingProgress } = useReadingProgress(bookId, activeSectionId)

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
  readerTheme.value === 'dark' ? 'rounded-[2rem] bg-[#111b28] shadow-sm' : 'rounded-[2rem] bg-white shadow-sm'
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
    const payload = await getReader(bookId.value)
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

function clearSelectionDraft() {
  selectionDraft.value = null
  draftNote.value = ''
  draftColor.value = 'amber'
  const selection = window.getSelection()
  selection?.removeAllRanges()
}

function getParagraphHighlights(paragraphId: string) {
  return (reader.value?.highlights || [])
    .filter((item) => item.paragraph_id === paragraphId)
    .sort((a, b) => a.start_offset - b.start_offset)
}

function buildSegments(text: string, paragraphId: string): HighlightSegment[] {
  const highlights = getParagraphHighlights(paragraphId)
  if (!highlights.length) {
    return [{ kind: 'text', text }]
  }

  let cursor = 0
  const segments: HighlightSegment[] = []
  highlights.forEach((highlight) => {
    const start = Math.max(cursor, highlight.start_offset)
    const end = Math.min(text.length, highlight.end_offset)

    if (start > cursor) {
      segments.push({ kind: 'text', text: text.slice(cursor, start) })
    }
    if (end > start) {
      segments.push({ kind: 'highlight', text: text.slice(start, end), highlight })
      cursor = end
    }
  })

  if (cursor < text.length) {
    segments.push({ kind: 'text', text: text.slice(cursor) })
  }
  return segments
}

function openHighlight(highlightId: number) {
  activeHighlightId.value = highlightId
  clearSelectionDraft()
}

function scrollToSection(sectionId: string) {
  activeSectionId.value = sectionId
  document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function handleSelection() {
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
    ElMessage.info('当前只支持单段落内划线')
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
    ElMessage.success('书本评论已发布')
  } catch (_error) {
    ElMessage.error('发表评论失败')
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
    await nextTick()
    await loadReader()
  }
)

</script>

<template>
  <div :class="rootClass">
    <div class="mx-auto flex max-w-[1600px] gap-6 px-4 py-6 lg:px-6">
      <aside class="sticky top-6 hidden h-[calc(100vh-3rem)] w-72 shrink-0 rounded-[2rem] bg-[#122620] p-6 text-stone-100 shadow-2xl lg:flex lg:flex-col">
        <template v-if="reader">
          <div class="mb-6">
            <p class="text-xs uppercase tracking-[0.35em] text-emerald-200/70">Outline</p>
            <h1 class="mt-3 text-2xl font-semibold leading-tight">{{ reader.book.title }}</h1>
            <p class="mt-2 text-sm text-stone-300">{{ reader.book.author }}</p>
          </div>

          <div class="mb-4 flex items-center justify-between text-xs uppercase tracking-[0.3em] text-stone-400">
            <span>章节</span>
            <span>{{ reader.highlights.length }} 条划线</span>
          </div>
          <div class="space-y-2 overflow-y-auto pr-2">
            <button
              v-for="item in reader.outline"
              :key="item.id"
              :class="[
                'block w-full rounded-2xl px-4 py-3 text-left text-sm transition',
                item.level === 2 ? 'ml-4 w-[calc(100%-1rem)] text-stone-300' : 'font-medium',
                activeSectionId === item.id ? 'bg-emerald-100 text-emerald-950' : 'bg-white/5 hover:bg-white/10',
              ]"
              @click="scrollToSection(item.id)"
            >
              {{ item.title }}
            </button>
          </div>
        </template>
      </aside>

      <main class="min-w-0 flex-1">
        <div v-if="loading" :class="cardClass" class="p-10 text-center text-stone-500">
          正在加载正文...
        </div>

        <template v-else-if="reader">
          <section
            class="mb-6 overflow-hidden rounded-[2rem] p-6 md:p-8"
            :class="readerTheme === 'dark' ? 'bg-[#111b28]' : 'bg-[#f5efe4]'"
          >
            <div class="grid gap-6 md:grid-cols-[1.15fr_0.85fr]">
              <div>
                <p class="text-sm uppercase tracking-[0.4em]" :class="readerTheme === 'dark' ? 'text-stone-400' : 'text-stone-500'">Reader</p>
                <h2 class="mt-4 max-w-3xl text-4xl font-semibold leading-tight md:text-5xl">
                  {{ reader.book.title }}
                </h2>
                <p class="mt-4 max-w-2xl text-lg leading-8" :class="readerTheme === 'dark' ? 'text-stone-300' : 'text-stone-600'">
                  {{ reader.book.description }}
                </p>
              </div>

              <div class="rounded-[1.75rem] bg-[#122620] p-6 text-stone-100">
                <div class="flex items-center gap-4">
                  <img :src="reader.book.cover" :alt="reader.book.title" class="h-36 w-24 rounded-2xl object-cover" />
                  <div>
                    <p class="text-sm uppercase tracking-[0.35em] text-emerald-200/70">Tips</p>
                    <p class="mt-3 text-lg font-medium">选中正文可划线</p>
                    <p class="mt-2 text-sm leading-6 text-stone-300">点击划线可查看评论。阅读进度会自动保存，回到首页可直接续读。</p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <div class="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
            <article :class="cardClass" class="p-6 md:p-8">
              <div v-if="selectionDraft" class="mb-8 rounded-[1.5rem] border border-amber-200 bg-amber-50 p-5 text-stone-900">
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
                  class="mt-4 min-h-28 w-full rounded-3xl border border-amber-100 bg-white px-4 py-3 outline-none focus:border-stone-400"
                  placeholder="写下你对这段文字的感受..."
                />
                <div class="mt-4 flex flex-wrap gap-3">
                  <button class="rounded-full bg-stone-900 px-5 py-3 text-sm font-medium text-white" @click="submitHighlight">
                    保存划线
                  </button>
                  <button class="rounded-full bg-white px-5 py-3 text-sm font-medium text-stone-500" @click="clearSelectionDraft">
                    取消
                  </button>
                </div>
              </div>

              <section
                v-for="section in reader.sections"
                :id="section.id"
                :key="section.id"
                class="scroll-mt-28 border-b py-8 first:pt-0 last:border-b-0"
                :class="readerTheme === 'dark' ? 'border-white/10' : 'border-stone-100'"
              >
                <p class="text-xs uppercase tracking-[0.35em]" :class="readerTheme === 'dark' ? 'text-stone-400' : 'text-stone-400'">Section</p>
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
                    <template v-for="(segment, index) in buildSegments(paragraph.text, paragraph.id)" :key="`${paragraph.id}-${index}`">
                      <span v-if="segment.kind === 'text'">{{ segment.text }}</span>
                      <button
                        v-else
                        type="button"
                        :class="[
                          'cursor-pointer rounded-md px-1 align-baseline underline decoration-2 underline-offset-4 transition',
                          colorMap[segment.highlight.color] || colorMap.amber,
                        ]"
                        @click="openHighlight(segment.highlight.id)"
                      >
                        {{ segment.text }}
                      </button>
                    </template>
                  </p>
                </div>
              </section>
            </article>

            <aside class="space-y-6">
              <section :class="cardClass" class="p-6">
                <p class="text-xs uppercase tracking-[0.3em]" :class="readerTheme === 'dark' ? 'text-stone-400' : 'text-stone-400'">Reading Settings</p>
                <h3 class="mt-2 text-xl font-semibold">阅读设置</h3>

                <div class="mt-4">
                  <p class="mb-2 text-sm">字体大小</p>
                  <div class="flex items-center gap-3">
                    <button class="rounded-full border px-3 py-1 text-sm" @click="decreaseFont">A-</button>
                    <span class="text-sm">{{ readerFontSize }} px</span>
                    <button class="rounded-full border px-3 py-1 text-sm" @click="increaseFont">A+</button>
                  </div>
                </div>

                <div class="mt-4">
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
              </section>

              <section :class="cardClass" class="p-6">
                <div class="flex items-center justify-between">
                  <h3 class="text-xl font-semibold">划线评论</h3>
                  <span class="rounded-full bg-stone-100 px-3 py-2 text-xs text-stone-500">{{ reader.highlights.length }} 条</span>
                </div>

                <div v-if="activeHighlight" class="mt-5">
                  <p
                    :class="[
                      'rounded-3xl px-4 py-4 text-lg leading-8 underline decoration-2 underline-offset-4',
                      colorMap[activeHighlight.color] || colorMap.amber,
                    ]"
                  >
                    {{ activeHighlight.selected_text }}
                  </p>
                  <p class="mt-4 text-sm leading-7" :class="readerTheme === 'dark' ? 'text-stone-300' : 'text-stone-600'">
                    {{ activeHighlight.note || '这条划线还没有批注。' }}
                  </p>
                  <div class="mt-4 flex items-center justify-between text-xs text-stone-400">
                    <span>{{ activeHighlight.created_by }}</span>
                    <span>{{ activeHighlight.created_at }}</span>
                  </div>

                  <div class="mt-6 space-y-3">
                    <div
                      v-for="comment in activeHighlight.comments"
                      :key="comment.id"
                      class="rounded-3xl px-4 py-4"
                      :class="readerTheme === 'dark' ? 'bg-white/5' : 'bg-stone-50'"
                    >
                      <div class="flex items-center justify-between text-xs text-stone-400">
                        <span>{{ comment.author }}</span>
                        <span>{{ comment.created_at }}</span>
                      </div>
                      <p class="mt-2 text-sm leading-7">{{ comment.content }}</p>
                    </div>
                  </div>

                  <textarea
                    v-model="highlightCommentDraft"
                    class="mt-5 min-h-28 w-full rounded-3xl border border-stone-200 px-4 py-3 outline-none focus:border-stone-400"
                    placeholder="对这条划线发表评论..."
                  />
                  <button class="mt-4 rounded-full bg-stone-900 px-5 py-3 text-sm font-medium text-white" @click="submitHighlightComment">
                    发表评论
                  </button>
                </div>
              </section>

              <section class="rounded-[2rem] bg-[#122620] p-6 text-stone-100 shadow-sm">
                <h3 class="text-2xl font-semibold">书本评论区</h3>
                <textarea
                  v-model="bookCommentDraft"
                  class="mt-5 min-h-28 w-full rounded-3xl border border-white/10 bg-white/10 px-4 py-3 text-stone-100 outline-none placeholder:text-stone-400"
                  placeholder="写下你对这本书的看法..."
                />
                <button class="mt-4 rounded-full bg-emerald-200 px-5 py-3 text-sm font-medium text-emerald-950" @click="submitBookComment">
                  发表评论
                </button>

                <div class="mt-6 space-y-3">
                  <div
                    v-for="comment in reader.book_comments"
                    :key="comment.id"
                    class="rounded-3xl bg-white/10 px-4 py-4"
                  >
                    <div class="flex items-center justify-between text-xs text-stone-300">
                      <span>{{ comment.author }}</span>
                      <span>{{ comment.created_at }}</span>
                    </div>
                    <p class="mt-2 text-sm leading-7 text-stone-100">{{ comment.content }}</p>
                  </div>
                </div>
              </section>
            </aside>
          </div>
        </template>
      </main>
    </div>
  </div>
</template>
