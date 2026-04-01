import { CircleCheck, ChatDotRound, MagicStick, MoonNight, Notebook, OfficeBuilding, Reading, RefreshRight, School, Switch } from '@element-plus/icons-vue'
import { markRaw, type Component } from 'vue'
import type { HomeCategoryItem } from '@/api/home'

export type CategoryEntryKey =
  | 'fantasy'
  | 'romance'
  | 'urban'
  | 'mystery'
  | 'history'
  | 'school'
  | 'transmigration'
  | 'light-novel'
  | 'completed'
  | 'ongoing'

export interface CategoryNavigationEntry {
  key: CategoryEntryKey
  label: string
  description: string
  icon: Component
  iconClass: string
  matchNames?: string[]
  keyword?: string
  completionStatus?: 'completed' | 'ongoing'
}

export interface ResolvedCategoryFilter {
  categoryId?: number
  keyword?: string
  completionStatus?: 'completed' | 'ongoing'
}

const normalize = (value?: string | null) => String(value || '').trim().toLowerCase()

export const CATEGORY_NAVIGATION_ENTRIES: CategoryNavigationEntry[] = [
  {
    key: 'fantasy',
    label: '玄幻',
    description: '奇想世界',
    icon: markRaw(MagicStick),
    iconClass: 'bg-violet-100 text-violet-700',
    matchNames: ['玄幻', '奇幻', 'fantasy'],
    keyword: '玄幻',
  },
  {
    key: 'romance',
    label: '言情',
    description: '情感拉满',
    icon: markRaw(ChatDotRound),
    iconClass: 'bg-rose-100 text-rose-700',
    matchNames: ['言情', '恋爱', 'romance'],
    keyword: '言情',
  },
  {
    key: 'urban',
    label: '都市',
    description: '现实节奏',
    icon: markRaw(OfficeBuilding),
    iconClass: 'bg-sky-100 text-sky-700',
    matchNames: ['都市', '现代', 'urban'],
    keyword: '都市',
  },
  {
    key: 'mystery',
    label: '悬疑',
    description: '反转追凶',
    icon: markRaw(MoonNight),
    iconClass: 'bg-slate-100 text-slate-700',
    matchNames: ['悬疑', '推理', 'mystery', 'suspense'],
    keyword: '悬疑',
  },
  {
    key: 'history',
    label: '历史',
    description: '风云旧卷',
    icon: markRaw(Reading),
    iconClass: 'bg-amber-100 text-amber-700',
    matchNames: ['历史', 'history', 'historical'],
    keyword: '历史',
  },
  {
    key: 'school',
    label: '校园',
    description: '青春日常',
    icon: markRaw(School),
    iconClass: 'bg-emerald-100 text-emerald-700',
    matchNames: ['校园', 'school'],
    keyword: '校园',
  },
  {
    key: 'transmigration',
    label: '穿越',
    description: '时空冒险',
    icon: markRaw(Switch),
    iconClass: 'bg-cyan-100 text-cyan-700',
    matchNames: ['穿越', '重生', 'transmigration'],
    keyword: '穿越',
  },
  {
    key: 'light-novel',
    label: '轻小说',
    description: '轻快易读',
    icon: markRaw(Notebook),
    iconClass: 'bg-orange-100 text-orange-700',
    matchNames: ['轻小说', 'light novel', 'lightnovel'],
    keyword: '轻小说',
  },
  {
    key: 'completed',
    label: '完结',
    description: '一口气看',
    icon: markRaw(CircleCheck),
    iconClass: 'bg-lime-100 text-lime-700',
    completionStatus: 'completed',
  },
  {
    key: 'ongoing',
    label: '连载',
    description: '持续追更',
    icon: markRaw(RefreshRight),
    iconClass: 'bg-blue-100 text-blue-700',
    completionStatus: 'ongoing',
  },
]

export function getCategoryEntry(key?: string | null) {
  return CATEGORY_NAVIGATION_ENTRIES.find((item) => item.key === key) || null
}

export function resolveCategoryFilter(
  entry: CategoryNavigationEntry | null | undefined,
  categories: HomeCategoryItem[]
): ResolvedCategoryFilter {
  if (!entry) return {}
  if (entry.completionStatus) {
    return { completionStatus: entry.completionStatus }
  }

  const matchedCategory = categories.find((category) => {
    const candidates = [category.name, category.code, category.en_name].map(normalize)
    return (entry.matchNames || []).some((name) => candidates.includes(normalize(name)))
  })

  if (matchedCategory) {
    return { categoryId: matchedCategory.id }
  }

  return { keyword: entry.keyword || entry.label }
}
