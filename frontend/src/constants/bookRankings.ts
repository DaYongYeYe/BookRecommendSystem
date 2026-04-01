export type BookRankingType = 'hot' | 'new_book' | 'surging' | 'completed' | 'collection' | 'following'

export interface BookRankingTypeOption {
  key: BookRankingType
  label: string
  description: string
  update_cycle: string
  primary_metric: string
  period_hint?: string
}

export const DEFAULT_RANKING_TYPES: BookRankingTypeOption[] = [
  {
    key: 'hot',
    label: '热门榜',
    description: '综合阅读热度、收藏人数和口碑表现排序。',
    update_cycle: '每小时更新',
    primary_metric: '综合热度',
    period_hint: '日榜/周榜/月榜后续开放',
  },
  {
    key: 'new_book',
    label: '新书榜',
    description: '优先展示近期上架且热度起势明显的新作品。',
    update_cycle: '每6小时更新',
    primary_metric: '新书热度',
    period_hint: '日榜/周榜/月榜后续开放',
  },
  {
    key: 'surging',
    label: '飙升榜',
    description: '按近7天增长速度排序，适合发现趋势作品。',
    update_cycle: '每2小时更新',
    primary_metric: '增长速度',
    period_hint: '日榜/周榜/月榜后续开放',
  },
  {
    key: 'completed',
    label: '完结榜',
    description: '优先展示已完结且口碑稳定的作品。',
    update_cycle: '每日更新',
    primary_metric: '完结口碑',
    period_hint: '日榜/周榜/月榜后续开放',
  },
  {
    key: 'collection',
    label: '收藏榜',
    description: '按加入书架人数排序，反映用户长期收藏意愿。',
    update_cycle: '每小时更新',
    primary_metric: '收藏人数',
    period_hint: '日榜/周榜/月榜后续开放',
  },
  {
    key: 'following',
    label: '追更榜',
    description: '聚焦连载作品的在读人数与近期追更活跃度。',
    update_cycle: '每小时更新',
    primary_metric: '追更热度',
    period_hint: '日榜/周榜/月榜后续开放',
  },
]

export function normalizeRankingType(value?: string | null): BookRankingType {
  const normalized = (value || '').trim() as BookRankingType
  return DEFAULT_RANKING_TYPES.some((item) => item.key === normalized) ? normalized : 'hot'
}

export function getRankingTypeMeta(type: BookRankingType) {
  return DEFAULT_RANKING_TYPES.find((item) => item.key === type) || DEFAULT_RANKING_TYPES[0]
}
