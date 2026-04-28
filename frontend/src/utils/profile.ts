import type { UserProfile } from '@/api/user'

export const DEFAULT_AVATAR_URL =
  'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=240&q=80'

export function resolveUserDisplayName(user: UserProfile | null) {
  if (!user) return ''
  return user.name || user.username || ''
}
