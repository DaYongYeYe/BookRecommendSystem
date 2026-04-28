import { getToken } from '@/api/request'

type JwtPayload = {
  is_admin?: boolean
  is_super_admin?: boolean
  tenant_id?: number
  role?: string
}

function decodeJwtPayload(token: string): JwtPayload | null {
  const parts = token.split('.')
  if (parts.length < 2) return null
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
    const payloadText = decodeURIComponent(
      atob(padded)
        .split('')
        .map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, '0')}`)
        .join('')
    )
    return JSON.parse(payloadText)
  } catch {
    return null
  }
}

export function isAdminToken(): boolean {
  const token = getToken()
  if (!token) return false
  const payload = decodeJwtPayload(token)
  if (!payload) return false
  return payload.is_admin === true || payload.role === 'admin'
}

export function isCreatorToken(): boolean {
  const token = getToken()
  if (!token) return false
  const payload = decodeJwtPayload(token)
  if (!payload) return false
  return payload.role === 'creator'
}

export function isSuperAdminToken(): boolean {
  const token = getToken()
  if (!token) return false
  const payload = decodeJwtPayload(token)
  if (!payload) return false
  return payload.is_super_admin === true
}

export function getTenantIdFromToken(): number | null {
  const token = getToken()
  if (!token) return null
  const payload = decodeJwtPayload(token)
  if (!payload) return null
  const raw = payload.tenant_id
  return typeof raw === 'number' ? raw : null
}
