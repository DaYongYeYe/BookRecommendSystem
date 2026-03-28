import request from './request'

export interface RbacRole {
  id: number
  name: string
  description?: string | null
  permission_count?: number
  user_count?: number
}

export interface RbacPermission {
  id: number
  name: string
  description?: string | null
}

export interface RbacUserSummary {
  id: number
  username: string
  email: string
  role: string
  is_super_admin?: boolean
}

export interface RbacRoleListResponse {
  roles: RbacRole[]
}

export interface RbacPermissionListResponse {
  permissions: RbacPermission[]
}

export function getRbacRoles() {
  return request.get<RbacRoleListResponse, RbacRoleListResponse>('/rbac/roles')
}

export function createRbacRole(data: { name: string; description?: string }) {
  return request.post('/rbac/roles', data)
}

export function updateRbacRole(roleId: number, data: { name?: string; description?: string }) {
  return request.put(`/rbac/roles/${roleId}`, data)
}

export function deleteRbacRole(roleId: number) {
  return request.delete(`/rbac/roles/${roleId}`)
}

export function getRbacPermissions() {
  return request.get<RbacPermissionListResponse, RbacPermissionListResponse>('/rbac/permissions')
}

export function createRbacPermission(data: { name: string; description?: string }) {
  return request.post('/rbac/permissions', data)
}

export function getRolePermissions(roleId: number) {
  return request.get<RbacPermissionListResponse, RbacPermissionListResponse>(`/rbac/roles/${roleId}/permissions`)
}

export function assignPermissionToRole(roleId: number, permissionId: number) {
  return request.post(`/rbac/roles/${roleId}/permissions`, { permission_id: permissionId })
}

export function removePermissionFromRole(roleId: number, permissionId: number) {
  return request.delete(`/rbac/roles/${roleId}/permissions/${permissionId}`)
}

export function getUserRoles(userId: number) {
  return request.get<RbacRoleListResponse, RbacRoleListResponse>(`/rbac/users/${userId}/roles`)
}

export function assignRoleToUser(userId: number, roleId: number) {
  return request.post(`/rbac/users/${userId}/roles`, { role_id: roleId })
}

export function removeRoleFromUser(userId: number, roleId: number) {
  return request.delete(`/rbac/users/${userId}/roles/${roleId}`)
}

export function getUserPermissions(userId: number) {
  return request.get<RbacPermissionListResponse, RbacPermissionListResponse>(`/rbac/users/${userId}/permissions`)
}
