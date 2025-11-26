图书推荐系统 包含用户端和管理端
使用前端使用vue3+element-plus 
后端使用python flask + mysql + redis

## 功能特性

### 用户管理
- 用户注册、登录、登出
- 用户信息管理
- 密码修改

### RBAC权限控制系统
- 角色管理（创建、更新、删除角色）
- 权限管理（创建、分配、移除权限）
- 用户角色分配
- 基于角色的权限访问控制

### 管理员功能
- 用户管理（查看、更新、删除用户）
- 系统配置管理

## API接口

### 认证接口
- POST /auth/register - 用户注册
- POST /auth/login - 用户登录
- POST /auth/logout - 用户登出
- GET /auth/check - 检查认证状态

### 用户接口
- GET /user/profile - 获取个人信息
- PUT /user/profile - 更新个人信息
- POST /user/change_password - 修改密码

### 管理员接口
- GET /admin/users - 获取所有用户
- GET /admin/users/<id> - 获取特定用户
- PUT /admin/users/<id> - 更新用户信息
- DELETE /admin/users/<id> - 删除用户

### 权限管理接口
- GET /rbac/roles - 获取所有角色
- POST /rbac/roles - 创建角色
- PUT /rbac/roles/<id> - 更新角色
- DELETE /rbac/roles/<id> - 删除角色
- GET /rbac/permissions - 获取所有权限
- POST /rbac/permissions - 创建权限
- POST /rbac/roles/<id>/permissions - 为角色分配权限
- DELETE /rbac/roles/<id>/permissions/<id> - 移除角色权限
- POST /rbac/users/<id>/roles - 为用户分配角色
- DELETE /rbac/users/<id>/roles/<id> - 移除用户角色
- GET /rbac/users/<id>/permissions - 获取用户权限