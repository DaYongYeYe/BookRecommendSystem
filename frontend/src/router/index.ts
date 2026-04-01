import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'
import Login from '@/views/Login.vue'
import Register from '@/views/Register.vue'
import Home from '@/views/Home.vue'
import Search from '@/views/Search.vue'
import CategoryDiscovery from '@/views/CategoryDiscovery.vue'
import Rankings from '@/views/Rankings.vue'
import RecommendationsMore from '@/views/RecommendationsMore.vue'
import Reader from '@/views/Reader.vue'
import BookDetail from '@/views/BookDetail.vue'
import BookEntry from '@/views/BookEntry.vue'
import CreatorEntry from '@/views/CreatorEntry.vue'
import UserProfile from '@/views/UserProfile.vue'
import UserLibrary from '@/views/UserLibrary.vue'
import AdminLogin from '@/views/admin/AdminLogin.vue'
import AdminRegister from '@/views/admin/AdminRegister.vue'
import AdminLayout from '@/views/admin/AdminLayout.vue'
import AdminDashboard from '@/views/admin/AdminDashboard.vue'
import AdminComments from '@/views/admin/AdminComments.vue'
import AdminBooks from '@/views/admin/AdminBooks.vue'
import AdminUsers from '@/views/admin/AdminUsers.vue'
import AdminManuscriptsReview from '@/views/admin/AdminManuscriptsReview.vue'
import AdminRoles from '@/views/admin/AdminRoles.vue'
import AdminPermissions from '@/views/admin/AdminPermissions.vue'
import AdminRolePermissions from '@/views/admin/AdminRolePermissions.vue'
import AdminUserRoles from '@/views/admin/AdminUserRoles.vue'
import CreatorLayout from '@/views/creator/CreatorLayout.vue'
import CreatorDashboard from '@/views/creator/CreatorDashboard.vue'
import CreatorManuscripts from '@/views/creator/CreatorManuscripts.vue'
import Forbidden from '@/views/Forbidden.vue'
import { getToken } from '@/api/request'
import { isAdminToken, isCreatorToken, isSuperAdminToken } from '@/utils/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: Home,
  },
  {
    path: '/search',
    name: 'Search',
    component: Search,
  },
  {
    path: '/categories',
    name: 'CategoryDiscovery',
    component: CategoryDiscovery,
  },
  {
    path: '/recommendations',
    name: 'RecommendationsMore',
    component: RecommendationsMore,
  },
  {
    path: '/rankings',
    name: 'Rankings',
    component: Rankings,
  },
  {
    path: '/login',
    name: 'Login',
    component: Login,
  },
  {
    path: '/register',
    name: 'Register',
    component: Register,
  },
  {
    path: '/reader/:bookId',
    name: 'Reader',
    component: Reader,
  },
  {
    path: '/books/:bookId',
    name: 'BookDetail',
    component: BookDetail,
  },
  {
    path: '/books/:bookId/entry',
    name: 'BookEntry',
    component: BookEntry,
  },
  {
    path: '/creator-center',
    name: 'CreatorEntry',
    component: CreatorEntry,
  },
  {
    path: '/user/profile',
    name: 'UserProfile',
    component: UserProfile,
    meta: { requiresAuth: true },
  },
  {
    path: '/user/library',
    name: 'UserLibrary',
    component: UserLibrary,
    meta: { requiresAuth: true },
  },
  {
    path: '/reader',
    redirect: '/reader/1',
  },
  {
    path: '/manage/login',
    name: 'AdminLogin',
    component: AdminLogin,
  },
  {
    path: '/admin',
    redirect: '/manage/dashboard',
  },
  {
    path: '/admin/:pathMatch(.*)*',
    redirect: (to) => {
      const rest = Array.isArray(to.params.pathMatch)
        ? to.params.pathMatch.join('/')
        : (to.params.pathMatch as string)
      return {
        path: `/manage/${rest || 'dashboard'}`,
        query: to.query,
      }
    },
  },
  {
    path: '/manage/register',
    name: 'AdminRegister',
    component: AdminRegister,
  },
  {
    path: '/403',
    name: 'Forbidden',
    component: Forbidden,
  },
  {
    path: '/manage',
    component: AdminLayout,
    meta: { requiresAdmin: true },
    children: [
      {
        path: '',
        redirect: '/manage/dashboard',
      },
      {
        path: 'dashboard',
        name: 'AdminDashboard',
        component: AdminDashboard,
      },
      {
        path: 'comments',
        name: 'AdminComments',
        component: AdminComments,
      },
      {
        path: 'books',
        name: 'AdminBooks',
        component: AdminBooks,
      },
      {
        path: 'users',
        name: 'AdminUsers',
        component: AdminUsers,
      },
      {
        path: 'manuscripts/review',
        name: 'AdminManuscriptsReview',
        component: AdminManuscriptsReview,
      },
      {
        path: 'rbac/roles',
        name: 'AdminRoles',
        component: AdminRoles,
        meta: { requiresSuperAdmin: true },
      },
      {
        path: 'rbac/permissions',
        name: 'AdminPermissions',
        component: AdminPermissions,
        meta: { requiresSuperAdmin: true },
      },
      {
        path: 'rbac/role-permissions',
        name: 'AdminRolePermissions',
        component: AdminRolePermissions,
        meta: { requiresSuperAdmin: true },
      },
      {
        path: 'rbac/user-roles',
        name: 'AdminUserRoles',
        component: AdminUserRoles,
        meta: { requiresSuperAdmin: true },
      },
    ],
  },
  {
    path: '/creator',
    component: CreatorLayout,
    meta: { requiresAuth: true, requiresCreator: true },
    children: [
      {
        path: '',
        redirect: '/creator/dashboard',
      },
      {
        path: 'dashboard',
        name: 'CreatorDashboard',
        component: CreatorDashboard,
      },
      {
        path: 'manuscripts',
        name: 'CreatorManuscripts',
        component: CreatorManuscripts,
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to, _from, next) => {
  if (to.meta.requiresAuth) {
    const token = getToken()
    if (!token) {
      next({
        path: '/login',
        query: { redirect: to.fullPath },
      })
      return
    }
  }

  if (to.meta.requiresAdmin) {
    const token = getToken()
    if (!token) {
      next({
        path: '/manage/login',
        query: { redirect: to.fullPath },
      })
      return
    }

    if (!isAdminToken()) {
      next({ path: '/login' })
      return
    }
  }

  if (to.meta.requiresSuperAdmin) {
    const token = getToken()
    if (!token) {
      next({
        path: '/manage/login',
        query: { redirect: to.fullPath },
      })
      return
    }
    if (!isAdminToken()) {
      next({ path: '/login' })
      return
    }
    if (!isSuperAdminToken()) {
      next({
        path: '/403',
        query: { redirect: to.fullPath },
      })
      return
    }
  }

  if (to.meta.requiresCreator) {
    const token = getToken()
    if (!token) {
      next({
        path: '/login',
        query: { redirect: to.fullPath },
      })
      return
    }
    if (!isCreatorToken()) {
      next({ path: '/' })
      return
    }
  }
  next()
})

export default router

