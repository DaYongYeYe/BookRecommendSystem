import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'
import Login from '@/views/Login.vue'
import Register from '@/views/Register.vue'
import Home from '@/views/Home.vue'
import Search from '@/views/Search.vue'
import CategoryDiscovery from '@/views/CategoryDiscovery.vue'
import Rankings from '@/views/Rankings.vue'
import RecommendationsMore from '@/views/RecommendationsMore.vue'
import CommunityPlaza from '@/views/CommunityPlaza.vue'
import Reader from '@/views/Reader.vue'
import BookDetail from '@/views/BookDetail.vue'
import BookEntry from '@/views/BookEntry.vue'
import CreatorEntry from '@/views/CreatorEntry.vue'
import UserProfileHub from '@/views/UserProfileHub.vue'
import UserProfile from '@/views/UserProfile.vue'
import UserLibrary from '@/views/UserLibrary.vue'
import UserReadingStats from '@/views/UserReadingStats.vue'
import AdminLogin from '@/views/admin/AdminLogin.vue'
import AdminRegister from '@/views/admin/AdminRegister.vue'
import AdminLayout from '@/views/admin/AdminLayout.vue'
import AdminDashboard from '@/views/admin/AdminDashboard.vue'
import AdminComments from '@/views/admin/AdminComments.vue'
import AdminBooks from '@/views/admin/AdminBooks.vue'
import AdminRecommendationConfig from '@/views/admin/AdminRecommendationConfig.vue'
import AdminWorksReview from '@/views/admin/AdminWorksReview.vue'
import AdminChaptersReview from '@/views/admin/AdminChaptersReview.vue'
import AdminUsers from '@/views/admin/AdminUsers.vue'
import AdminManuscriptsReview from '@/views/admin/AdminManuscriptsReview.vue'
import AdminRoles from '@/views/admin/AdminRoles.vue'
import AdminPermissions from '@/views/admin/AdminPermissions.vue'
import AdminRolePermissions from '@/views/admin/AdminRolePermissions.vue'
import AdminUserRoles from '@/views/admin/AdminUserRoles.vue'
import CreatorLayout from '@/views/creator/CreatorLayout.vue'
import CreatorDashboard from '@/views/creator/CreatorDashboard.vue'
import CreatorManuscripts from '@/views/creator/CreatorManuscripts.vue'
import CreatorBookChapters from '@/views/creator/CreatorBookChapters.vue'
import CreatorWorks from '@/views/creator/CreatorWorks.vue'
import Forbidden from '@/views/Forbidden.vue'
import { clearToken, getToken } from '@/api/request'
import { USER_PROFILE_HUB_ROUTE_NAME, USER_PROFILE_ROUTE_NAME } from '@/constants/routes'
import { isAdminToken, isCreatorToken, isSuperAdminToken } from '@/utils/auth'
import { applyRouteSeo } from '@/utils/seo'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: Home,
    meta: {
      seo: {
        title: '阿书铺子 | 现代图书推荐系统',
        description: '发现高分好书、热门榜单和个性化推荐，在阿书铺子开启沉浸式阅读。',
      },
    },
  },
  {
    path: '/search',
    name: 'Search',
    component: Search,
    meta: {
      seo: {
        title: '搜索图书 | 阿书铺子',
        description: '按书名、作者、分类和关键词搜索图书，快速找到适合当前阅读状态的作品。',
      },
    },
  },
  {
    path: '/categories',
    name: 'CategoryDiscovery',
    component: CategoryDiscovery,
    meta: {
      seo: {
        title: '分类发现 | 阿书铺子',
        description: '浏览玄幻、言情、现实、悬疑、科幻等图书分类，发现新的阅读方向。',
      },
    },
  },
  {
    path: '/recommendations',
    name: 'RecommendationsMore',
    component: RecommendationsMore,
    meta: {
      seo: {
        title: '更多推荐 | 阿书铺子',
        description: '查看更多精选图书推荐，按热度、口碑和阅读偏好扩展你的候选书单。',
      },
    },
  },
  {
    path: '/rankings',
    name: 'Rankings',
    component: Rankings,
    meta: {
      seo: {
        title: '图书排行榜 | 阿书铺子',
        description: '查看热门榜、新书榜、飙升榜、完结榜、收藏榜和追更榜，发现近期值得读的书。',
      },
    },
  },
  {
    path: '/community',
    name: 'CommunityPlaza',
    component: CommunityPlaza,
    meta: {
      seo: {
        title: '社区书单与书评 | 阿书铺子',
        description: '浏览读者创建的公开书单和书评，从真实阅读反馈里找到下一本好书。',
      },
    },
  },
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: {
      seo: {
        title: '登录 | 阿书铺子',
        description: '登录阿书铺子，同步书架、阅读进度和个性化推荐。',
        robots: 'noindex,nofollow',
      },
    },
  },
  {
    path: '/register',
    name: 'Register',
    component: Register,
    meta: {
      seo: {
        title: '注册 | 阿书铺子',
        description: '注册阿书铺子账号，建立个人书架并获得更贴合兴趣的图书推荐。',
        robots: 'noindex,nofollow',
      },
    },
  },
  {
    path: '/reader/:bookId',
    name: 'Reader',
    component: Reader,
    meta: { seo: { title: '阅读器 | 阿书铺子', robots: 'noindex,nofollow' } },
  },
  {
    path: '/books/:bookId',
    name: 'BookDetail',
    component: BookDetail,
    meta: {
      seo: {
        title: '图书详情 | 阿书铺子',
        description: '查看图书简介、评分、目录和相关推荐，判断是否适合现在开读。',
      },
    },
  },
  {
    path: '/books/:bookId/entry',
    name: 'BookEntry',
    component: BookEntry,
    meta: { seo: { title: '图书入口 | 阿书铺子', robots: 'noindex,nofollow' } },
  },
  {
    path: '/creator-center',
    name: 'CreatorEntry',
    component: CreatorEntry,
    meta: {
      seo: {
        title: '创作者入口 | 阿书铺子',
        description: '了解阿书铺子创作者能力，提交作品并管理自己的原创内容。',
      },
    },
  },
  {
    path: '/user/profile-hub',
    name: USER_PROFILE_HUB_ROUTE_NAME,
    component: UserProfileHub,
    meta: { requiresAuth: true },
  },
  {
    path: '/user/profile',
    name: USER_PROFILE_ROUTE_NAME,
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
    path: '/user/reading-stats',
    name: 'UserReadingStats',
    component: UserReadingStats,
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
        path: 'recommendation-config',
        name: 'AdminRecommendationConfig',
        component: AdminRecommendationConfig,
      },
      {
        path: 'works/review',
        name: 'AdminWorksReview',
        component: AdminWorksReview,
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
        path: 'chapters/review',
        name: 'AdminChaptersReview',
        component: AdminChaptersReview,
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
        redirect: '/creator/works',
      },
      {
        path: 'works',
        name: 'CreatorWorks',
        component: CreatorWorks,
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
      {
        path: 'books/:bookId/chapters',
        name: 'CreatorBookChapters',
        component: CreatorBookChapters,
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

const AUTH_CHECK_TTL_MS = 30 * 1000
let cachedAuthCheck:
  | {
      token: string
      checkedAt: number
      isAuthenticated: boolean
      role: string | null
      isCreator: boolean
    }
  | null = null

async function checkAuthRoleWithServer(token: string): Promise<{ isAuthenticated: boolean; role: string | null; isCreator: boolean } | null> {
  const now = Date.now()
  if (cachedAuthCheck && cachedAuthCheck.token === token && now - cachedAuthCheck.checkedAt <= AUTH_CHECK_TTL_MS) {
    return { isAuthenticated: cachedAuthCheck.isAuthenticated, role: cachedAuthCheck.role, isCreator: cachedAuthCheck.isCreator }
  }

  try {
    const response = await fetch('/auth/check', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    const payload = await response.json().catch(() => null)
    const isAuthenticated = Boolean(response.ok && payload?.is_authenticated && payload?.user)
    const role = (payload?.user?.role as string | undefined) ?? null
    const isCreator = Boolean(payload?.user?.is_creator || role === 'creator')
    cachedAuthCheck = {
      token,
      checkedAt: now,
      isAuthenticated,
      role,
      isCreator,
    }
    return { isAuthenticated, role, isCreator }
  } catch {
    return null
  }
}

router.beforeEach(async (to, _from, next) => {
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
    const serverAuth = await checkAuthRoleWithServer(token)
    if (serverAuth && !serverAuth.isAuthenticated) {
      clearToken()
      next({
        path: '/login',
        query: { redirect: to.fullPath },
      })
      return
    }
    if (serverAuth && !serverAuth.isCreator) {
      next({
        path: '/403',
        query: { redirect: to.fullPath },
      })
      return
    }
    if (!serverAuth && !isCreatorToken()) {
      next({
        path: '/403',
        query: { redirect: to.fullPath },
      })
      return
    }
  }

  if (to.path === '/creator-center') {
    const token = getToken()
    if (token) {
      const serverAuth = await checkAuthRoleWithServer(token)
      if (serverAuth && !serverAuth.isAuthenticated) {
        clearToken()
      } else if (serverAuth && serverAuth.isCreator) {
        next({ path: '/creator/works' })
        return
      }
    }
  }
  next()
})

router.afterEach((to) => {
  applyRouteSeo(to)
})

export default router

