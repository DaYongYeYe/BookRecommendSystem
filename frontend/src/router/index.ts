import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'
import Login from '@/views/Login.vue'
import Register from '@/views/Register.vue'
import Home from '@/views/Home.vue'
import Reader from '@/views/Reader.vue'
import BookDetail from '@/views/BookDetail.vue'
import BookEntry from '@/views/BookEntry.vue'
import AdminLogin from '@/views/admin/AdminLogin.vue'
import AdminRegister from '@/views/admin/AdminRegister.vue'
import AdminLayout from '@/views/admin/AdminLayout.vue'
import AdminDashboard from '@/views/admin/AdminDashboard.vue'
import AdminComments from '@/views/admin/AdminComments.vue'
import AdminBooks from '@/views/admin/AdminBooks.vue'
import AdminUsers from '@/views/admin/AdminUsers.vue'
import { getToken } from '@/api/request'
import { isAdminToken } from '@/utils/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: Home,
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
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to, _from, next) => {
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
  next()
})

export default router

