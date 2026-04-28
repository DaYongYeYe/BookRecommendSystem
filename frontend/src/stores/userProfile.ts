import { defineStore } from 'pinia'
import { getUserProfile, type UserProfile } from '@/api/user'
import { getToken } from '@/api/request'

type ProfileState = {
  profile: UserProfile | null
  loaded: boolean
}

export const useUserProfileStore = defineStore('userProfile', {
  state: (): ProfileState => ({
    profile: null,
    loaded: false,
  }),
  actions: {
    async fetchProfile(force = false) {
      if (!getToken()) {
        this.clearProfile()
        return null
      }
      if (!force && this.loaded && this.profile) {
        return this.profile
      }
      const res = await getUserProfile()
      this.profile = res.user
      this.loaded = true
      return this.profile
    },
    async ensureProfileLoaded() {
      return this.fetchProfile(false)
    },
    setProfile(profile: UserProfile | null) {
      this.profile = profile
      this.loaded = Boolean(profile)
    },
    clearProfile() {
      this.profile = null
      this.loaded = false
    },
  },
})
