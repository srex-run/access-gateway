import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface Preferences {
  collapsed: boolean
  theme: 'light' | 'dark'
  toggleSidebar: () => void
  toggleTheme: () => void
}

export const usePreferences = create<Preferences>()(persist(set => ({
  collapsed: false, theme: 'light',
  toggleSidebar: () => set(state => ({ collapsed: !state.collapsed })),
  toggleTheme: () => set(state => ({ theme: state.theme === 'light' ? 'dark' : 'light' })),
}), { name: 'access-gateway-ui', partialize: ({ collapsed, theme }) => ({ collapsed, theme }) }))
