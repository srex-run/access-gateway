import { IconApps, IconCheckCircle, IconHistory, IconSafe, IconSettings, IconUserGroup } from '@arco-design/web-react/icon'
import { navigationItems } from '@/shared/config/navigation'

const icons = { apps: <IconApps />, approval: <IconCheckCircle />, audit: <IconHistory />, security: <IconSafe />, users: <IconUserGroup />, settings: <IconSettings /> }
export const navigation = navigationItems.map(item => ({ ...item, icon: icons[item.icon] }))
