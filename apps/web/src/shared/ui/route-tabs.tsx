import { Tabs } from '@arco-design/web-react'
import { createContext, useContext, useState } from 'react'
import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { useSearchParams } from 'react-router-dom'

const ToolbarHost = createContext<HTMLDivElement | null | undefined>(undefined)

interface RouteTabsProps { items: { key: string; title: string; content: ReactNode }[]; param?: string }
export function RouteTabs({ items, param = 'tab' }: RouteTabsProps) {
  const [params, setParams] = useSearchParams()
  const [host, setHost] = useState<HTMLDivElement | null>(null)
  const current = params.get(param)
  const selected = items.find(item => item.key === current)?.key ?? items[0]?.key
  return <ToolbarHost.Provider value={host}><Tabs className="route-tabs" headerPadding={false} activeTab={selected} destroyOnHide extra={<div ref={setHost} className="tab-toolbar-host" />} onChange={value => setParams(previous => {
    const next = new URLSearchParams(previous)
    next.set(param, value)
    return next
  }, { replace: true })}>{items.map(item => <Tabs.TabPane key={item.key} title={item.title}>{item.content}</Tabs.TabPane>)}</Tabs></ToolbarHost.Provider>
}

// Keep query and form state in the active pane while placing its controls in the header.
export function TabToolbar({ title, children }: { title: string; children: ReactNode }) {
  const host = useContext(ToolbarHost)
  const toolbar = <div className="tab-toolbar">{children}</div>
  if (host !== undefined) return host ? createPortal(toolbar, host) : null
  return <Tabs className="route-tabs list-header" headerPadding={false} activeTab="list" extra={toolbar}>
    <Tabs.TabPane key="list" title={title} />
  </Tabs>
}
