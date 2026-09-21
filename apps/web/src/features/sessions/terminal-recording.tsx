import { useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Button, Empty, Modal, Space } from '@arco-design/web-react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import { ErrorNotice } from '@/shared/ui/page'
import { HelpPopover } from '@/shared/ui/help-popover'
import { terminalRecordingQuery } from './api'
import { terminalAppearance } from './terminal-theme'
import './terminal-recording.css'

function TerminalRecording({ sessionId, channelId, cols }: { sessionId: string; channelId: string; cols: number }) {
  const host = useRef<HTMLDivElement>(null)
  const terminal = useRef<Terminal | null>(null)
  const rendered = useRef<string[]>([])
  const query = useInfiniteQuery(terminalRecordingQuery(sessionId, channelId))
  const frames = useMemo(() => (query.data?.pages.flatMap(page => page.frames) ?? []).map(frame => {
    try { return { id: frame.id, bytes: Uint8Array.from(atob(frame.data), char => char.charCodeAt(0)) } }
    catch { return { id: frame.id, bytes: null } }
  }), [query.data])
  const invalid = frames.some(frame => !frame.bytes)

  useEffect(() => {
    if (!host.current) return
    const term = new Terminal({ ...terminalAppearance(), cols: Math.max(2, Math.min(500, cols || 120)), rows: 24, disableStdin: true, cursorBlink: false, cursorInactiveStyle: 'none', scrollback: 10000 })
    term.open(host.current)
    terminal.current = term
    rendered.current = []
    return () => { terminal.current = null; term.dispose() }
  }, [cols])

  useEffect(() => {
    const term = terminal.current
    if (!term) return
    const previous = rendered.current
    if (previous.some((id, index) => frames[index]?.id !== id)) {
      term.reset()
      rendered.current = []
    }
    for (const frame of frames.slice(rendered.current.length)) {
      // Feed original bytes, preserving UTF-8 and escape sequences split
      // between frames. xterm restores spacing, cursor edits and tables.
      if (frame.bytes) term.write(frame.bytes)
      rendered.current.push(frame.id)
    }
  }, [frames, cols])

  return <div className="terminal-recording">
    <div className="terminal-recording-toolbar"><Space>
      <Button size="small" loading={query.isFetching} onClick={() => void query.refetch()}>刷新记录</Button>
      {query.hasNextPage && <Button size="small" loading={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>加载后续记录</Button>}
      <HelpPopover title="终端记录">按原始顺序还原此终端中的命令回显和响应，保留表格、换行及颜色。执行结果与耗时可在访问轨迹的对应命令中查看。</HelpPopover>
    </Space></div>
    <ErrorNotice error={query.error} retry={() => void query.refetch()} />
    {invalid && <Alert type="error" content="部分历史输出无法解码。" />}
    {!query.isPending && !query.error && frames.length === 0 && <Empty description="暂无终端输出" />}
    <div className="terminal-recording-viewport"><div className="terminal-recording-screen" ref={host} aria-label="终端审计记录" /></div>
  </div>
}

export function TerminalRecordingButton({ sessionId, channelId, cols = 120 }: { sessionId: string; channelId: string; cols?: number }) {
  const [open, setOpen] = useState(false)
  return <>
    <Button type="text" size="small" onClick={() => setOpen(true)}>查看终端记录</Button>
    <Modal visible={open} title="终端记录" footer={null} onCancel={() => setOpen(false)} unmountOnExit style={{ width: 'min(1100px, calc(100vw - 32px))' }}>
      {open && <TerminalRecording sessionId={sessionId} channelId={channelId} cols={cols} />}
    </Modal>
  </>
}
