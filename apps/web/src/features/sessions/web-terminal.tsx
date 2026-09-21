import { Alert, Button, Form, Input, Select, Space, Tag } from '@arco-design/web-react'
import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { describeError, request, resourcePath, sealTerminalStart } from '@/shared/api/client'
import { HelpPopover } from '@/shared/ui/help-popover'
import { SectionTitle } from '@/shared/ui/page'
import type { SessionRecordDetail } from './types'
import { terminalClients, terminalProtocol, validTerminalDatabase } from './terminal-model'
import { terminalAppearance } from './terminal-theme'
import type { TerminalProtocol } from './terminal-model'
import '@xterm/xterm/css/xterm.css'
import './web-terminal.css'

type Status = 'idle' | 'connecting' | 'ready' | 'closed'
type TerminalDemoDefaults = { enabled: false } | { enabled: true; password: string; database: string }
const statusText: Record<Status, string> = { idle: '未连接', connecting: '连接中', ready: '已连接', closed: '已断开' }
const terminalSize = (term: Terminal) => ({ rows: Math.min(300, Math.max(2, term.rows)), cols: Math.min(500, Math.max(2, term.cols)) })

export function WebTerminal({ value }: { value: SessionRecordDetail }) {
  const session = value.session
  const protocol = terminalProtocol(session.audit_policy?.protocol)
  return session.connection_mode === 'audit' && protocol ? <ClientTerminal value={value} protocol={protocol} key={`${session.id}:${protocol}`} /> : null
}

function ClientTerminal({ value, protocol }: { value: SessionRecordDetail; protocol: TerminalProtocol }) {
  const { session } = value
  const client = terminalClients[protocol]
  const ssh = protocol === 'ssh'
  const panel = useRef<HTMLDivElement>(null)
  const host = useRef<HTMLDivElement>(null)
  const terminal = useRef<Terminal | null>(null)
  const fitAddon = useRef<FitAddon | null>(null)
  const socket = useRef<WebSocket | null>(null)
  const disposeConnection = useRef<(() => void) | null>(null)
  const defaultsRequest = useRef<AbortController | null>(null)
  const defaultsConsumed = useRef(false)
  const editedCredentials = useRef({ password: false, database: false })
  const ready = useRef(false)
  const [status, setStatus] = useState<Status>('idle')
  const [error, setError] = useState('')
  const [method, setMethod] = useState<'password' | 'key'>('password')
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [database, setDatabase] = useState<string>(client.database ?? '')
  const [authSource, setAuthSource] = useState('admin')
  const [fullscreen, setFullscreen] = useState(false)
  const [fontSize, setFontSize] = useState(14)
  const [hasSelection, setHasSelection] = useState(false)
  const [focused, setFocused] = useState(false)

  useEffect(() => {
    if (!session.can_web_connect || defaultsConsumed.current || (protocol === 'http' && !value.target_account)) return
    const controller = new AbortController()
    defaultsRequest.current = controller
    // Fetch secrets through encrypted transport directly; never put them in the query cache.
    void request<TerminalDemoDefaults>(resourcePath('sessions', session.id, '/terminal/demo-defaults'), { method: 'POST', body: {}, signal: controller.signal }).then(defaults => {
      if (controller.signal.aborted) return
      defaultsConsumed.current = true
      if (!defaults.enabled) return
      if (!editedCredentials.current.password) setPassword(defaults.password)
      if (!editedCredentials.current.database && ['mysql', 'postgresql', 'mongodb'].includes(protocol)) setDatabase(defaults.database)
    }).catch(reason => {
      if (!controller.signal.aborted) setError(`默认连接信息加载失败：${describeError(reason)}`)
    })
    return () => { controller.abort(); defaultsRequest.current = null }
  }, [session.can_web_connect, session.id, protocol, value.target_account])

  useEffect(() => {
    if (!host.current) return
    // xterm only blinks the caret while the terminal holds focus; an inactive
    // outline keeps it locatable so the screen never looks frozen.
    const term = new Terminal({ ...terminalAppearance(), cursorBlink: true, cursorStyle: 'block', cursorInactiveStyle: 'outline', disableStdin: true, scrollback: 10000 })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(host.current)
    terminal.current = term
    fitAddon.current = fit
    const input = term.textarea
    const trackFocus = () => setFocused(!!input && input.ownerDocument.activeElement === input)
    input?.addEventListener('focus', trackFocus)
    input?.addEventListener('blur', trackFocus)
    trackFocus()
    let frame = 0
    const observer = new ResizeObserver(() => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => fit.fit())
    })
    observer.observe(host.current)
    const data = term.onData((text: string) => {
      if (!ready.current || socket.current?.readyState !== WebSocket.OPEN) return
      // Bound pasted input as well as individual keystrokes (UTF-8 ≤ 16 KiB).
      let chunk = ''
      for (const character of text) {
        if (chunk.length + character.length > 4096) { socket.current.send(JSON.stringify({ type: 'input', data: chunk })); chunk = '' }
        chunk += character
      }
      if (chunk) socket.current.send(JSON.stringify({ type: 'input', data: chunk }))
    })
    const resize = term.onResize(({ rows, cols }: { rows: number; cols: number }) => {
      if (ready.current && socket.current?.readyState === WebSocket.OPEN) socket.current.send(JSON.stringify({ type: 'resize', rows: Math.min(300, Math.max(2, rows)), cols: Math.min(500, Math.max(2, cols)) }))
    })
    // Legacy mouse reports contain raw bytes outside UTF-8. Keep xterm's
    // binary input separate from JSON keyboard/IME/bracketed-paste data.
    const binary = term.onBinary((text: string) => {
      if (!ready.current || socket.current?.readyState !== WebSocket.OPEN) return
      const bytes = Uint8Array.from(text, character => character.charCodeAt(0) & 255)
      for (let offset = 0; offset < bytes.length; offset += 16384) socket.current.send(bytes.subarray(offset, offset + 16384))
    })
    const selection = term.onSelectionChange(() => setHasSelection(term.hasSelection()))
    term.attachCustomKeyEventHandler(event => {
      if (event.type !== 'keydown') return true
      if (event.key === 'Enter' && !event.isComposing) {
        // xterm forwards Enter to the PTY; keep it out of page shortcuts and forms.
        event.preventDefault()
        event.stopPropagation()
      }
      if (event.key.toLowerCase() === 'l' && event.ctrlKey && !event.shiftKey && !event.altKey && !event.metaKey) {
        event.preventDefault()
        clearScreen()
        return false
      }
      // Keep Ctrl+C/Ctrl+V available to the remote shell. Copy uses the
      // desktop terminal shortcuts; ordinary browser paste stays with xterm.
      if (event.key.toLowerCase() === 'c' && !event.altKey && ((event.metaKey && !event.ctrlKey) || (event.ctrlKey && event.shiftKey && !event.metaKey))) {
        event.preventDefault()
        void copySelection()
        return false
      }
      if (event.key.toLowerCase() === 'v' && event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey) {
        event.preventDefault()
        void paste()
        return false
      }
      return true
    })
    const onFullscreen = () => { setFullscreen(document.fullscreenElement === panel.current); fit.fit(); term.focus() }
    document.addEventListener('fullscreenchange', onFullscreen)
    fit.fit()
    return () => {
      ready.current = false
      disposeConnection.current?.()
      cancelAnimationFrame(frame)
      document.removeEventListener('fullscreenchange', onFullscreen)
      input?.removeEventListener('focus', trackFocus); input?.removeEventListener('blur', trackFocus)
      observer.disconnect(); data.dispose(); binary.dispose(); resize.dispose(); selection.dispose(); term.dispose(); terminal.current = null; fitAddon.current = null
    }
  }, [])

  useEffect(() => {
    if (!session.can_web_connect && socket.current) disconnect()
  }, [session.can_web_connect])

  useEffect(() => {
    if (status !== 'ready') return
    const term = terminal.current
    const ws = socket.current
    if (!term || !ws) return
    // React must commit the connected layout before xterm measures its host
    // and takes focus. A fit alone does not repaint when rows/cols are equal.
    let frame = requestAnimationFrame(() => {
      if (!ready.current || terminal.current !== term || socket.current !== ws || ws.readyState !== WebSocket.OPEN) return
      fitAddon.current?.fit()
      term.refresh(0, term.rows - 1)
      ws.send(JSON.stringify({ type: 'resize', ...terminalSize(term) }))
      // Unmounting the login form hands focus back to the document. Claim it
      // one frame later, or the caret never starts blinking on connect.
      frame = requestAnimationFrame(() => term.focus())
    })
    return () => cancelAnimationFrame(frame)
  }, [status])

  function disconnect() {
    ready.current = false
    disposeConnection.current?.()
    if (terminal.current) terminal.current.options.disableStdin = true
    setStatus('closed')
  }

  function focusTerminal() {
    if (ready.current) terminal.current?.focus()
  }

  function clearScreen() {
    const term = terminal.current
    if (!term) return
    term.clear()
    // Ask the active client to redraw its prompt and any pending input.
    if (ready.current) term.input('\x0c', true)
    term.scrollToBottom()
    term.focus()
  }

  async function copySelection() {
    const text = terminal.current?.getSelection()
    if (!text) return
    try { await navigator.clipboard.writeText(text) }
    catch { setError('复制失败，请允许浏览器访问剪贴板。') }
    terminal.current?.focus()
  }

  async function paste() {
    try {
      const text = await navigator.clipboard.readText()
      if (ready.current) { terminal.current?.paste(text); terminal.current?.focus() }
    } catch { setError('无法读取剪贴板，请在终端中使用浏览器的粘贴快捷键。') }
  }

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement === panel.current) await document.exitFullscreen()
      else await panel.current?.requestFullscreen()
    } catch { setError('浏览器未允许全屏显示。') }
  }

  function changeFontSize(size: number) {
    setFontSize(size)
    if (terminal.current) terminal.current.options.fontSize = size
    fitAddon.current?.fit()
    terminal.current?.focus()
  }

  async function connect() {
    const term = terminal.current
    if (!session.can_web_connect || status === 'connecting' || status === 'ready') return
    if (!term) { setError('终端尚未准备完成，请稍后重试。'); return }
    if (!validTerminalDatabase(protocol, database, authSource)) {
      setError(protocol === 'redis' ? '数据库编号必须为非负整数。' : '数据库名仅支持字母、数字、下划线、短横线和点，最多 128 个字符。'); return
    }
    if (location.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)) {
      setError('请通过 HTTPS 打开站内终端。'); return
    }
    // A delayed response must not replace submitted values or refill cleared credentials.
    defaultsConsumed.current = true
    defaultsRequest.current?.abort()
    const url = new URL(`/api/v1/sessions/${encodeURIComponent(session.id)}/terminal`, location.origin)
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    disposeConnection.current?.()
    const controller = new AbortController()
    ready.current = false
    setStatus('connecting'); setError(''); term.reset(); term.options.disableStdin = true
    // Only an encrypted envelope can leave the browser, including localhost.
    let start: Record<string, unknown> | null = { type: 'start', ...terminalSize(term), ...(!ssh || method === 'password' ? { password } : { private_key: privateKey, passphrase }), ...(client.database !== undefined ? { database } : {}), ...(protocol === 'mongodb' ? { auth_source: authSource } : {}) }
    let sealed: Awaited<ReturnType<typeof sealTerminalStart>> | null = null
    const timeout = window.setTimeout(() => {
      if (controller.signal.aborted || ready.current) return
      setError('终端连接超时，请检查目标服务后重新连接。')
      disconnect()
    }, 30_000)
    disposeConnection.current = () => { start = null; controller.abort(); window.clearTimeout(timeout) }
    try {
      await request(resourcePath('sessions', session.id, '/terminal/preflight'), { method: 'POST', signal: controller.signal })
      if (controller.signal.aborted) return
      sealed = await sealTerminalStart(url.pathname, start, controller.signal)
      setPassword(''); setPrivateKey(''); setPassphrase('')
    }
    catch (error) {
      if (!controller.signal.aborted) { setError(describeError(error)); disconnect() }
      return
    } finally { start = null }
    if (controller.signal.aborted) return
    let ws: WebSocket
    try { ws = new WebSocket(url) }
    catch { setError('浏览器无法建立终端连接，请检查网站连接配置后重试。'); disconnect(); return }
    ws.binaryType = 'arraybuffer'
    socket.current = ws
    let finished = false
    disposeConnection.current = () => {
      sealed = null
      controller.abort()
      window.clearTimeout(timeout)
      ws.onopen = null; ws.onmessage = null; ws.onerror = null; ws.onclose = null
      ws.close(1000)
      if (socket.current === ws) socket.current = null
    }
    ws.onopen = () => { if (sealed) ws.send(JSON.stringify(sealed)); sealed = null }
    ws.onmessage = event => {
      if (socket.current !== ws) return
      if (event.data instanceof ArrayBuffer) { term.write(new Uint8Array(event.data)); return }
      try {
        const message: unknown = JSON.parse(String(event.data))
        if (!message || typeof message !== 'object' || !('type' in message)) throw new Error('invalid response')
        if (message.type === 'ready') {
          window.clearTimeout(timeout)
          ready.current = true; term.options.disableStdin = false; setStatus('ready')
        }
        else if (message.type === 'exit') { finished = true; disconnect() }
        else if (message.type === 'error') { finished = true; setError('data' in message && typeof message.data === 'string' ? message.data : '终端连接失败'); disconnect() }
      } catch { finished = true; setError('终端响应无效'); disconnect() }
    }
    ws.onerror = () => { finished = true; sealed = null; setError('会话检查已通过，但 WebSocket 连接失败。请检查网站代理是否转发 Upgrade / Connection 请求头；后端日志可按会话 ID 查询拒绝原因。') }
    ws.onclose = () => {
      if (socket.current !== ws) return
      if (!finished) setError('终端连接已中断，请重新连接。')
      disconnect()
    }
  }

  const busy = status === 'connecting' || status === 'ready'
  return <section className="session-web-terminal" aria-label="站内终端">
    <SectionTitle>站内终端 · {client.name}<HelpPopover title="站内终端">直接通过网站使用 {client.client}，无需开放公网会话端口。使用申请中的目标账号登录，凭据仅用于本次连接。{ssh ? '支持密码和 SSH 私钥认证，连接目标主机的真实 shell。目录和软链接颜色取决于目标的 ls 配置；Linux 可用 ls --color=auto -al 查看彩色列表。' : protocol === 'http' ? '输入 GET /path 或 POST /path --data 内容发起请求；支持 curl 请求参数。填写目标账号时使用 HTTP Basic 认证，也可在请求中设置认证头。' : '可以使用对应客户端的查询、事务和数据库管理命令；访问范围受目标账号权限及端口审计规则约束。'}支持方向键、Tab、Ctrl+C 和原生客户端快捷键。复制选中文字使用 ⌘C 或 Ctrl+Shift+C；粘贴使用 ⌘V、Ctrl+Shift+V 或工具栏按钮。可调整字号和全屏显示，窗口大小自动同步。终端输出及操作会被审计，关闭页面会断开客户端；会话到期或结束后自动回收。</HelpPopover></SectionTitle>
    {session.can_web_connect && !busy && <Form layout="vertical" onSubmit={connect} className="terminal-login">
      <div className="terminal-login-fields">
        {(protocol !== 'http' || value.target_account) && <Form.Item label="目标账号"><Input aria-label="终端目标账号" value={value.target_account} readOnly /></Form.Item>}
        {ssh && <Form.Item label="认证方式"><Select aria-label="终端认证方式" value={method} onChange={setMethod} options={[{ value: 'password', label: '密码' }, { value: 'key', label: 'SSH 私钥' }]} /></Form.Item>}
        {(!ssh || method === 'password') ? (protocol !== 'http' || value.target_account) && <Form.Item label={<>目标密码{!ssh && <HelpPopover title="目标密码">使用目标服务的登录密码；目标账号允许空密码时可以留空。</HelpPopover>}</>}><Input.Password aria-label="终端目标密码" value={password} onChange={next => { editedCredentials.current.password = true; setPassword(next) }} autoComplete="off" maxLength={8192} /></Form.Item> : <>
          <Form.Item label={<>SSH 私钥<HelpPopover title="SSH 私钥">粘贴完整的 OpenSSH 或 PEM 私钥，包括 BEGIN 和 END 行。对应公钥须已添加到目标账号的 authorized_keys。</HelpPopover></>} className="terminal-login-field-wide"><Input.TextArea aria-label="终端 SSH 私钥" value={privateKey} onChange={setPrivateKey} autoComplete="off" maxLength={32768} autoSize={{ minRows: 3, maxRows: 6 }} /></Form.Item>
          <Form.Item label={<>私钥口令<HelpPopover title="私钥口令">仅在私钥已加密时填写创建私钥时设置的口令；未加密的私钥可留空。</HelpPopover></>}><Input.Password aria-label="终端私钥口令" value={passphrase} onChange={setPassphrase} autoComplete="off" maxLength={8192} /></Form.Item>
        </>}
        {client.database !== undefined && <Form.Item label={protocol === 'redis' ? '数据库编号' : '数据库名'}><Input aria-label="终端数据库" value={database} onChange={next => { editedCredentials.current.database = true; setDatabase(next) }} maxLength={128} placeholder={protocol === 'mysql' ? '选填，连接后可使用 USE 切换' : undefined} /></Form.Item>}
        <div className="terminal-login-actions"><Button type="primary" htmlType="submit" disabled={ssh && (method === 'password' ? !password : !privateKey)}>连接终端</Button></div>
        {protocol === 'mongodb' && <Form.Item label={<>认证数据库<HelpPopover title="认证数据库">MongoDB 账号所在的数据库，通常为 admin；它可以与要访问的数据库不同。</HelpPopover></>}><Input aria-label="终端认证数据库" value={authSource} onChange={setAuthSource} maxLength={128} /></Form.Item>}
      </div>
    </Form>}
    {!session.can_web_connect && <Alert type="info" content={session.status === 'provisioning' ? '会话准备完成后可连接终端。' : '仅申请人可在有效会话内连接终端。'} />}
    <div className="terminal-panel" ref={panel}>
      <div className="terminal-toolbar">
        <Space size="mini" wrap>
          <Tag color={status === 'ready' ? 'green' : undefined}>{statusText[status]}</Tag>
          <Button size="small" disabled={status !== 'ready'} onClick={() => { terminal.current?.input('\x03', true); terminal.current?.focus() }}>中断 Ctrl+C</Button>
          <Button size="small" onClick={clearScreen}>清屏 Ctrl+L</Button>
          <Button size="small" disabled={!hasSelection} onClick={() => void copySelection()}>复制选中</Button>
          <Button size="small" disabled={status !== 'ready'} onClick={() => void paste()}>粘贴</Button>
        </Space>
        <Space size="mini" wrap>
          <Select aria-label="终端字号" size="small" className="terminal-font-size" value={fontSize} onChange={changeFontSize} getPopupContainer={() => panel.current ?? document.body} options={[12, 14, 16, 18, 20].map(size => ({ value: size, label: `${size} px` }))} />
          <Button size="small" onClick={() => void toggleFullscreen()}>{fullscreen ? '退出全屏' : '全屏终端'}</Button>
          {busy && <Button size="small" onClick={disconnect}>断开终端</Button>}
        </Space>
      </div>
      {error && <Alert type="error" content={error} />}
      <div className="terminal-screen" data-ready={status === 'ready'} data-focused={focused} onPointerEnter={focusTerminal} onPointerDown={focusTerminal}><div className="terminal-host" ref={host} style={{ fontSize, fontFamily: terminalAppearance().fontFamily }} aria-label={`${client.name} 会话终端`} /></div>
      {status === 'ready' && !focused && <button type="button" className="terminal-focus-hint" onMouseDown={event => event.preventDefault()} onClick={focusTerminal}>点击终端继续输入</button>}
    </div>
  </section>
}
