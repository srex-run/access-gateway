import { Button, Input, Tooltip } from '@arco-design/web-react'
import { IconDelete, IconPlus } from '@arco-design/web-react/icon'
import { useState, type KeyboardEvent, type ReactNode } from 'react'
import { CompactTags } from './compact-tags'
import './labels.css'

export type Labels = Record<string, string>

function labelKeyName(key: string, value: Labels, keyAliases: Labels) {
  const alias = Object.hasOwn(keyAliases, key) ? keyAliases[key] : undefined
  return alias && !Object.hasOwn(value, alias) ? alias : key
}

export function LabelTags({ value = {}, keyAliases = {} }: { value?: Labels; keyAliases?: Labels }) {
  const labels = value ?? {}
  return <CompactTags values={Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)).map(([key, val]) => `${labelKeyName(key, labels, keyAliases)}=${val}`)} />
}

interface LabelEditorProps {
  value?: Labels
  onChange?: (value: Labels) => void
  disabled?: boolean
  compact?: boolean
  keyAliases?: Labels
  formatValue?: (key: string, value: string) => string
  renderValueInput?: (key: string, value: string, onChange: (value: string) => void) => ReactNode
  validateEntry?: (key: string, value: string) => boolean
}

export function LabelEditor({ value = {}, onChange, disabled = false, compact = false, keyAliases = {}, formatValue, renderValueInput, validateEntry }: LabelEditorProps) {
  const [key, setKey] = useState('')
  const [val, setVal] = useState('')
  const [adding, setAdding] = useState(false)
  const entries = Object.entries(value)
  const validEntry = !!key.trim() && (validateEntry?.(key.trim(), val.trim()) ?? true)
  const cancel = () => { setKey(''); setVal(''); setAdding(false) }
  const add = () => {
    const name = key.trim()
    if (disabled || !validEntry || entries.length >= 64) return
    const storedKey = Object.hasOwn(value, name) ? name : Object.entries(keyAliases).find(([, alias]) => alias === name)?.[0] ?? name
    onChange?.({ ...value, [storedKey]: val.trim() })
    cancel()
  }
  const addButton = <Tooltip content="添加标签"><Button type="text" htmlType="button" icon={<IconPlus />} aria-label="添加标签" disabled={disabled || adding || entries.length >= 64} onClick={() => setAdding(true)} /></Tooltip>
  const submitDraft = compact ? (event: KeyboardEvent<HTMLInputElement>) => { event.preventDefault(); add() } : undefined
  return <div className={`label-editor${compact ? ' label-editor--compact' : ''}`}>
    {entries.map(([k, v]) => {
      const name = labelKeyName(k, value, keyAliases)
      const displayValue = formatValue?.(k, v) ?? v
      return <div className="label-row" key={k}>
        {compact ? <Tooltip content={`${name}:${displayValue || '-'}`}><code className="label-inline-value">{name}:{displayValue || '-'}</code></Tooltip> : <><code className="break-text">{name}</code><span className="break-text">{displayValue || '-'}</span></>}
        <Tooltip content="删除标签"><Button type="text" htmlType="button" icon={<IconDelete />} aria-label={`删除标签 ${name}`} disabled={disabled || k.startsWith('access-gateway.io/')} onClick={() => { const next = { ...value }; delete next[k]; onChange?.(next) }} /></Tooltip>
        {compact && addButton}
      </div>
    })}
    {compact && !entries.length && !adding && !disabled && <div className="label-row">{addButton}</div>}
    {!disabled && (!compact || adding) && <div className="label-row label-row--draft">
      <Input aria-label="标签键" placeholder="标签键" value={key} onChange={setKey} maxLength={317} onPressEnter={submitDraft} />
      {compact && <span aria-hidden="true">:</span>}
      {renderValueInput?.(key.trim(), val, setVal) ?? <Input aria-label="标签值" placeholder="标签值" value={val} onChange={setVal} maxLength={63} onPressEnter={submitDraft} />}
      {compact && <Tooltip content="取消添加"><Button type="text" htmlType="button" icon={<IconDelete />} aria-label="取消添加标签" onClick={cancel} /></Tooltip>}
      <Tooltip content={compact ? '确认添加' : '添加标签'}><Button htmlType="button" icon={<IconPlus />} aria-label={compact ? '确认添加标签' : '添加标签'} disabled={!validEntry || entries.length >= 64} onClick={add} /></Tooltip>
    </div>}
  </div>
}
