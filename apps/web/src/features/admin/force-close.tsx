import { Button, Form, Input, Modal, Select } from '@arco-design/web-react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { openRecordsQuery, SessionStatusTag, useSessionActions } from '@/features/sessions'
import type { SessionRecord } from '@/features/sessions'
import { ErrorNotice } from '@/shared/ui/page'
import { ResourceForm } from '@/shared/ui/resource-form'
import { useState } from 'react'
import { requiredRules } from './fields'

function sessionLabel(session: SessionRecord) {
  return `${session.asset_name}:${session.target_port} · ${session.applicant_name} · ${session.target_account || '未指定账号'} · ${session.id.slice(0, 8)}`
}

function SessionOption({ session }: { session: SessionRecord }) {
  return <span className="force-session-option" title={`${sessionLabel(session)} · ${session.id}`}>
    <span className="force-session-label">{sessionLabel(session)}</span><SessionStatusTag status={session.status} />
  </span>
}

export function ForceCloseForm() {
  const [form] = Form.useForm<{ id: string; reason: string }>()
  const [dirty, setDirty] = useState(false)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<SessionRecord>()
  const query = useInfiniteQuery(openRecordsQuery(search))
  const records = [...new Map((query.data?.pages.flatMap(page => page.records) ?? []).map(record => [record.id, record])).values()]
  const { forceClose } = useSessionActions()
  return <ResourceForm form={form} onSubmit={value => {
    Modal.confirm({
      title: '强制回收会话？',
      content: <><p className="break-text">{selected ? sessionLabel(selected) : value.id}</p><p>现有连接将被关闭，此操作将记录到审计日志。</p></>,
      okText: '确认回收',
      onOk: async () => {
        await forceClose.mutateAsync(value)
        form.resetFields()
        setSelected(undefined)
        setSearch('')
        setDirty(false)
      },
    })
  }} onChange={() => setDirty(true)} dirty={dirty} submitting={forceClose.isPending} error={forceClose.error} submitText="强制回收">
    <ErrorNotice error={query.error} retry={() => void (query.isFetchNextPageError ? query.fetchNextPage() : query.refetch())} />
    <Form.Item label="开放会话" field="id" rules={[{ required: true, message: '请选择需要回收的开放会话' }]}>
      <Select aria-label="开放会话" placeholder="搜索申请人、资产、账号或会话编号" showSearch allowClear filterOption={false}
        loading={query.isFetching} onSearch={value => setSearch(value.trim())}
        onChange={id => setSelected(records.find(record => record.id === id))}
        onVisibleChange={visible => { if (visible) void query.refetch() }}
        notFoundContent={query.isPending ? '加载中…' : query.isError ? '加载失败，请重试' : search ? '没有匹配的开放会话' : '暂无开放会话'}
        options={records.map(record => ({ value: record.id, label: <SessionOption session={record} /> }))}
        renderFormat={(option, value) => {
          const id = typeof value === 'object' ? value.value : value
          return option?.children ?? (selected?.id === id ? <SessionOption session={selected} /> : typeof value === 'object' ? value.label : value)
        }}
        onPopupScroll={element => {
          if (element.scrollHeight - element.scrollTop - element.clientHeight < 32 && query.hasNextPage && !query.isFetching && !query.isFetchNextPageError) void query.fetchNextPage()
        }}
        dropdownRender={menu => <>{menu}{query.hasNextPage && <Button type="text" long loading={query.isFetchingNextPage} disabled={query.isFetching && !query.isFetchingNextPage} onMouseDown={event => event.preventDefault()} onClick={() => void query.fetchNextPage()}>加载更多</Button>}</>}
      />
    </Form.Item>
    <Form.Item label="回收原因" field="reason" rules={requiredRules}><Input.TextArea maxLength={2000} autoSize={{ minRows: 2, maxRows: 4 }} /></Form.Item>
  </ResourceForm>
}
