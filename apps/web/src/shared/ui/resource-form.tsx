import { Button, Form, Space } from '@arco-design/web-react'
import { IconCheck, IconClose } from '@arco-design/web-react/icon'
import type { FormInstance } from '@arco-design/web-react'
import type { ReactNode } from 'react'
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useUnsavedChanges } from '@/shared/hooks/use-unsaved-changes'
import { ErrorNotice } from './page'

interface ResourceFormProps<T extends object> {
  form: FormInstance<T>
  children: ReactNode
  initialValues?: Partial<T>
  onSubmit: (values: T) => void
  onChange?: () => void
  submitting: boolean
  dirty: boolean
  saved?: boolean
  backTo?: string
  error?: unknown
  submitText?: string
}

export function ResourceForm<T extends object>({ form, children, initialValues, onSubmit, onChange, submitting, dirty, saved = false, backTo, error, submitText = '保存' }: ResourceFormProps<T>) {
  const navigate = useNavigate()
  useUnsavedChanges(dirty && !saved)
  useEffect(() => { if (saved && backTo) void navigate(backTo, { replace: true }) }, [saved, backTo, navigate])
  return <Form<T> form={form} size="small" layout="vertical" className="resource-form" initialValues={initialValues} onSubmit={onSubmit} onValuesChange={onChange} disabled={submitting}>
    {children}
    <ErrorNotice error={error} />
    <div className="form-footer"><Space>
      <Button type="primary" htmlType="submit" icon={<IconCheck />} loading={submitting}>{submitText}</Button>
      {backTo && <Button icon={<IconClose />} disabled={submitting} onClick={() => void navigate(backTo)}>取消</Button>}
    </Space></div>
  </Form>
}
