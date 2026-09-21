import { Form, Message } from '@arco-design/web-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { catalogKeys } from '@/features/catalog'

export function useAdminForm<T extends object, R>(submit: (value: T) => Promise<R>, successText = '保存成功') {
  const [form] = Form.useForm<T>()
  const [dirty, setDirty] = useState(false)
  const client = useQueryClient()
  const mutation = useMutation({
    mutationFn: submit,
    onSuccess: async () => {
      setDirty(false)
      await client.invalidateQueries({ queryKey: catalogKeys.all })
      Message.success(successText)
    },
  })
  const change = () => { setDirty(true); if (mutation.isSuccess || mutation.isError) mutation.reset() }
  return { form, dirty, mutation, change }
}
