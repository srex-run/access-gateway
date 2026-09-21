import { Modal } from '@arco-design/web-react'
import { useEffect } from 'react'
import { useBeforeUnload, useBlocker } from 'react-router-dom'

export function useUnsavedChanges(dirty: boolean): void {
  const blocker = useBlocker(dirty)
  useBeforeUnload(event => {
    if (dirty) {
      event.preventDefault()
      event.returnValue = ''
    }
  })
  useEffect(() => {
    if (blocker.state !== 'blocked') return
    const modal = Modal.confirm({
      title: '放弃未保存的修改？',
      content: '离开后，本次修改将不会保存。',
      okText: '放弃修改', cancelText: '继续编辑',
      onOk: () => blocker.proceed(), onCancel: () => blocker.reset(),
    })
    return () => modal.close()
  }, [blocker])
}
