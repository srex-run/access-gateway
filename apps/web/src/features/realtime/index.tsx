import { Alert } from '@arco-design/web-react'
import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { connectEventStream } from '@/shared/api/event-stream'
import { changedQueryRoots } from './model'

export function RealtimeUpdates({ userID }: { userID: string }) {
  const client = useQueryClient()
  const [failure, setFailure] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    const pending = new Set<string>()
    let flush: ReturnType<typeof setTimeout> | undefined
    const clear = () => { clearTimeout(flush); flush = undefined; pending.clear() }
    void connectEventStream({
      signal: controller.signal,
      ready: () => {
        setFailure('')
        clear()
        // Invalidate inactive pages too, so revisiting them cannot reuse a
        // snapshot from before an outage. Only mounted queries fetch now.
        void client.invalidateQueries()
      },
      change: topic => {
        pending.add(topic)
        if (flush) return
        // One-shot batching is started by a change, never by an idle timer.
        flush = setTimeout(() => {
          const roots = changedQueryRoots(pending)
          clear()
          void client.invalidateQueries({ predicate: query => roots.has(String(query.queryKey[0])) })
        }, 250)
      },
      disconnected: setFailure,
      unauthorized: () => {
        controller.abort()
        clear()
        void client.cancelQueries().then(() => { client.clear(); window.location.replace('/login') })
      },
    })
    return () => { controller.abort(); clear() }
  }, [client, userID])
  return failure ? <Alert type="warning" content={failure} /> : null
}
