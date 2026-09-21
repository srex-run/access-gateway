const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
})

export function formatTime(value?: string | null): string {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '-' : dateFormatter.format(date)
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} 秒`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor(seconds % 3600 / 60)
  return [hours ? `${hours} 小时` : '', minutes ? `${minutes} 分钟` : ''].filter(Boolean).join(' ')
}

export function shortID(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value
}
