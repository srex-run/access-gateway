export function downloadText(value: string, name: string) {
  const url = URL.createObjectURL(new Blob([value], { type: 'text/plain' }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  URL.revokeObjectURL(url)
}
