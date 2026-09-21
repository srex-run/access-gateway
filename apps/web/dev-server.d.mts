export function developmentWebConfig(env: Record<string, string | undefined>): {
  port: number
  host: string
  publicURL: string
  allowedHosts: string[]
}
