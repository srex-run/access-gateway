import { expect, test } from '@playwright/test'
import { mockEncryptedTransport } from './transport-mock'

const userID = '11111111-1111-4111-8111-111111111111'
const expiresAt = '2030-01-01T00:00:00Z'
const providers = [{ id: 'local', name: '本地账号', kind: 'password' }]

test('password authentication stops at MFA until a second factor is verified', async ({ page }) => {
  let verified = false
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/auth/providers')) return route.fulfill({ json: providers })
    if (path.endsWith('/auth/me')) return route.fulfill({ status: verified ? 200 : 401, json: { user_id: userID, permissions: ['directory:read'] } })
    if (path.endsWith('/auth/local/login')) return transport.open(route).fulfill({ stage: 'mfa-verify', expires_at: expiresAt })
    if (path.endsWith('/auth/mfa')) return route.fulfill({ json: { stage: 'mfa-verify', expires_at: expiresAt } })
    if (path.endsWith('/auth/mfa/verify')) {
      const input = transport.open(route)
      expect(input.body).toEqual({ code: '123456' })
      verified = true
      return input.fulfill({ user_id: userID })
    }
    return route.fulfill({ json: [] })
  })
  const transport = await mockEncryptedTransport(page)
  await page.goto('/login')
  await page.getByLabel('账号', { exact: true }).fill('alice')
  await page.getByLabel('密码', { exact: true }).fill('correct-password')
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL(/\/mfa$/)
  expect(verified).toBe(false)
  await page.getByLabel('验证码或恢复码', { exact: true }).fill('123456')
  await page.getByRole('button', { name: '验证并登录' }).click()
  await expect(page).toHaveURL(/\/catalog$/)
})

test('enrollment renders QR locally and keeps recovery codes until acknowledged', async ({ page }) => {
  const secret = 'JBSWY3DPEHPK3PXP'
  const codes = Array.from({ length: 10 }, (_, index) => `${index}1234567-89ABCDEF-01234567-89ABCDEF`)
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/auth/mfa')) return route.fulfill({ json: { stage: 'mfa-enroll', expires_at: expiresAt } })
    if (path.endsWith('/auth/mfa/enroll')) return transport.open(route).fulfill({ secret, uri: `otpauth://totp/Access:alice?secret=${secret}&issuer=Access` })
    if (path.endsWith('/auth/mfa/confirm')) return transport.open(route).fulfill({ user_id: userID, codes })
    return route.fulfill({ json: [] })
  })
  const transport = await mockEncryptedTransport(page)
  await page.goto('/mfa')
  await page.getByRole('button', { name: '生成绑定二维码' }).click()
  await expect(page.locator('.mfa-enrollment svg')).toBeVisible()
  await expect(page.getByLabel('手动绑定密钥', { exact: true })).toHaveValue(secret)
  await page.getByLabel('验证码', { exact: true }).fill('123456')
  await page.getByRole('button', { name: '确认绑定', exact: true }).click()
  await expect(page.getByText(codes[0]!, { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '完成', exact: true })).toBeDisabled()
  await page.getByRole('checkbox', { name: '我已妥善保存恢复码' }).check()
  await expect(page.getByRole('button', { name: '完成', exact: true })).toBeEnabled()
  expect(await page.evaluate(() => JSON.stringify([localStorage, sessionStorage]))).not.toContain(secret)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
})

test('invitation token leaves the address bar and activation follows MFA policy', async ({ page }) => {
  const token = 'a'.repeat(43)
  let accepted = false
  const urls: string[] = []
  page.on('request', request => urls.push(request.url()))
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/auth/invitation/preview')) {
      const input = transport.open(route)
      expect(input.body).toEqual({ token })
      return input.fulfill({ username: 'alice', nickname: 'Alice', inviter_name: 'Admin', expires_at: expiresAt })
    }
    if (path.endsWith('/auth/invitation/accept')) {
      const input = transport.open(route)
      expect(input.body).toEqual({ token, password: 'invitation-password' })
      accepted = true
      return input.fulfill({ stage: 'mfa-enroll', expires_at: expiresAt })
    }
    if (path.endsWith('/auth/mfa')) return route.fulfill({ json: { stage: 'mfa-enroll', expires_at: expiresAt } })
    return route.fulfill({ json: [] })
  })
  const transport = await mockEncryptedTransport(page)
  await page.goto(`/invite#${token}`)
  await expect(page).toHaveURL(/\/invite$/)
  await expect(page.getByText('alice', { exact: true })).toBeVisible()
  await page.getByLabel('设置密码', { exact: true }).fill('invitation-password')
  await page.getByLabel('确认密码', { exact: true }).fill('mismatched-password')
  await page.getByRole('button', { name: '激活账户' }).click()
  await expect(page.getByText('两次输入的密码不一致')).toBeVisible()
  expect(accepted).toBe(false)
  await page.getByLabel('确认密码', { exact: true }).fill('invitation-password')
  await page.getByRole('button', { name: '激活账户' }).click()
  await expect(page).toHaveURL(/\/mfa$/)
  expect(urls.some(url => url.includes(token))).toBe(false)
})

test('administrators invite without choosing a password and receive a one-time fallback link', async ({ page }) => {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/auth/me')) return route.fulfill({ json: { user_id: userID, permissions: ['user:read', 'user:manage'] } })
    if (path.endsWith('/admin/invitations') && route.request().method() === 'POST') {
      const input = transport.open(route)
      expect(input.body).toEqual({ nickname: 'Alice', username: 'alice', email: 'alice@example.com' })
      return input.fulfill({ id: userID, username: 'alice', sent: false, delivery: 'not_configured', expires_at: expiresAt, accept_url: `https://access.example.com/invite#${'b'.repeat(43)}` }, 201)
    }
    return route.fulfill({ json: [] })
  })
  const transport = await mockEncryptedTransport(page)
  await page.goto('/admin/users/invite')
  await expect(page.getByLabel('初始密码', { exact: true })).toHaveCount(0)
  await page.getByLabel('昵称', { exact: true }).fill('Alice')
  await page.getByLabel('用户名', { exact: true }).fill('alice')
  await page.getByLabel('邮箱', { exact: true }).fill('alice@example.com')
  await page.getByRole('button', { name: '创建邀请', exact: true }).click()
  await expect(page.getByText('邮件服务尚未启用，请复制邀请链接交给受邀用户。')).toBeVisible()
  await expect(page.getByText(`https://access.example.com/invite#${'b'.repeat(43)}`, { exact: true })).toBeVisible()
})
