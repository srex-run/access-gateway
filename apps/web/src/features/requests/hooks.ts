import { Form, Message } from '@arco-design/web-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { assetQuery, portQuery, regionQuery } from '@/features/catalog'
import { useIdentity } from '@/features/auth'
import { createRequest, createTestAccess, cancelRequest, requestKeys, accessOptionsQuery } from './api'
import { createSubmissionKey, DEMO_SESSION_TTL_SECONDS, MAX_REQUEST_TTL_SECONDS, requestTargetAccountRequired, resolveRequestPort, toRequestInput } from './model'
import { formatDuration } from '@/shared/lib/format'
import type { RequestFormValues } from './types'

export function useRequestForm() {
  const [params] = useSearchParams()
  const [form] = Form.useForm<RequestFormValues>()
  const [selectedRegion, setRegion] = useState(params.get('region') ?? '')
  const [assetID, setAssetID] = useState(params.get('asset') ?? '')
  const [dirty, setDirty] = useState(false)
  const [clientAccess, setClientAccess] = useState(false)
  const targetAccountEdited = useRef(false)
  const accessOptions = useQuery(accessOptionsQuery)
  const demoMode = accessOptions.data?.demo_mode === true
  const identity = useIdentity()
  const canTest = !demoMode && (identity.data?.permissions.includes('role:manage') ?? false)
  const [testRequested, setTestRequested] = useState(params.get('mode') === 'test')
  const testAccess = canTest && testRequested
  const [keyFor] = useState(createSubmissionKey)
  const client = useQueryClient()
  const regions = useQuery(regionQuery)
  const availableRegions = regions.data?.filter(value => value.status === 'enabled')
  const region = selectedRegion || (availableRegions?.length === 1 ? availableRegions[0]?.id ?? '' : '')
  const assets = useQuery(assetQuery(region))
  const asset = assets.data?.find(value => value.id === assetID)
  const ports = useQuery(portQuery(asset?.id ?? ''))
  const targetPort: unknown = Form.useWatch('target_port', form)
  const targetAccountRequired = requestTargetAccountRequired(ports.data ?? [], targetPort)
  const maxTTL = Math.min(asset?.max_ttl_seconds ?? MAX_REQUEST_TTL_SECONDS, demoMode ? DEMO_SESSION_TTL_SECONDS : testAccess ? 600 : MAX_REQUEST_TTL_SECONDS)
  const demoDurationError = demoMode && asset && maxTTL < DEMO_SESSION_TTL_SECONDS ? `当前资产最多允许 ${formatDuration(maxTTL)}，无法创建 5 分钟演示会话，请选择其他资产。` : undefined
  useEffect(() => {
    if (!demoMode || targetAccountEdited.current) return
    const current: unknown = form.getFieldValue('target_account')
    if (current === undefined || current === null || current === '') form.setFieldsValue({ target_account: 'test' })
  }, [demoMode, form])
  useEffect(() => {
    if (region) form.setFieldsValue({ region_id: region })
  }, [region, form])
  useEffect(() => {
    if (!asset || !ports.isSuccess) return
    const selected: unknown = form.getFieldValue('target_port')
    const port = resolveRequestPort(ports.data, selected)
    if (port !== selected) form.setFieldsValue({ target_port: port })
  }, [asset, ports.data, ports.isSuccess, form])
  useEffect(() => {
    if (demoMode) {
      form.setFieldsValue({ ttl_seconds: DEMO_SESSION_TTL_SECONDS, emergency: false })
      return
    }
    if (!asset) return
    const ttl: unknown = form.getFieldValue('ttl_seconds')
    if (typeof ttl === 'number' && ttl > maxTTL) form.setFieldsValue({ ttl_seconds: maxTTL })
  }, [asset, maxTTL, demoMode, form])
  useEffect(() => {
    if (!targetAccountRequired && form.getFieldError('target_account')) form.setFields({ target_account: { error: undefined } })
  }, [targetAccountRequired, form])
  const create = useMutation({
    mutationFn: async (values: RequestFormValues) => {
      if (!accessOptions.isSuccess) throw new Error('访问配置尚未加载，请稍后重试。')
      if (demoDurationError) throw new Error(demoDurationError)
      const input = toRequestInput({ ...values, client_access: clientAccess && accessOptions.data?.client_access_enabled === true }, demoMode)
      return testAccess ? createTestAccess(input, keyFor(input, 'admin_test')) : createRequest(input, keyFor(input, demoMode ? 'demo' : 'required'))
    },
    onSuccess: async value => { await client.invalidateQueries({ queryKey: requestKeys.all }); Message.success(value.approval_mode === 'demo' ? '已自动审批，演示会话创建中' : testAccess ? '测试会话创建中' : '申请已提交') },
  })
  const changeRegion = (value: string) => {
    setRegion(value); setAssetID('')
    form.setFieldsValue({ asset_id: '', target_port: undefined })
  }
  const changeAsset = (value: string) => {
    setAssetID(value)
    const selected = assets.data?.find(item => item.id === value)
    const current: unknown = form.getFieldValue('ttl_seconds')
    form.setFieldsValue({ target_port: undefined, ttl_seconds: demoMode ? DEMO_SESSION_TTL_SECONDS : Math.min(selected?.max_ttl_seconds ?? 3600, testAccess ? 600 : MAX_REQUEST_TTL_SECONDS, typeof current === 'number' && current > 0 ? current : 3600) })
  }
  const changeTestAccess = (value: boolean) => {
    setTestRequested(value); setDirty(true); create.reset()
    if (value) {
      form.setFieldsValue({ emergency: false, ttl_seconds: Math.min(asset?.max_ttl_seconds ?? 600, 600) })
    }
  }
  const markTargetAccountEdited = () => { targetAccountEdited.current = true }
  return { form, region, assetID, asset, regions, assets, ports, targetAccountRequired, markTargetAccountEdited, dirty, setDirty, create, changeRegion, changeAsset, canTest, testAccess, changeTestAccess, maxTTL, demoMode, demoDurationError, userID: identity.data?.user_id, accessOptions, clientAccess, setClientAccess }
}

export function useCancelRequest() {
  const client = useQueryClient()
  return useMutation({ mutationFn: cancelRequest, onSuccess: async () => { await client.invalidateQueries({ queryKey: requestKeys.all }); Message.success('申请已取消') } })
}
