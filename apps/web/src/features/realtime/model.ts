const topicKeys: Record<string, readonly string[]> = {
  notifications: ['notifications'],
  requests: ['requests', 'approvals', 'workflow-progress', 'sessions'],
  sessions: ['sessions', 'requests', 'workflow-progress'],
  cloud: ['admin', 'catalog'],
  catalog: ['catalog', 'governance', 'label-preview', 'sessions', 'requests', 'workflow-progress'],
  audit: ['audit'],
}

export function changedQueryRoots(topics: Iterable<string>): Set<string> {
  const roots = new Set<string>()
  for (const topic of topics) {
    if (Object.hasOwn(topicKeys, topic)) for (const key of topicKeys[topic]!) roots.add(key)
  }
  return roots
}
