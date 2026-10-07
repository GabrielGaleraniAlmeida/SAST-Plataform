import client from './client'

export const getOverviewStats = async () => (await client.get('/stats/summary')).data

export const getSeverityDistribution = async () => {
  const { data } = await client.get('/stats/severity-distribution')
  return data.labels.map((label, i) => ({ severity: label.toLowerCase(), count: data.values[i] }))
}

export const getVulnerabilityTrend = async (days = 30) =>
  (await client.get('/stats/trends', { params: { days } })).data.data

export const getTopVulnerableFiles = async (limit = 5) => {
  const { data } = await client.get('/stats/top-files', { params: { limit } })
  return data.items.map((f) => ({ file_path: f.file_path, count: f.vulnerabilities_count }))
}

export const getVulnerabilitiesByRule = async (limit = 10) => {
  const { data } = await client.get('/stats/by-rule')
  return data.items.slice(0, limit)
}
