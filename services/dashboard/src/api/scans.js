import client from './client'

export const getScans = async (params = {}) => (await client.get('/scans', { params })).data

export const createScan = async (payload) => (await client.post('/scans', payload)).data
