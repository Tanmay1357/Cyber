import { useState, useEffect } from 'react'
import { createWs } from '../api/ws'

const DEFAULT_STATS = {
  total_flows: 0, attacks: 0, benign: 0,
  threat_rate: 0, avg_confidence: 0,
  active_flows: 0, uptime_seconds: 0,
  traffic_history: [], traffic_labels: [],
}

export function useStats() {
  const [stats, setStats] = useState(DEFAULT_STATS)
  useEffect(() => {
    const conn = createWs('/ws/stats', (msg) => setStats(msg))
    return () => conn.close()
  }, [])
  return stats
}
