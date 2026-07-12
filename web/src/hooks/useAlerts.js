import { useState, useEffect, useCallback } from 'react'
import { createWs } from '../api/ws'

const MAX_ALERTS = 200

export function useAlerts() {
  const [alerts, setAlerts]       = useState([])
  const [selectedId, setSelected] = useState(null)
  const [wsError, setWsError]     = useState(null)
  const [wsState, setWsState]     = useState('connecting')

  useEffect(() => {
    const conn = createWs('/ws/alerts', (msg) => {
      if (msg.kind === 'flow') {
        setAlerts(prev => [msg, ...prev].slice(0, MAX_ALERTS))
      } else if (msg.kind === 'error') {
        setWsError(msg.message)
      }
    }, {
      onStatus: (state) => {
        setWsState(state)
        if (state === 'open') setWsError(null)
      },
    })
    return () => conn.close()
  }, [])

  const selectAlert = useCallback((id) => setSelected(id), [])
  const clearLocal  = useCallback(() => { setAlerts([]); setSelected(null) }, [])

  return { alerts, selectedId, selectAlert, wsError, wsState, clearLocal }
}
