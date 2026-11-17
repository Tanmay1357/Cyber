import { useMemo } from 'react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

const WINDOW = 60

export default function LiveTrafficChart({ history = [], labels = [] }) {
  const data = useMemo(() => {
    const h = history.slice(-WINDOW)
    const l = labels.slice(-WINDOW)
    return h.map((count, i) => ({ time: l[i] ?? '', count }))
  }, [history, labels])

  return (
    <div className="surface panel" style={{ overflow: 'hidden' }}>
      <div className="panel-header">
        <span className="label">Live Traffic</span>
      </div>
      <div style={{ height: 160 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 6, right: 10, left: -20, bottom: 0 }}>
            <XAxis
              dataKey="time"
              tick={{ fontSize: 8, fill: 'var(--text-xfaint)', fontFamily: 'var(--font-mono)' }}
              interval="preserveStartEnd"
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fontSize: 8, fill: 'var(--text-xfaint)' }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: 'var(--surface)', border: '1px solid var(--border)',
                borderRadius: 6, fontSize: 10, color: 'var(--text)',
              }}
              itemStyle={{ color: 'var(--accent)' }}
              labelStyle={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 9 }}
            />
            <Line
              type="monotone"
              dataKey="count"
              stroke="var(--accent)"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
