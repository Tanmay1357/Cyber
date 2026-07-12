import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

export default function TrafficChart({ history, labels }) {
  const data = (history || []).map((v, i) => ({ t: (labels || [])[i] || '', v }))
  return (
    <div className="surface panel">
      <div className="panel-header">
        <span className="label">Live Traffic — Packet Rate</span>
        <div style={{ display: 'flex', gap: 12 }}>
          {[['Benign','#93c5fd'],['Attack','#ef4444']].map(([l,c]) => (
            <span key={l} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-muted)' }}>
              <span style={{ width: 10, height: 10, borderRadius: 3, background: c, display: 'inline-block' }} />{l}
            </span>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={140}>
        <BarChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
          <XAxis dataKey="t" tick={{ fontSize: 9, fill: 'var(--text-xfaint)', fontFamily: 'var(--font-mono)' }} interval="preserveStartEnd" />
          <YAxis tick={{ fontSize: 9, fill: 'var(--text-xfaint)' }} />
          <Tooltip contentStyle={{ fontSize: 11, borderRadius: 6, border: '1px solid var(--border)' }} />
          <Bar dataKey="v" radius={[3,3,0,0]} maxBarSize={24}>
            {data.map((d, i) => <Cell key={i} fill={d.v > 50 ? '#ef4444' : '#93c5fd'} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
