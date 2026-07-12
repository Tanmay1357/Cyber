import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'

export default function DonutChart({ attacks, benign }) {
  const total = attacks + benign
  const pct = total > 0 ? ((attacks / total) * 100).toFixed(2) : '0.00'
  const data = [{ v: attacks || 0.001 }, { v: Math.max(benign, 0.001) }]
  return (
    <div className="surface panel" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
      <span className="label" style={{ alignSelf: 'flex-start' }}>Traffic Split</span>
      <ResponsiveContainer width={110} height={110}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={34} outerRadius={52} startAngle={90} endAngle={-270} dataKey="v" strokeWidth={0}>
            <Cell fill="#ef4444" />
            <Cell fill="#34d399" />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--threat)' }}>{pct}%</div>
        <div className="label">Attack</div>
      </div>
      {[['Attack', attacks, '#ef4444'], ['Benign', benign, '#34d399']].map(([l, v, c]) => (
        <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-muted)', width: '100%' }}>
          <span style={{ width: 10, height: 10, borderRadius: 3, background: c, flexShrink: 0 }} />
          <span style={{ flex: 1 }}>{l}</span>
          <strong style={{ color: 'var(--text)' }}>{v}</strong>
        </div>
      ))}
    </div>
  )
}
