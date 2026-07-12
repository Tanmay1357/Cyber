function Sparkline({ data, color, height = 24 }) {
  if (!data || data.length < 2) {
    return <div style={{ height, marginTop: 6 }} />
  }
  const max = Math.max(...data, 1)
  const min = Math.min(...data, 0)
  const range = max - min || 1
  const w = 120
  const stepX = w / (data.length - 1)
  const points = data
    .map((v, i) => `${(i * stepX).toFixed(1)},${(height - ((v - min) / range) * height).toFixed(1)}`)
    .join(' ')
  return (
    <svg width={w} height={height} style={{ marginTop: 6, display: 'block', overflow: 'visible' }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}

function SkeletonCard({ borderRight }) {
  return (
    <div style={{ padding: '16px 24px', borderRight: borderRight ? '1px solid var(--border-subtle)' : 'none' }}>
      <div className="skeleton" style={{ width: '60%', height: 32, marginTop: 8, borderRadius: 6 }} />
      <div className="skeleton" style={{ width: 120, height: 24, marginTop: 6, borderRadius: 6 }} />
      <div className="skeleton" style={{ width: '50%', height: 10, marginTop: 8, borderRadius: 4 }} />
      <div className="skeleton" style={{ width: '70%', height: 8, marginTop: 4, borderRadius: 4 }} />
    </div>
  )
}

export default function KpiCards({ stats }) {
  const trafficHistory = stats.traffic_history || []
  const isEmpty = stats.total_flows === 0 && trafficHistory.length === 0

  if (isEmpty) {
    return (
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
        {[0, 1, 2, 3].map(i => <SkeletonCard key={i} borderRight={i < 3} />)}
      </div>
    )
  }

  // Approximate per-bucket attack rate by re-using the threat_rate as a constant
  // across history (we don't track per-bucket attack counts on the wire).
  const threatRateHistory = trafficHistory.map(() => stats.threat_rate || 0)

  const cards = [
    {
      label:  'Attacks Detected',
      value:  stats.attacks,
      color:  'var(--threat)',
      delta:  `${stats.attacks} alerts in buffer`,
      sparkData: trafficHistory.map((flows, i) => Math.round(flows * (threatRateHistory[i] || 0))),
    },
    {
      label:  'Benign Flows',
      value:  stats.benign,
      color:  'var(--accent)',
      delta:  'normal baseline',
      sparkData: trafficHistory,
    },
    {
      label:  'Threat Rate',
      value:  `${(stats.threat_rate * 100).toFixed(2)}%`,
      color:  'var(--amber)',
      delta:  stats.threat_rate > 0.001 ? 'above threshold' : 'within normal',
      sparkData: threatRateHistory,
    },
    {
      label:  'Avg Confidence',
      value:  `${(stats.avg_confidence * 100).toFixed(1)}%`,
      color:  'var(--benign)',
      delta:  'model certainty',
      sparkData: trafficHistory.length > 1
        ? trafficHistory.map(() => stats.avg_confidence || 0)
        : [],
    },
  ]

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
      {cards.map((c, i) => (
        <div key={c.label}
          style={{ padding: '16px 24px', borderRight: i < 3 ? '1px solid var(--border-subtle)' : 'none',
            position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3,
            background: `linear-gradient(90deg, ${c.color}, ${c.color}88)` }} />
          <div style={{ fontSize: 30, fontWeight: 800, color: c.color, marginTop: 8, lineHeight: 1.1 }}>{c.value}</div>
          <Sparkline data={c.sparkData} color={c.color} />
          <div className="label" style={{ marginTop: 5 }}>{c.label}</div>
          <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 3 }}>{c.delta}</div>
        </div>
      ))}
    </div>
  )
}
