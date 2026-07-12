export default function StatusBar({ modelFile, source, stats }) {
  const items = [
    { dot: '#059669', text: `Model: ${modelFile || 'not loaded'}` },
    { dot: '#2563eb', text: `Source: ${source || '—'}` },
    { dot: '#94a3b8', text: `Flows: ${stats.total_flows}` },
    { dot: '#94a3b8', text: `Attacks: ${stats.attacks}` },
  ]
  return (
    <div style={{ background: 'var(--surface)', borderTop: '1px solid var(--border)', padding: '7px 24px', display: 'flex', alignItems: 'center', gap: 20, flexShrink: 0 }}>
      {items.map((it, i) => (
        <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: it.dot, flexShrink: 0 }} />
          {it.text}
        </span>
      ))}
      <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-xfaint)', fontFamily: 'var(--font-mono)' }}>NIDS-XAI v1.0 — FYP 2026</span>
    </div>
  )
}
