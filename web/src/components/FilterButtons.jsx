export default function FilterButtons({ active, onChange }) {
  const btns = [
    { key: 'all',    label: 'All' },
    { key: 'attack', label: 'Threats' },
    { key: 'benign', label: 'Benign' },
  ]
  return (
    <div style={{ display: 'flex', gap: 5 }}>
      {btns.map(b => (
        <button
          key={b.key}
          onClick={() => onChange(b.key)}
          style={{
            padding: '3px 12px', borderRadius: 'var(--radius-full)',
            fontSize: 10, fontWeight: 700, border: '1px solid', cursor: 'pointer',
            background: active === b.key
              ? (b.key === 'attack' ? 'var(--threat-light)' : b.key === 'benign' ? 'var(--benign-light)' : 'var(--border)')
              : 'var(--surface)',
            color: active === b.key
              ? (b.key === 'attack' ? 'var(--threat)' : b.key === 'benign' ? 'var(--benign)' : 'var(--text)')
              : 'var(--text-muted)',
            borderColor: active === b.key
              ? (b.key === 'attack' ? 'var(--threat)' : b.key === 'benign' ? 'var(--benign)' : 'var(--text-faint)')
              : 'var(--border)',
          }}
        >{b.label}</button>
      ))}
    </div>
  )
}
