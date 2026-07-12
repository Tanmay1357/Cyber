import { useState } from 'react'

/* ── Page header with subtitle ───────────────────────────────────────── */
export function PageHeader({ title, subtitle, children }) {
  return (
    <div style={{ marginBottom: 24, display: 'flex', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
      <div style={{ flex: 1 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text)', margin: 0, marginBottom: 4 }}>
          {title}
        </h2>
        {subtitle && (
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
            {subtitle}
          </p>
        )}
      </div>
      {children && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>{children}</div>}
    </div>
  )
}

/* ── Hover tooltip with info icon ────────────────────────────────────── */
export function InfoTip({ text, children }) {
  const [show, setShow] = useState(false)
  return (
    <span style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', gap: 4 }}
      onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        width: 13, height: 13, borderRadius: '50%', border: '1px solid var(--text-xfaint)',
        color: 'var(--text-faint)', fontSize: 9, fontWeight: 700, cursor: 'help', userSelect: 'none' }}>?</span>
      {show && (
        <span style={{ position: 'absolute', bottom: '120%', left: '50%', transform: 'translateX(-50%)',
          background: '#0f172a', color: '#fff', fontSize: 10, lineHeight: 1.5, padding: '6px 10px',
          borderRadius: 6, whiteSpace: 'normal', minWidth: 200, maxWidth: 260, zIndex: 100,
          boxShadow: 'var(--shadow)', textAlign: 'left', fontWeight: 400, letterSpacing: 0 }}>
          {text}
        </span>
      )}
    </span>
  )
}

/* ── Stat / metric card with optional info tooltip ───────────────────── */
export function MetricCard({ label, value, color = 'var(--accent)', sub, info, accent }) {
  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '14px 16px', flex: 1, minWidth: 130, textAlign: 'center',
      borderTop: accent ? `3px solid ${color}` : '1px solid var(--border)' }}>
      <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 6, textTransform: 'uppercase',
        letterSpacing: 0.8, fontWeight: 600 }}>
        {info ? <InfoTip text={info}>{label}</InfoTip> : label}
      </p>
      <p style={{ fontSize: 22, fontWeight: 700, color, fontFamily: 'var(--font-mono)', lineHeight: 1.1 }}>
        {value}
      </p>
      {sub && <p style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 4 }}>{sub}</p>}
    </div>
  )
}

/* ── Skeleton loader (animated placeholder) ─────────────────────────── */
export function Skeleton({ width = '100%', height = 16, style }) {
  return <div className="skeleton" style={{ width, height, ...style }} />
}

/* ── Pill toggle group ───────────────────────────────────────────────── */
export function PillGroup({ options, value, onChange, disabled }) {
  return (
    <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
      {options.map(opt => (
        <button key={opt.id || opt} onClick={() => !disabled && onChange(opt.id || opt)} disabled={disabled}
          title={opt.help}
          style={{ padding: '5px 12px', fontSize: 11, fontWeight: 600, border: 'none',
            cursor: disabled ? 'default' : 'pointer',
            background: (opt.id || opt) === value ? 'var(--accent)' : 'transparent',
            color:      (opt.id || opt) === value ? '#fff' : 'var(--text-muted)' }}>
          {opt.label || opt}
        </button>
      ))}
    </div>
  )
}

