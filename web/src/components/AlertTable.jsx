import { useState } from 'react'
import FilterButtons from './FilterButtons'
import { InfoTip } from './ui'

function Row({ alert, selected, onSelect }) {
  const isAtk = alert.is_attack
  const sel = selected === alert.id
  // Confidence in the decision shown (falls back for older alerts without the field).
  const conf = alert.confidence != null
    ? alert.confidence
    : (isAtk ? alert.attack_prob : 1 - alert.attack_prob)
  return (
    <tr
      onClick={() => onSelect(alert.id)}
      style={{
        cursor: 'pointer',
        background: sel
          ? (isAtk ? 'var(--threat-light)' : 'var(--benign-light)')
          : (isAtk ? '#fff5f5' : '#f0fdf4'),
        borderLeft: `3px solid ${isAtk ? 'var(--threat)' : 'var(--benign)'}`,
        outline: sel ? `1px solid ${isAtk ? 'var(--threat-border)' : 'var(--benign-border)'}` : 'none',
        transition: 'background .12s',
      }}
    >
      <td style={{ padding: '7px 10px' }}>
        <span className={`badge badge--${isAtk ? 'attack' : 'benign'}`}>
          {isAtk ? 'ATTACK' : 'BENIGN'}
        </span>
      </td>
      <td className="mono" style={{ padding: '7px 6px', fontSize: 10, color: 'var(--text-muted)' }}>{alert.src_ip}</td>
      <td className="mono" style={{ padding: '7px 6px', fontSize: 10, color: 'var(--text-muted)' }}>{alert.dst_ip}:{alert.dst_port}</td>
      <td style={{ padding: '7px 6px', fontSize: 11, fontWeight: 700, color: isAtk ? 'var(--threat)' : 'var(--benign)' }}>
        {(conf * 100).toFixed(1)}%
      </td>
      <td className="mono" style={{ padding: '7px 10px', fontSize: 9, color: 'var(--text-xfaint)' }}>{alert.timestamp}</td>
    </tr>
  )
}

export default function AlertTable({ alerts, selectedId, onSelect, onClear }) {
  const [filter, setFilter] = useState('all')
  const visible = alerts.filter(a =>
    filter === 'all'    ? true :
    filter === 'attack' ? a.is_attack :
    !a.is_attack
  )
  return (
    <div className="surface panel" style={{ overflow: 'hidden' }}>
      <div className="panel-header">
        <span className="label">
          Alert Log {alerts.length > 0 && (
            <span style={{ color: 'var(--text-faint)', fontWeight: 500, marginLeft: 6 }}>({alerts.length})</span>
          )}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <FilterButtons active={filter} onChange={setFilter} />
          {onClear && alerts.length > 0 && (
            <button onClick={onClear} title="Clear all alerts from the buffer"
              style={{ padding: '3px 10px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)',
                border: '1px solid var(--border)', borderRadius: 5, background: 'var(--surface)', cursor: 'pointer' }}>
              Clear
            </button>
          )}
        </div>
      </div>
      <div style={{ overflowY: 'auto', maxHeight: 220 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Type</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Source</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Destination</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>
                <InfoTip text="The model's confidence in the decision shown (Attack or Benign). P(attack) ≥ threshold triggers an alert.">Confidence</InfoTip>
              </th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {visible.map(a => <Row key={a.id} alert={a} selected={selectedId} onSelect={onSelect} />)}
          </tbody>
        </table>
        {visible.length === 0 && (
          <p style={{ textAlign: 'center', color: 'var(--text-faint)', padding: 24, fontSize: 12 }}>
            No alerts yet.
          </p>
        )}
      </div>
    </div>
  )
}
