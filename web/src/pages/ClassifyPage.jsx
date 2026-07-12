import { useState, useRef } from 'react'
import TopBar from '../components/TopBar'
import http from '../api/http'
import { PageHeader, InfoTip } from '../components/ui'
import { useModel } from '../hooks/useModel'

function StatCard({ label, value, color, sub }) {
  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '16px 18px', flex: 1, minWidth: 130, borderTop: `3px solid ${color}` }}>
      <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>{label}</p>
      <p style={{ fontSize: 22, fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>{value}</p>
      {sub && <p style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 2 }}>{sub}</p>}
    </div>
  )
}

function ExplanationCard({ exp }) {
  if (exp.error) {
    return (
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
        <p style={{ fontSize: 11, color: 'var(--threat)' }}>{exp.error}</p>
      </div>
    )
  }
  const isAttack = exp.prediction?.toUpperCase() === 'ATTACK'
  const conf = isAttack ? exp.attack_prob : 1 - exp.attack_prob   // confidence in the decision shown
  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>
          row #{exp.row_index}
        </span>
        <span style={{ padding: '2px 8px', borderRadius: 99, fontSize: 10, fontWeight: 700,
          background: isAttack ? 'var(--threat-light)' : 'var(--benign-light)',
          color:      isAttack ? 'var(--threat)'       : 'var(--benign)' }}>
          {exp.prediction} · {(conf * 100).toFixed(1)}%
        </span>
        {exp.predicted_type && isAttack && (
          <span title="Predicted attack category from the type classifier"
            style={{ fontSize: 10, fontWeight: 700, color: 'var(--threat)',
              background: 'var(--threat-light)', border: '1px solid var(--threat-border)',
              borderRadius: 99, padding: '2px 8px' }}>
            {exp.predicted_type}{exp.predicted_type_conf != null ? ` ${(exp.predicted_type_conf * 100).toFixed(0)}%` : ''}
          </span>
        )}
        {exp.actual_type && (
          <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)',
            border: '1px solid var(--border)', borderRadius: 99, padding: '2px 8px' }}>
            {exp.actual_type}
          </span>
        )}
      </div>
      {exp.summary && (
        <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7, marginBottom: 10, whiteSpace: 'pre-wrap' }}>
          {exp.summary}
        </p>
      )}
      {exp.top_factors?.map((f, i) => (
        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11,
          fontFamily: 'var(--font-mono)', padding: '3px 0',
          color: f.direction === 'positive' ? '#dc2626' : '#2563eb' }}>
          <span>{f.feature}</span>
          <span>{f.shap_value > 0 ? '+' : ''}{f.shap_value.toFixed(4)}</span>
        </div>
      ))}
    </div>
  )
}

function MetricsPanel({ metrics }) {
  const { confusion: c } = metrics
  const pct = v => `${(v * 100).toFixed(1)}%`
  const cells = [
    { label: 'Accuracy',  value: pct(metrics.accuracy),  color: '#2563eb' },
    { label: 'Precision', value: pct(metrics.precision), color: '#7c3aed' },
    { label: 'Recall',    value: pct(metrics.recall),    color: '#059669' },
    { label: 'F1 Score',  value: pct(metrics.f1),        color: '#d97706' },
  ]
  return (
    <div style={{ marginBottom: 24 }}>
      <p className="label" style={{ marginBottom: 10 }}>
        Measured Against Ground Truth (CSV contained a Label column)
      </p>
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        {cells.map(m => (
          <div key={m.label} style={{ background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '14px 18px', flex: 1, minWidth: 120, borderTop: `3px solid ${m.color}` }}>
            <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>{m.label}</p>
            <p style={{ fontSize: 22, fontWeight: 700, color: m.color, fontFamily: 'var(--font-mono)' }}>{m.value}</p>
          </div>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr', gap: 1, background: 'var(--border)',
        border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden', maxWidth: 420 }}>
        {[
          { k: '',           a: 'Pred. Benign', b: 'Pred. Attack', head: true },
          { k: 'Actual Benign', a: c.tn, b: c.fp },
          { k: 'Actual Attack', a: c.fn, b: c.tp },
        ].map((r, i) => (
          [r.k, r.a, r.b].map((val, j) => (
            <div key={`${i}-${j}`} style={{ background: 'var(--surface)', padding: '8px 12px', fontSize: 11,
              fontFamily: 'var(--font-mono)', textAlign: j === 0 ? 'left' : 'center',
              fontWeight: r.head || j === 0 ? 700 : 400,
              color: r.head || j === 0 ? 'var(--text-muted)' : 'var(--text)' }}>
              {val}
            </div>
          ))
        ))}
      </div>
      <p style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 8 }}>
        TP {c.tp} · TN {c.tn} · FP {c.fp} · FN {c.fn} — over {metrics.actual_attacks + metrics.actual_benign} labelled flows
        ({metrics.actual_attacks} attack / {metrics.actual_benign} benign).
      </p>
    </div>
  )
}

function TypeBreakdown({ items }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <p className="label" style={{ marginBottom: 10 }}>
        <InfoTip text="The true attack types in this file come from its Label column. The model gives an Attack/Benign verdict; this table shows how many flows of each type it flagged as an attack.">
          Attack Types in This File
        </InfoTip>
      </p>
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', fontSize: 11 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-faint)' }}>
              <th style={{ padding: '8px 12px' }}>Type</th>
              <th style={{ padding: '8px 12px', textAlign: 'right' }}>Flows</th>
              <th style={{ padding: '8px 12px', textAlign: 'right' }}>Flagged as attack</th>
              <th style={{ padding: '8px 12px', textAlign: 'right' }}>Detection rate</th>
            </tr>
          </thead>
          <tbody>
            {items.map(t => (
              <tr key={t.type} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <td style={{ padding: '6px 12px', fontWeight: 600,
                  color: t.is_benign ? 'var(--benign)' : 'var(--threat)' }}>{t.type}</td>
                <td style={{ padding: '6px 12px', textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{t.count.toLocaleString()}</td>
                <td style={{ padding: '6px 12px', textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{t.flagged_attack.toLocaleString()}</td>
                <td style={{ padding: '6px 12px', textAlign: 'right', fontFamily: 'var(--font-mono)',
                  color: t.is_benign ? 'var(--text-faint)' : (t.detection_rate >= 0.95 ? 'var(--benign)' : 'var(--amber)') }}>
                  {t.is_benign ? '—' : `${(t.detection_rate * 100).toFixed(1)}%`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function ClassifyPage() {
  const [file, setFile]       = useState(null)
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr]         = useState(null)
  const [reExpLoading, setReExpLoading] = useState(false)
  const inputRef = useRef(null)
  const { modelInfo } = useModel()

  async function randomiseExplanations() {
    if (!file) return
    setReExpLoading(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const r = await http.post('/classify/explanations?n_explain=3', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setData(d => ({ ...d, explanations: r.data.explanations }))
    } catch (e) {
      setErr(e.response?.data?.detail || 'Could not refresh explanations.')
    } finally {
      setReExpLoading(false)
    }
  }

  async function classify() {
    if (!file) return
    setLoading(true); setErr(null); setData(null)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const r = await http.post('/classify?explain=true&n_explain=3', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setData(r.data)
    } catch (e) {
      setErr(e.response?.data?.detail || 'Classification failed.')
    } finally {
      setLoading(false)
    }
  }

  function onPick(e) {
    const f = e.target.files?.[0]
    if (f) setFile(f)
  }

  function onDrop(e) {
    e.preventDefault()
    const f = e.dataTransfer.files?.[0]
    if (f && f.name.toLowerCase().endsWith('.csv')) setFile(f)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <TopBar />
      <div style={{ flex: 1, padding: '32px 40px', overflowY: 'auto', maxWidth: 1100, width: '100%', margin: '0 auto' }}>

        <PageHeader
          title="Classify Unknown Data"
          subtitle="Upload a CSV in CICFlowMeter format (the same column layout as the CIC-IDS datasets). The active model classifies every flow as Attack or Benign, and SHAP explains a few representative samples so you can see why."
        >
          {modelInfo?.model_file && (
            <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>
              Using: <strong style={{ color: 'var(--text-muted)' }}>{modelInfo.model_file}</strong>
            </span>
          )}
        </PageHeader>

        {/* Drop zone */}
        <div onDrop={onDrop} onDragOver={e => e.preventDefault()}
          style={{ border: '2px dashed var(--border)', borderRadius: 10, padding: '32px 20px',
            textAlign: 'center', background: 'var(--surface)', marginBottom: 18 }}>
          <input ref={inputRef} type="file" accept=".csv" onChange={onPick} style={{ display: 'none' }} />
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>
            {file ? <strong>{file.name}</strong> : 'Drop a CSV file here, or click to browse'}
          </p>
          <button onClick={() => inputRef.current?.click()}
            style={{ padding: '6px 16px', background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 6, fontSize: 11, fontWeight: 600, cursor: 'pointer', marginRight: 8 }}>
            Browse…
          </button>
          <button onClick={classify} disabled={!file || loading}
            style={{ padding: '6px 22px', background: !file || loading ? 'var(--border)' : 'var(--accent)',
              color: '#fff', border: 'none', borderRadius: 6, fontSize: 11, fontWeight: 700,
              cursor: !file || loading ? 'default' : 'pointer' }}>
            {loading ? 'Classifying…' : 'Classify'}
          </button>
        </div>

        {err && <p style={{ color: 'var(--threat)', fontSize: 12, marginBottom: 16 }}>{err}</p>}

        {data && (
          <>
            <p style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 12 }}>
              {data.filename} · {data.total.toLocaleString()} rows analyzed
            </p>

            <div style={{ display: 'flex', gap: 10, marginBottom: 24, flexWrap: 'wrap' }}>
              <StatCard label="Total"   value={data.total.toLocaleString()}    color="#2563eb" />
              <StatCard label="Attacks" value={data.attacks.toLocaleString()}  color="#dc2626" sub={`${data.attack_pct}%`} />
              <StatCard label="Benign"  value={data.benign.toLocaleString()}   color="#059669" sub={`${data.benign_pct}%`} />
              <StatCard label="Avg Confidence" value={`${(data.avg_confidence * 100).toFixed(1)}%`} color="#7c3aed" />
            </div>

            {data.metrics && <MetricsPanel metrics={data.metrics} />}

            {data.type_breakdown?.length > 0 && <TypeBreakdown items={data.type_breakdown} />}

            {data.explanations?.length > 0 && (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                  <p className="label" style={{ margin: 0 }}>Sample Explanations (SHAP)</p>
                  <button onClick={randomiseExplanations} disabled={reExpLoading || !file}
                    title="Pick and explain a different random set of flows"
                    style={{ padding: '4px 12px', fontSize: 11, fontWeight: 700,
                      background: reExpLoading ? 'var(--border)' : 'var(--surface)', color: 'var(--accent)',
                      border: '1px solid var(--accent-border)', borderRadius: 6,
                      cursor: reExpLoading || !file ? 'default' : 'pointer' }}>
                    {reExpLoading ? 'Randomising…' : '🎲 Randomise'}
                  </button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12, marginBottom: 24 }}>
                  {data.explanations.map((e, i) => <ExplanationCard key={i} exp={e} />)}
                </div>
              </>
            )}

            {data.preview?.length > 0 && (
              <>
                <p className="label" style={{ marginBottom: 10 }}>
                  Per-Row Preview {data.total > 100 && <span style={{ color: 'var(--text-faint)', fontWeight: 400 }}>(first 100 of {data.total.toLocaleString()})</span>}
                </p>
                <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
                  <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                    <table style={{ width: '100%', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      <thead style={{ position: 'sticky', top: 0, background: 'var(--surface)' }}>
                        <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                          <th style={{ padding: '8px 12px', fontWeight: 600 }}>#</th>
                          <th style={{ padding: '8px 12px', fontWeight: 600 }}>Prediction</th>
                          <th style={{ padding: '8px 12px', fontWeight: 600, textAlign: 'right' }}>Attack Prob</th>
                          {data.preview[0]?.actual_type != null && <th style={{ padding: '8px 12px', fontWeight: 600 }}>Attack Type</th>}
                          {data.metrics && <th style={{ padding: '8px 12px', fontWeight: 600 }}>Actual</th>}
                          {data.metrics && <th style={{ padding: '8px 12px', fontWeight: 600, textAlign: 'center' }}>✓</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {data.preview.map(r => (
                          <tr key={r.index} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                            <td style={{ padding: '6px 12px', color: 'var(--text-faint)' }}>{r.index}</td>
                            <td style={{ padding: '6px 12px',
                              color: r.prediction === 'Attack' ? 'var(--threat)' : 'var(--benign)', fontWeight: 600 }}>
                              {r.prediction}
                            </td>
                            <td style={{ padding: '6px 12px', textAlign: 'right' }}>{(r.attack_prob * 100).toFixed(1)}%</td>
                            {r.actual_type != null && (
                              <td style={{ padding: '6px 12px', color: 'var(--text-muted)' }}>{r.actual_type}</td>
                            )}
                            {data.metrics && (
                              <td style={{ padding: '6px 12px',
                                color: r.actual === 'Attack' ? 'var(--threat)' : 'var(--benign)', fontWeight: 600 }}>
                                {r.actual}
                              </td>
                            )}
                            {data.metrics && (
                              <td style={{ padding: '6px 12px', textAlign: 'center',
                                color: r.correct ? 'var(--benign)' : 'var(--threat)', fontWeight: 700 }}>
                                {r.correct ? '✓' : '✕'}
                              </td>
                            )}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </>
        )}

      </div>
    </div>
  )
}
