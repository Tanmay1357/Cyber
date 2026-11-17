import { useState } from 'react'
import http from '../api/http'

export default function AlertExplanation({ alert, onFeedback }) {
  const [submitted, setSubmitted] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  if (!alert) return null

  async function handleFeedback(label) {
    setSubmitting(true)
    setError(null)
    try {
      await http.post('/feedback', { alert_id: alert.id, label })
      setSubmitted(true)
      onFeedback?.(label)
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to save feedback.')
    } finally {
      setSubmitting(false)
    }
  }

  const explanations = Array.isArray(alert.explanation) ? alert.explanation : []

  return (
    <div style={{ borderTop: '1px solid var(--border)', padding: '12px 22px' }}>
      {explanations.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <span className="label">Explanation</span>
          <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
            {explanations.map((line, i) => (
              <li key={i} style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7 }}>{line}</li>
            ))}
          </ul>
        </div>
      )}

      {submitted ? (
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '4px 12px', borderRadius: 6,
          background: 'var(--benign-light)', color: 'var(--benign)',
          border: '1px solid #bbf7d0', fontSize: 11, fontWeight: 600,
        }}>
          ✓ Feedback saved
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="label" style={{ marginRight: 4 }}>Feedback:</span>
          <button
            onClick={() => handleFeedback('true_positive')}
            disabled={submitting}
            style={{
              padding: '3px 10px', fontSize: 10, fontWeight: 600, cursor: 'pointer',
              border: '1px solid var(--threat-border)', borderRadius: 5,
              background: 'var(--threat-light)', color: 'var(--threat)',
              opacity: submitting ? 0.6 : 1,
            }}
          >
            ✓ True Positive
          </button>
          <button
            onClick={() => handleFeedback('false_positive')}
            disabled={submitting}
            style={{
              padding: '3px 10px', fontSize: 10, fontWeight: 600, cursor: 'pointer',
              border: '1px solid var(--border)', borderRadius: 5,
              background: 'var(--surface)', color: 'var(--text-muted)',
              opacity: submitting ? 0.6 : 1,
            }}
          >
            ✗ False Positive
          </button>
          {error && <span style={{ fontSize: 10, color: 'var(--threat)' }}>{error}</span>}
        </div>
      )}
    </div>
  )
}
