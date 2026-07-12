import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../api/ws', () => ({
  createWs: vi.fn(() => ({ close: vi.fn() })),
}))

import { useAlerts } from '../useAlerts'
import { createWs } from '../../api/ws'

describe('useAlerts', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('starts with empty alerts and no selection', () => {
    const { result } = renderHook(() => useAlerts())
    expect(result.current.alerts).toEqual([])
    expect(result.current.selectedId).toBeNull()
  })

  it('prepends new flow events to alerts', () => {
    let capturedHandler
    createWs.mockImplementation((_, handler) => {
      capturedHandler = handler
      return { close: vi.fn() }
    })
    const { result } = renderHook(() => useAlerts())
    act(() => capturedHandler({ kind: 'flow', id: 'abc', is_attack: true }))
    expect(result.current.alerts[0].id).toBe('abc')
  })

  it('caps alerts at 200', () => {
    let capturedHandler
    createWs.mockImplementation((_, handler) => {
      capturedHandler = handler
      return { close: vi.fn() }
    })
    const { result } = renderHook(() => useAlerts())
    act(() => {
      for (let i = 0; i < 250; i++) {
        capturedHandler({ kind: 'flow', id: String(i), is_attack: false })
      }
    })
    expect(result.current.alerts.length).toBe(200)
  })

  it('selectAlert sets selectedId', () => {
    const { result } = renderHook(() => useAlerts())
    act(() => result.current.selectAlert('xyz'))
    expect(result.current.selectedId).toBe('xyz')
  })
})
