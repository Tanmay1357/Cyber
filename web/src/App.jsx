import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'

// Code-split everything other than the landing page so the initial bundle is small.
const AlertsPage   = lazy(() => import('./pages/AlertsPage'))
const ExplainPage  = lazy(() => import('./pages/ExplainPage'))
const TrainPage    = lazy(() => import('./pages/TrainPage'))
const EvaluatePage = lazy(() => import('./pages/EvaluatePage'))
const ClassifyPage = lazy(() => import('./pages/ClassifyPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))

function PageFallback() {
  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      color: 'var(--text-faint)', fontSize: 13 }}>
      Loading…
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<PageFallback />}>
        <Routes>
          <Route path="/"          element={<Dashboard />} />
          <Route path="/alerts"    element={<AlertsPage />} />
          <Route path="/explain"   element={<ExplainPage />} />
          <Route path="/train"     element={<TrainPage />} />
          <Route path="/evaluate"  element={<EvaluatePage />} />
          <Route path="/classify"  element={<ClassifyPage />} />
          <Route path="/settings"  element={<SettingsPage />} />
          <Route path="*"          element={<Navigate to="/" />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  )
}
