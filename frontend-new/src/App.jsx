import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Shell }        from './components/layout/Shell';
import { Upload }       from './pages/Upload';
import { LiveAnalysis } from './pages/LiveAnalysis';
import { CaseDetail }   from './pages/CaseDetail';

/*
 * Routing:
 *   /               → Upload / Analyze (landing page)
 *   /live/:caseId   → Live analysis progress
 *   /case/:caseId   → Case detail / report
 * No Cases list page — navigated to case detail directly from live analysis.
 */
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Shell />}>
          <Route index                element={<Upload />} />
          <Route path="live/:caseId"  element={<LiveAnalysis />} />
          <Route path="case/:caseId"  element={<CaseDetail />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
