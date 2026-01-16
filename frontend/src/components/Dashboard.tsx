import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import type { CalculateResponse, BreachDetection } from '../lib/types';
import ResultsCard from './ResultsCard';
import Sidebar from './Sidebar';
import ExploitDBSidebar from './ExploitDBSidebar';
import { saveSearchToHistory } from './Sidebar';

export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const [results, setResults] = useState<CalculateResponse | null>(null);
  const [breachDetection, setBreachDetection] = useState<BreachDetection | null>(null);
  const [companyName, setCompanyName] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Get data from location state
    const state = location.state as { 
      results?: CalculateResponse; 
      companyName?: string;
      businessVertical?: string;
      subVertical?: string;
    } | null;
    
    if (state?.results) {
      setResults(state.results);
      setCompanyName(state.companyName || '');
      
      // Extract breach detection from metadata
      if (state.results.metadata?.breach_detection) {
        setBreachDetection(state.results.metadata.breach_detection as BreachDetection);
      }
      
      // Save to history if not already saved
      const companyName = state.companyName;
      const businessVertical = state.businessVertical;
      const subVertical = state.subVertical;
      
      if (companyName && businessVertical) {
        saveSearchToHistory(
          companyName,
          businessVertical,
          subVertical,
          state.results
        );
      }
    } else {
      // If no data, redirect back to calculator
      navigate('/');
    }
    
    setLoading(false);
  }, [location, navigate]);

  const getBreachStatusColor = (status: string) => {
    switch (status) {
      case 'high':
        return 'bg-gruvbox-bg0 border-gruvbox-yellow text-gruvbox-light';
      case 'medium':
        return 'bg-gruvbox-bg0 border-gruvbox-orange text-gruvbox-light';
      default:
        return 'bg-gruvbox-bg0 border-gruvbox-gray text-gruvbox-light';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gruvbox-dark text-gruvbox-light font-hacker flex items-center justify-center">
        <div className="text-gruvbox-green-bright text-xl font-mono">Loading...</div>
      </div>
    );
  }

  if (!results) {
    return (
      <div className="min-h-screen bg-gruvbox-dark text-gruvbox-light font-hacker flex items-center justify-center">
        <div className="text-center">
          <div className="text-gruvbox-red text-xl font-mono mb-4">No data available</div>
          <button
            onClick={() => navigate('/')}
            className="hacker-button"
          >
            {'>'} Back to Calculator
          </button>
        </div>
      </div>
    );
  }

  return (
    <>
      <Sidebar />
      <ExploitDBSidebar />
      <div className="min-h-screen bg-gruvbox-dark text-gruvbox-light font-hacker relative overflow-hidden">
      {/* Grid background */}
      <div className="fixed inset-0 opacity-5 pointer-events-none"
           style={{
             backgroundImage: `
               linear-gradient(rgba(184, 187, 38, 0.1) 1px, transparent 1px),
               linear-gradient(90deg, rgba(184, 187, 38, 0.1) 1px, transparent 1px)
             `,
             backgroundSize: '50px 50px'
           }}
      />
      
      <div className="max-w-7xl mx-auto p-6 relative z-10">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-4">
            <h1 className="text-4xl font-bold glow-text text-gruvbox-green-bright font-hacker tracking-wide">
              {'>'} ATLAS Dashboard
            </h1>
            <button
              onClick={() => navigate('/')}
              className="hacker-button text-sm"
            >
              {'<'} New Analysis
            </button>
          </div>
          {companyName && (
            <p className="text-gruvbox-gray text-sm font-mono">
              Analysis for: <span className="text-gruvbox-green-bright">{companyName}</span>
            </p>
          )}
        </div>

        {/* Public Breach Reports - Supplementary Information */}
        {breachDetection && (
          <div className={`terminal-card rounded px-6 py-4 mb-6 border ${getBreachStatusColor(breachDetection.status)}`}>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <h2 className="text-lg font-bold mb-2 font-hacker text-gruvbox-green-bright">
                  {'>'} Public Breach Reports (Additional Context)
                </h2>
                <p className="text-xs text-gruvbox-gray font-mono mb-3">
                  Public articles and reports mentioning {companyName} and security incidents from our data sources
                </p>
                
                {breachDetection.articles && breachDetection.articles.length > 0 ? (
                  <div className="mt-3">
                    <div className="text-xs text-gruvbox-gray font-mono mb-3">
                      Found {breachDetection.article_count} article(s)
                    </div>
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {breachDetection.articles.slice(0, 5).map((article, idx) => (
                        <div key={idx} className="bg-gruvbox-bg0 rounded p-2 text-xs border border-gruvbox-bg0 hover:border-gruvbox-green-bright transition-colors">
                          <a
                            href={article.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-semibold text-gruvbox-blue-bright hover:text-gruvbox-blue hover:underline block mb-1"
                          >
                            {article.title}
                          </a>
                          <div className="text-xs opacity-75 font-mono mb-1">
                            {article.source} • {new Date(article.date).toLocaleDateString()}
                          </div>
                          {article.excerpt && (
                            <div className="mt-1 opacity-80 italic text-xs font-mono line-clamp-2">
                              {article.excerpt}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                    {breachDetection.articles.length > 5 && (
                      <div className="text-xs text-gruvbox-gray font-mono mt-2">
                        ... and {breachDetection.articles.length - 5} more article(s)
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-sm text-gruvbox-gray font-mono mt-2">
                    No public breach reports found in our data sources.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Threat Actors Section */}
        <div className="mb-6">
          <h2 className="text-2xl font-bold mb-4 glow-text text-gruvbox-green-bright font-hacker">
            {'>'} Top Threat Actors
          </h2>
          {results.results.length === 0 ? (
            <div className="terminal-card rounded px-6 py-8 text-center">
              <p className="text-gruvbox-gray font-mono">
                No threat actors found for this industry.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {results.results.map((actorResult, index) => (
                <ResultsCard key={index} result={actorResult} />
              ))}
            </div>
          )}
        </div>

        {/* Metadata Section */}
        {results.metadata && (
          <div className="terminal-card rounded px-6 py-4 mt-6">
            <h3 className="text-lg font-bold mb-2 font-hacker text-gruvbox-green-bright">
              {'>'} Analysis Metadata
            </h3>
            <div className="text-sm font-mono text-gruvbox-gray">
              <div>Request ID: {results.request_id}</div>
              {results.metadata.calculated_at && (
                <div>Calculated: {results.metadata.calculated_at}</div>
              )}
              {results.metadata.message && (
                <div className="mt-2 text-gruvbox-yellow">{results.metadata.message}</div>
              )}
            </div>
          </div>
        )}
      </div>
      </div>
    </>
  );
}
