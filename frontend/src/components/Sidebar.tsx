import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import type { CalculateResponse } from '../lib/types';

interface SearchHistoryItem {
  id: string;
  companyName: string;
  businessVertical: string;
  subVertical?: string;
  timestamp: string;
  results: CalculateResponse;
}

const STORAGE_KEY = 'atlas_search_history';
const MAX_HISTORY = 20;

export default function Sidebar() {
  const navigate = useNavigate();
  const [history, setHistory] = useState<SearchHistoryItem[]>([]);
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = () => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        setHistory(parsed);
      }
    } catch (e) {
      console.error('Failed to load search history:', e);
    }
  };

  const clearHistory = () => {
    localStorage.removeItem(STORAGE_KEY);
    setHistory([]);
  };

  const loadSearch = (item: SearchHistoryItem) => {
    navigate('/dashboard', {
      state: {
        results: item.results,
        companyName: item.companyName
      }
    });
    setIsOpen(false);
  };

  const deleteSearch = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const updated = history.filter(h => h.id !== id);
    setHistory(updated);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  };

  return (
    <>
      {/* Toggle Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed left-4 top-4 z-50 hacker-button text-sm font-hacker"
        aria-label="Toggle sidebar"
      >
        {isOpen ? '<' : '>'} History
      </button>

      {/* Sidebar */}
      <div
        className={`fixed left-0 top-0 h-full bg-gruvbox-dark border-r-2 border-gruvbox-green-bright z-40 transition-transform duration-300 shadow-lg ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        style={{ width: '320px' }}
      >
        <div className="p-4 h-full flex flex-col">
          {/* Header */}
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-gruvbox-green-bright glow-text font-hacker">
              {'>'} Search History
            </h2>
            <button
              onClick={() => setIsOpen(false)}
              className="text-gruvbox-gray hover:text-gruvbox-light font-mono"
            >
              ×
            </button>
          </div>

          {/* Clear Button */}
          {history.length > 0 && (
            <button
              onClick={clearHistory}
              className="mb-4 text-sm text-gruvbox-red hover:text-gruvbox-red-bright font-mono"
            >
              Clear All
            </button>
          )}

          {/* History List */}
          <div className="flex-1 overflow-y-auto">
            {history.length === 0 ? (
              <div className="text-gruvbox-gray text-sm font-mono text-center py-8">
                No search history yet.
                <br />
                Previous searches will appear here.
              </div>
            ) : (
              <div className="space-y-2">
                {history.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => loadSearch(item)}
                    className="terminal-card rounded p-3 cursor-pointer hover:border-gruvbox-green-bright hover:bg-gruvbox-bg0 transition-colors relative group border border-gruvbox-bg0"
                  >
                    <button
                      onClick={(e) => deleteSearch(item.id, e)}
                      className="absolute top-2 right-2 text-gruvbox-gray hover:text-gruvbox-red opacity-0 group-hover:opacity-100 transition-opacity text-xs"
                      aria-label="Delete"
                    >
                      ×
                    </button>
                    <div className="font-semibold text-gruvbox-green-bright font-mono text-sm mb-1">
                      {item.companyName}
                    </div>
                    <div className="text-xs text-gruvbox-gray font-mono">
                      {item.businessVertical}
                      {item.subVertical && ` / ${item.subVertical}`}
                    </div>
                    <div className="text-xs text-gruvbox-gray font-mono mt-1">
                      {new Date(item.timestamp).toLocaleString()}
                    </div>
                    <div className="text-xs text-gruvbox-blue font-mono mt-1">
                      {item.results.results.length} threat actor(s)
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="text-xs text-gruvbox-gray font-mono mt-4 pt-4 border-t border-gruvbox-bg0">
            {history.length} / {MAX_HISTORY} searches
          </div>
        </div>
      </div>

      {/* Overlay */}
      {isOpen && (
        <div
          onClick={() => setIsOpen(false)}
          className="fixed inset-0 bg-black bg-opacity-50 z-30"
        />
      )}
    </>
  );
}

// Utility function to save search to history
export const saveSearchToHistory = (
  companyName: string,
  businessVertical: string,
  subVertical: string | undefined,
  results: CalculateResponse
) => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    let history: SearchHistoryItem[] = stored ? JSON.parse(stored) : [];

    // Create new history item
    const newItem: SearchHistoryItem = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      companyName,
      businessVertical,
      subVertical,
      timestamp: new Date().toISOString(),
      results
    };

    // Remove duplicates (same company + industry)
    history = history.filter(
      h => !(h.companyName === companyName && 
             h.businessVertical === businessVertical && 
             h.subVertical === subVertical)
    );

    // Add to beginning
    history.unshift(newItem);

    // Limit to MAX_HISTORY
    history = history.slice(0, MAX_HISTORY);

    // Save to localStorage
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  } catch (e) {
    console.error('Failed to save search history:', e);
  }
};
