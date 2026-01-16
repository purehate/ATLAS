import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { calculateThreats, getIndustries, searchCompanies } from '../lib/api';
import type { IndustryInfo } from '../lib/types';
import type { CompanySearchResult } from '../lib/api';
import { saveSearchToHistory } from './Sidebar';
import Sidebar from './Sidebar';
import ExploitDBSidebar from './ExploitDBSidebar';

export default function Calculator() {
  const navigate = useNavigate();
  const [companyName, setCompanyName] = useState('');
  const [businessVertical, setBusinessVertical] = useState('');
  const [subVertical, setSubVertical] = useState('');
  const [industries, setIndustries] = useState<IndustryInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Company autocomplete state
  const [companySuggestions, setCompanySuggestions] = useState<CompanySearchResult[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [searchingCompanies, setSearchingCompanies] = useState(false);
  const companyInputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);

  // Load industries on mount
  useEffect(() => {
    getIndustries()
      .then((data) => {
        console.log('Loaded industries:', data.length);
        setIndustries(data);
      })
      .catch((err) => {
        console.error('Failed to load industries:', err);
        setError('Failed to load industries. Please check if the backend is running.');
      });
  }, []);

  // Company search with debounce
  useEffect(() => {
    if (companyName.length < 2) {
      setCompanySuggestions([]);
      setShowSuggestions(false);
      return;
    }

    const timeoutId = setTimeout(async () => {
      setSearchingCompanies(true);
      try {
        const results = await searchCompanies(companyName, 10);
        setCompanySuggestions(results.companies);
        setShowSuggestions(results.companies.length > 0);
      } catch (err) {
        console.error('Company search failed:', err);
        setCompanySuggestions([]);
        setShowSuggestions(false);
      } finally {
        setSearchingCompanies(false);
      }
    }, 300); // 300ms debounce

    return () => clearTimeout(timeoutId);
  }, [companyName]);

  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        suggestionsRef.current &&
        !suggestionsRef.current.contains(event.target as Node) &&
        companyInputRef.current &&
        !companyInputRef.current.contains(event.target as Node)
      ) {
        setShowSuggestions(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await calculateThreats({
        company_name: companyName,
        business_vertical: businessVertical,
        sub_vertical: subVertical || undefined,
      });
      
      // Save to history
      saveSearchToHistory(companyName, businessVertical, subVertical, response);
      
      // Navigate to dashboard with results
      navigate('/dashboard', {
        state: {
          results: response,
          companyName: companyName,
          businessVertical: businessVertical,
          subVertical: subVertical
        }
      });
    } catch (err: any) {
      setError(err.response?.data?.detail || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  // Get unique verticals from industries
  const verticals = Array.from(
    new Set(industries.filter((i) => !i.parent_id).map((i) => i.name))
  );

  // Get sub-verticals for selected vertical
  const subVerticals = industries.filter(
    (i) => i.parent_id && industries.find((p) => p.id === i.parent_id)?.name === businessVertical
  );

  return (
    <>
      <Sidebar />
      <ExploitDBSidebar />
      <div className="max-w-4xl mx-auto p-6 relative z-10">
      <h1 className="text-4xl font-bold mb-8 glow-text text-gruvbox-green-bright font-hacker tracking-wide">
        {'>'} ATLAS
      </h1>
      <p className="text-gruvbox-gray text-sm font-mono mb-6">
        Adversary Technique & Landscape Analysis by Sector
      </p>
      
      <form onSubmit={handleSubmit} className="terminal-card rounded px-8 pt-6 pb-8 mb-6">
        <div className="mb-4 relative">
          <label className="block text-gruvbox-green-bright text-sm font-bold mb-2 font-hacker" htmlFor="company">
            {'>'} Company Name
          </label>
          <div className="relative">
            <input
              ref={companyInputRef}
              className="terminal-input rounded w-full py-2 px-3 leading-tight font-mono"
              id="company"
              type="text"
              placeholder="Start typing company name..."
              value={companyName}
              onChange={(e) => {
                setCompanyName(e.target.value);
                setShowSuggestions(true);
              }}
              onFocus={() => {
                if (companySuggestions.length > 0) {
                  setShowSuggestions(true);
                }
              }}
              required
            />
            {searchingCompanies && (
              <div className="absolute right-3 top-2 text-gruvbox-green-bright text-xs font-mono">
                Searching...
              </div>
            )}
            
            {/* Autocomplete dropdown */}
            {showSuggestions && companySuggestions.length > 0 && (
              <div
                ref={suggestionsRef}
                className="absolute z-50 w-full mt-1 bg-gruvbox-dark border border-gruvbox-green-bright rounded shadow-lg max-h-60 overflow-y-auto"
              >
                {companySuggestions.map((company, index) => (
                  <div
                    key={index}
                    className="px-4 py-2 hover:bg-gruvbox-bg0 cursor-pointer border-b border-gruvbox-bg0 last:border-b-0"
                    onClick={() => {
                      setCompanyName(company.name);
                      setShowSuggestions(false);
                    }}
                  >
                    <div className="text-gruvbox-green-bright font-mono font-semibold">
                      {company.name}
                    </div>
                    {company.jurisdiction && (
                      <div className="text-gruvbox-gray text-xs font-mono mt-1">
                        {company.jurisdiction.toUpperCase()}
                        {company.company_number && ` • #${company.company_number}`}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
            
            {showSuggestions && companySuggestions.length === 0 && companyName.length >= 2 && !searchingCompanies && (
              <div className="absolute z-50 w-full mt-1 bg-gruvbox-dark border border-gruvbox-gray rounded shadow-lg px-4 py-2">
                <div className="text-gruvbox-gray text-sm font-mono">
                  No companies found. You can still proceed with your entry.
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="mb-4">
          <label className="block text-gruvbox-green-bright text-sm font-bold mb-2 font-hacker" htmlFor="vertical">
            {'>'} Business Vertical
          </label>
          <select
            className="terminal-input rounded w-full py-2 px-3 leading-tight font-mono"
            id="vertical"
            value={businessVertical}
            onChange={(e) => {
              setBusinessVertical(e.target.value);
              setSubVertical(''); // Reset sub-vertical when vertical changes
            }}
            required
          >
            <option value="" className="bg-gruvbox-dark text-gruvbox-light">Select a vertical...</option>
            {verticals.map((v) => (
              <option key={v} value={v} className="bg-gruvbox-dark text-gruvbox-light">
                {v}
              </option>
            ))}
          </select>
        </div>

        {subVerticals.length > 0 && (
          <div className="mb-4">
              <label className="block text-gruvbox-green-bright text-sm font-bold mb-2 font-hacker" htmlFor="subvertical">
                {'>'} Sub-Vertical (Optional)
              </label>
            <select
              className="terminal-input rounded w-full py-2 px-3 leading-tight font-mono"
              id="subvertical"
              value={subVertical}
              onChange={(e) => setSubVertical(e.target.value)}
            >
              <option value="" className="bg-gruvbox-dark text-gruvbox-light">None</option>
              {subVerticals.map((sv) => (
                <option key={sv.id} value={sv.name} className="bg-gruvbox-dark text-gruvbox-light">
                  {sv.name}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="flex items-center justify-between">
          <button
            className="hacker-button disabled:opacity-50 disabled:cursor-not-allowed"
            type="submit"
            disabled={loading}
          >
            {loading ? '> Calculating...' : '> Calculate Threats'}
          </button>
        </div>
      </form>

      {error && (
        <div className="terminal-card border-gruvbox-red rounded px-4 py-3 mb-6">
          <div className="text-gruvbox-red font-hacker">
            <span className="text-gruvbox-red">[ERROR]</span> {error}
          </div>
        </div>
      )}
      </div>
    </>
  );
}
