import { useState } from 'react';
import type { ActorResult } from '../lib/types';

interface ResultsCardProps {
  result: ActorResult;
}

export default function ResultsCard({ result }: ResultsCardProps) {
  const [showTechniques, setShowTechniques] = useState(false);
  const [showExplanations, setShowExplanations] = useState(false);

  const confidenceColor = {
    High: 'bg-gruvbox-green text-gruvbox-darker border-gruvbox-green-bright',
    Medium: 'bg-gruvbox-orange text-gruvbox-light border-gruvbox-orange',
    Low: 'bg-gruvbox-red text-gruvbox-light border-gruvbox-red',
  }[result.confidence] || 'bg-gruvbox-gray text-gruvbox-light border-gruvbox-gray';

  return (
    <div className="terminal-card rounded-lg p-6 mb-4">
      <div className="flex justify-between items-start mb-4">
        <div>
          <h2 className="text-2xl font-bold text-gruvbox-green-bright glow-text font-hacker">
            {'>'} {result.threat_actor_group.name}
          </h2>
          {result.threat_actor_group.aliases.length > 0 && (
            <p className="text-sm text-gruvbox-gray mt-1 font-mono">
              Also known as: {result.threat_actor_group.aliases.join(', ')}
            </p>
          )}
          {result.threat_actor_group.mitre_id && (
            <p className="text-sm text-gruvbox-blue font-mono mt-1">
              MITRE ID: {result.threat_actor_group.mitre_id}
            </p>
          )}
        </div>
        <div className="text-right">
          <span className={`px-3 py-1 rounded border-2 text-sm font-semibold font-hacker ${confidenceColor} shadow-glow-green-sm`}>
            {result.confidence} Confidence
          </span>
          <p className="text-sm text-gruvbox-gray mt-2 font-mono">Score: {result.weighted_score.toFixed(2)}</p>
        </div>
      </div>

      <div className="mt-4">
        <button
          className="text-gruvbox-green-bright hover:text-gruvbox-green font-semibold font-hacker transition-colors"
          onClick={() => setShowTechniques(!showTechniques)}
        >
          {showTechniques ? '▼' : '▶'} Top Techniques ({result.top_techniques.length})
        </button>
        {showTechniques && (
          <div className="mt-2 space-y-2">
            {result.top_techniques.map((tech, idx) => (
              <div key={idx} className="bg-gruvbox-dark border border-gruvbox-green p-3 rounded font-mono">
                <div className="flex justify-between">
                  <div>
                    <span className="font-semibold text-gruvbox-green-bright">{tech.technique.technique_id}</span>
                    <span className="ml-2 font-semibold text-gruvbox-light">{tech.technique.name}</span>
                  </div>
                  <div className="text-sm text-gruvbox-gray">
                    Score: {tech.score.toFixed(2)} | Evidence: {tech.evidence_count}
                  </div>
                </div>
                <div className="text-sm text-gruvbox-blue mt-1">
                  Tactic: {tech.technique.tactic}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {result.explanations.length > 0 && (
        <div className="mt-4">
          <button
            className="text-gruvbox-green-bright hover:text-gruvbox-green font-semibold font-hacker transition-colors"
            onClick={() => setShowExplanations(!showExplanations)}
          >
            {showExplanations ? '▼' : '▶'} Why This Result ({result.explanations.length} sources)
          </button>
          {showExplanations && (
            <div className="mt-2 space-y-3">
              {result.explanations.map((exp, idx) => (
                <div key={idx} className="bg-gruvbox-dark border-l-4 border-gruvbox-blue p-3 rounded">
                  <a
                    href={exp.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-semibold text-gruvbox-blue-bright hover:text-gruvbox-blue hover:underline font-mono"
                  >
                    {exp.source_title}
                  </a>
                  <p className="text-sm text-gruvbox-gray mt-1 font-mono">
                    Date: {new Date(exp.source_date).toLocaleDateString()}
                  </p>
                  {exp.excerpt && (
                    <p className="text-sm text-gruvbox-light mt-2 italic font-mono">"{exp.excerpt}"</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
