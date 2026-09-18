import React from 'react';
import { SeverityLevel } from '../../types';

interface SeverityMeterProps {
  score: number;
  verdict: SeverityLevel;
}

export const SeverityMeter: React.FC<SeverityMeterProps> = ({ score, verdict }) => {
  const getColor = () => {
    if (score >= 75) return '#ef4444'; // Red
    if (score >= 50) return '#f97316'; // Orange
    if (score >= 25) return '#f59e0b'; // Amber
    if (score > 0) return '#06b6d4';   // Cyan
    return '#10b981';                  // Green
  };

  const strokeColor = getColor();
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex items-center gap-4 bg-zinc-900/40 p-3 rounded-xl border border-zinc-800/80">
      <div className="relative w-20 h-20 flex items-center justify-center flex-shrink-0">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r={radius}
            className="stroke-zinc-800"
            strokeWidth="8"
            fill="transparent"
          />
          <circle
            cx="50"
            cy="50"
            r={radius}
            stroke={strokeColor}
            strokeWidth="8"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-xl font-mono font-bold leading-none text-zinc-100">{score}</span>
          <span className="text-[9px] font-mono uppercase text-zinc-400">/ 100</span>
        </div>
      </div>

      <div className="flex flex-col">
        <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider">Operational Risk</div>
        <div className="text-base font-mono font-bold tracking-tight" style={{ color: strokeColor }}>
          {verdict} THREAT
        </div>
        <div className="text-xs text-zinc-400 mt-0.5">
          {score >= 75 && 'Immediate containment and active blocking required.'}
          {score >= 50 && score < 75 && 'Suspicious indicators warrant deep host review.'}
          {score >= 25 && score < 50 && 'Elevated baseline deviation detected.'}
          {score < 25 && 'Normal baseline; no hostile signatures found.'}
        </div>
      </div>
    </div>
  );
};
