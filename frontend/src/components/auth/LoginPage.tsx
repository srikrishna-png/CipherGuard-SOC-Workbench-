import React, { useState } from 'react';
import { Shield, Lock, Terminal, User, KeyRound, CheckCircle2, ArrowRight } from 'lucide-react';
import { CyberButton } from '../ui/CyberButton';
import { GlitchText } from '../ui/GlitchText';

export interface UserProfile {
  username: string;
  role: string;
  clearance: string;
  avatarInitials: string;
  badgeColor: string;
  loginTime: string;
}

interface LoginPageProps {
  onLoginSuccess: (user: UserProfile) => void;
  onCancel: () => void;
}

const DEMO_PROFILES: UserProfile[] = [
  {
    username: 'srikrishna-png',
    role: 'Lead SOC Architect & Security Director',
    clearance: 'OMNI-TOP-SECRET // LEVEL 5',
    avatarInitials: 'SK',
    badgeColor: 'border-emerald-500 text-emerald-400 bg-emerald-950/60',
    loginTime: ''
  },
  {
    username: 'triage_analyst_01',
    role: 'Tier-1 Security Triage Specialist',
    clearance: 'RESTRICTED // LEVEL 2',
    avatarInitials: 'TA',
    badgeColor: 'border-cyan-500 text-cyan-400 bg-cyan-950/60',
    loginTime: ''
  },
  {
    username: 'incident_responder',
    role: 'Tier-2 Incident Handler & Forensics Lead',
    clearance: 'SECRET // LEVEL 4',
    avatarInitials: 'IR',
    badgeColor: 'border-amber-500 text-amber-400 bg-amber-950/60',
    loginTime: ''
  }
];

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess, onCancel }) => {
  const [username, setUsername] = useState('srikrishna-png');
  const [passcode, setPasscode] = useState('••••••••••••');
  const [selectedClearance, setSelectedClearance] = useState('OMNI-TOP-SECRET // LEVEL 5');
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [authSuccess, setAuthSuccess] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) return;

    setIsAuthenticating(true);
    setTimeout(() => {
      setIsAuthenticating(false);
      setAuthSuccess(true);
      setTimeout(() => {
        const user: UserProfile = {
          username: username.trim(),
          role: username === 'srikrishna-png' ? 'Lead SOC Architect' : 'Cyber Security Analyst',
          clearance: selectedClearance,
          avatarInitials: username.slice(0, 2).toUpperCase(),
          badgeColor: 'border-emerald-500 text-emerald-400 bg-emerald-950/60',
          loginTime: new Date().toLocaleTimeString()
        };
        onLoginSuccess(user);
      }, 600);
    }, 700);
  };

  const handleSelectDemoProfile = (profile: UserProfile) => {
    setUsername(profile.username);
    setSelectedClearance(profile.clearance);
    setPasscode('••••••••••••');
  };

  return (
    <div className="relative min-h-screen bg-[#09090b] text-zinc-100 flex items-center justify-center p-4 pt-20">
      {/* Background Matrix Grid */}
      <div className="absolute inset-0 bg-grid-cyber pointer-events-none -z-10 [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)]" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/10 blur-[130px] rounded-full pointer-events-none -z-10" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyan-500/10 blur-[130px] rounded-full pointer-events-none -z-10" />

      <div className="w-full max-w-md bg-zinc-900/85 border border-zinc-800/90 rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.9)] overflow-hidden backdrop-blur-md">
        {/* Terminal Header */}
        <div className="px-5 py-3.5 bg-zinc-950/90 border-b border-zinc-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
            <span className="text-[11px] font-mono text-zinc-400 ml-2">
              auth_gate.exe --sec-level=5
            </span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60 text-emerald-400">
            TLS 1.3 ENCRYPTED
          </span>
        </div>

        <div className="p-6">
          {/* Brand Icon & Heading */}
          <div className="text-center mb-6">
            <div className="inline-flex p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 mb-3 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
              <Shield size={28} />
            </div>
            <h2 className="text-xl font-bold font-mono tracking-tight text-zinc-100">
              <GlitchText text="CipherGuard Access Portal" className="text-emerald-400" />
            </h2>
            <p className="text-xs text-zinc-400 font-mono mt-1">
              Authenticate operator credentials for defensive triage clearance
            </p>
          </div>

          {/* Quick Demo Profiles */}
          <div className="mb-5">
            <label className="block text-[11px] font-mono uppercase tracking-wider text-zinc-400 mb-2 font-bold">
              Select Operator Clearance Profile:
            </label>
            <div className="space-y-1.5">
              {DEMO_PROFILES.map((p) => {
                const isSelected = username === p.username;
                return (
                  <button
                    type="button"
                    key={p.username}
                    onClick={() => handleSelectDemoProfile(p)}
                    className={`w-full p-2.5 rounded-xl text-left border transition-all flex items-center justify-between ${
                      isSelected
                        ? 'bg-zinc-850 border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.15)]'
                        : 'bg-zinc-900/60 border-zinc-800/80 hover:bg-zinc-850 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center font-mono text-xs font-bold ${
                        isSelected ? 'bg-emerald-500 text-zinc-950' : 'bg-zinc-800 text-zinc-300'
                      }`}>
                        {p.avatarInitials}
                      </div>
                      <div>
                        <div className="text-xs font-mono font-bold text-zinc-200">{p.username}</div>
                        <div className="text-[10px] text-zinc-400">{p.role}</div>
                      </div>
                    </div>
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${p.badgeColor}`}>
                      {p.clearance.split('//')[0].trim()}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-zinc-300 mb-1 flex items-center gap-1.5">
                <User size={13} className="text-emerald-400" /> Operator ID / Callsign
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg bg-zinc-950 border border-zinc-800 text-sm font-mono text-zinc-100 focus:outline-none focus:border-emerald-500 transition-colors"
                placeholder="operator_callsign"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-zinc-300 mb-1 flex items-center gap-1.5">
                <KeyRound size={13} className="text-emerald-400" /> Security Token / Keyphrase
              </label>
              <input
                type="password"
                value={passcode}
                onChange={(e) => setPasscode(e.target.value)}
                required
                className="w-full px-3 py-2 rounded-lg bg-zinc-950 border border-zinc-800 text-sm font-mono text-zinc-100 focus:outline-none focus:border-emerald-500 transition-colors"
                placeholder="••••••••••••"
              />
            </div>

            <div className="pt-2">
              <CyberButton
                type="submit"
                variant="primary"
                size="md"
                disabled={isAuthenticating || authSuccess}
                className="w-full text-center"
              >
                {isAuthenticating ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-3.5 h-3.5 border-2 border-zinc-950 border-t-transparent rounded-full animate-spin" />
                    Verifying Credentials...
                  </span>
                ) : authSuccess ? (
                  <span className="flex items-center justify-center gap-2 text-zinc-950">
                    <CheckCircle2 size={16} /> Access Granted
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    <Lock size={15} /> Authenticate Session <ArrowRight size={15} />
                  </span>
                )}
              </CyberButton>
            </div>
          </form>

          {/* Quick cancel / back link */}
          <div className="mt-4 text-center">
            <button
              onClick={onCancel}
              className="text-xs font-mono text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              Continue in Guest Mode &rarr;
            </button>
          </div>
        </div>

        {/* Security Footer Notice */}
        <div className="p-3 bg-zinc-950/80 border-t border-zinc-800/80 text-center text-[10px] font-mono text-zinc-400">
          AUTHORIZED SOC PERSONNEL ONLY // COMPLIANT WITH NIST SP 800-61R2
        </div>
      </div>
    </div>
  );
};
