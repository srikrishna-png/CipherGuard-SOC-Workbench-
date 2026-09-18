import React, { useState, useEffect } from 'react';
import { 
  X, ShieldCheck, CheckCircle2, AlertOctagon, 
  RefreshCw, Database, Hash, Lock, Clock 
} from 'lucide-react';
import { AuditLedgerEntry, AuditVerificationResponse } from '../../types';
import { fetchAuditEntries, verifyAuditIntegrity } from '../../lib/api';

interface AuditLedgerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AuditLedgerModal: React.FC<AuditLedgerModalProps> = ({ isOpen, onClose }) => {
  const [entries, setEntries] = useState<AuditLedgerEntry[]>([]);
  const [verification, setVerification] = useState<AuditVerificationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

  const loadEntries = async () => {
    setIsLoading(true);
    try {
      const data = await fetchAuditEntries(30);
      setEntries(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadEntries();
      setVerification(null);
    }
  }, [isOpen]);

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const res = await verifyAuditIntegrity();
      setVerification(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIsVerifying(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/80 backdrop-blur-md"
        onClick={onClose}
      />

      {/* Modal Card */}
      <div className="relative w-full max-w-4xl max-h-[88vh] bg-[#0d0d10] border border-zinc-800 rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.8)] flex flex-col z-10 overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-emerald-950/70 border border-emerald-800/50 text-emerald-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="font-mono font-bold text-base text-zinc-100 flex items-center gap-2">
                Cryptographic Tamper-Evident Audit Ledger
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-zinc-800 text-cyan-400 border border-zinc-700 font-mono">
                  SHA-256 Chained
                </span>
              </div>
              <div className="text-xs text-zinc-400 font-mono mt-0.5">
                NIST SP 800-86 Forensic Chain of Custody &bull; SQLite: <code className="text-zinc-300">data/cyber_suite.db</code>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Verification Banner */}
        <div className="p-4 bg-zinc-950/70 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              onClick={handleVerify}
              disabled={isVerifying}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-mono font-bold text-xs transition-all shadow-[0_0_12px_rgba(16,185,129,0.25)] active:scale-95 disabled:opacity-50"
            >
              {isVerifying ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Recomputing Hashes...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Verify Audit Log Integrity</span>
                </>
              )}
            </button>

            <button
              onClick={loadEntries}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-zinc-800/80 hover:bg-zinc-700 text-zinc-300 font-mono text-xs border border-zinc-700/60 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>

          {verification && (
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-mono text-xs border ${
              verification.is_valid
                ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                : 'bg-red-950/60 text-red-400 border-red-800/60'
            }`}>
              {verification.is_valid ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <span>100% UNTAMPERED ({verification.total_records} RECORDS VERIFIED)</span>
                </>
              ) : (
                <>
                  <AlertOctagon className="w-4 h-4 text-red-400 flex-shrink-0" />
                  <span>TAMPERING DETECTED AT BLOCK ID: {verification.tampered_records.join(', ')}</span>
                </>
              )}
            </div>
          )}
        </div>

        {/* Ledger Table */}
        <div className="flex-1 overflow-y-auto p-4">
          {isLoading && entries.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-zinc-500">
              Loading cryptographic ledger records...
            </div>
          ) : entries.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-zinc-500">
              No analysis records found. Run tools in the workbench to generate audit events.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-zinc-800 text-zinc-400">
                    <th className="pb-2 font-semibold">ID</th>
                    <th className="pb-2 font-semibold">Timestamp</th>
                    <th className="pb-2 font-semibold">Tool</th>
                    <th className="pb-2 font-semibold">Verdict</th>
                    <th className="pb-2 font-semibold">Risk</th>
                    <th className="pb-2 font-semibold">Entry SHA-256 Hash</th>
                    <th className="pb-2 font-semibold">Chained Prev Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50">
                  {entries.map((entry) => (
                    <tr key={entry.id} className="hover:bg-zinc-900/40 transition-colors">
                      <td className="py-2.5 font-bold text-emerald-400">#{entry.id}</td>
                      <td className="py-2.5 text-zinc-400 whitespace-nowrap">{entry.timestamp.slice(11, 19)}</td>
                      <td className="py-2.5 text-zinc-200 font-semibold">{entry.tool_id}</td>
                      <td className="py-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          entry.verdict === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                          entry.verdict === 'MALICIOUS' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                          entry.verdict === 'SUSPICIOUS' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                          'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}>
                          {entry.verdict}
                        </span>
                      </td>
                      <td className="py-2.5 text-zinc-300">{entry.risk_score}</td>
                      <td className="py-2.5 text-cyan-300 font-mono text-[11px] truncate max-w-[140px]" title={entry.entry_hash}>
                        {entry.entry_hash.slice(0, 16)}...
                      </td>
                      <td className="py-2.5 text-zinc-500 font-mono text-[11px] truncate max-w-[140px]" title={entry.prev_hash}>
                        {entry.prev_hash.slice(0, 16)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-zinc-950/80 border-t border-zinc-800 text-[11px] font-mono text-zinc-500 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>Hash Formula: SHA256(ID + Timestamp + Tool + Actor + InputHash + Verdict + Risk + PrevHash)</span>
          </div>
          <button 
            onClick={onClose}
            className="px-3 py-1 rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
