import React, { useState } from 'react';
import { 
  ShieldCheck, AlertTriangle, AlertOctagon, Info, 
  ExternalLink, Layers, Terminal, BookOpen, Clock, Hash, 
  CheckCircle2, Copy, Check, Download, Sparkles, ArrowRight, 
  Key, FileCode, RefreshCw, Image as ImageIcon, Eye
} from 'lucide-react';
import { FiveLayerAnalysisResult } from '../../types';
import { Badge } from '../ui/Badge';
import { CodeBlock } from '../ui/CodeBlock';
import { SeverityMeter } from '../ui/SeverityMeter';

interface FiveLayerResultCardProps {
  result: FiveLayerAnalysisResult | null;
  isLoading: boolean;
  onSelectToolById?: (toolId: string) => void;
  onLoadPayloadIntoInput?: (payload: string, targetMode?: 'generation' | 'analysis') => void;
}

export const FiveLayerResultCard: React.FC<FiveLayerResultCardProps> = ({
  result,
  isLoading,
  onSelectToolById,
  onLoadPayloadIntoInput
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey(null);
    }, 2000);
  };

  const handleDownloadDataUrl = (dataUrl: string, filename = 'stego_carrier_payload.png') => {
    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  if (isLoading) {
    return (
      <div className="h-full min-h-[400px] flex flex-col items-center justify-center bg-[#0c0c0f] rounded-xl border border-zinc-800/80 p-8 text-center">
        <div className="w-12 h-12 border-3 border-emerald-500 border-t-transparent rounded-full animate-spin mb-4" />
        <div className="font-mono text-sm font-bold text-zinc-200">Executing Deep Defensive Analysis...</div>
        <div className="text-xs text-zinc-500 font-mono mt-1">Inspecting byte patterns, evaluating RFC compliance &amp; calculating threat metrics</div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="h-full min-h-[400px] flex flex-col items-center justify-center bg-[#0c0c0f] rounded-xl border border-dashed border-zinc-800 p-8 text-center text-zinc-500">
        <div className="w-12 h-12 rounded-xl bg-zinc-900 flex items-center justify-center mb-3 text-zinc-600">
          <Layers className="w-6 h-6" />
        </div>
        <div className="font-mono text-sm font-semibold text-zinc-400">Workbench Awaiting Telemetry</div>
        <div className="text-xs text-zinc-600 max-w-sm mt-1">
          Select a cybersecurity tool from the left sidebar, toggle Generation or Analysis mode, and run analysis.
        </div>
      </div>
    );
  }

  const hasPayload = Boolean(result.generated_payload || result.extracted_secret);
  const isImagePayload = Boolean(result.generated_payload && result.generated_payload.startsWith('data:image/'));

  return (
    <div className="flex flex-col h-full bg-[#0c0c0f] rounded-xl border border-zinc-800/80 overflow-hidden shadow-xl space-y-4 p-4 lg:p-6 overflow-y-auto">
      {/* Top Meta Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2">
          <Badge level={result.verdict} />
          <span className="text-xs font-mono font-bold text-zinc-200">{result.tool_name}</span>
          {result.operation_mode && (['stego_detector', 'aes_gcm_suite', 'crypto_benchmark', 'rsa_signature_suite', 'hmac_authenticator'].includes(result.tool_id) || result.operation_mode === 'generation') && (
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
              result.operation_mode === 'generation' 
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/60' 
                : 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/60'
            }`}>
              {result.operation_mode === 'generation' ? '⚡ Generation Mode' : '🔍 Analysis Mode'}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 text-[11px] font-mono text-zinc-500">
          <span className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            {result.execution_time_ms} ms
          </span>
          {result.audit_hash && (
            <span className="flex items-center gap-1 text-emerald-400/90 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/50">
              <Hash className="w-3 h-3" />
              Ledger Sealed: {result.audit_hash.slice(0, 8)}...
            </span>
          )}
        </div>
      </div>

      {/* DEDICATED CRYPTOGRAPHIC OUTPUT & RECOVERED SECRET BUFFER */}
      {hasPayload && (
        <div className="bg-gradient-to-r from-emerald-950/40 via-zinc-900/80 to-cyan-950/40 border-2 border-emerald-500/40 rounded-xl p-4 shadow-[0_0_24px_rgba(16,185,129,0.12)] space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-zinc-800/80">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                <Key className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-mono font-bold text-zinc-100 uppercase tracking-wider">
                  Cryptographic Payload &amp; Output Buffer
                </h3>
                <p className="text-[11px] text-zinc-400 font-mono">
                  {result.operation_mode === 'generation' 
                    ? 'Synthesized cryptographic output ready for deployment or transmission.' 
                    : 'Carved plaintext secret recovered from container inspection.'}
                </p>
              </div>
            </div>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded bg-zinc-900 text-emerald-400 border border-emerald-800/50 font-semibold flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              Output Ready
            </span>
          </div>

          {/* If there is an extracted secret / plaintext message */}
          {result.extracted_secret && (
            <div className="bg-zinc-950/90 border border-emerald-500/30 rounded-lg p-3">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  {result.operation_mode === 'generation' ? 'Generated Payload / Bundle:' : 'Recovered Plaintext / Extracted Secret:'}
                </span>
                <button
                  onClick={() => handleCopy(result.extracted_secret!, 'secret')}
                  className="flex items-center gap-1.5 px-3 py-1 bg-emerald-500 hover:bg-emerald-400 text-zinc-950 text-xs font-mono font-bold rounded shadow-md transition-all active:scale-95"
                >
                  {copiedKey === 'secret' ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Copied! ✓</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Decoded Text</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="text-xs font-mono text-zinc-100 bg-[#09090c] p-2.5 rounded border border-zinc-800/80 overflow-x-auto whitespace-pre-wrap break-all select-all selection:bg-emerald-500 selection:text-black">
                {result.extracted_secret}
              </pre>
            </div>
          )}

          {/* If there is a generated Stego Image Container */}
          {isImagePayload && result.generated_payload && (
            <div className="bg-zinc-950/90 border border-cyan-500/30 rounded-lg p-3">
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                  <ImageIcon className="w-3.5 h-3.5" />
                  Synthesized Steganographic Carrier Image:
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleDownloadDataUrl(result.generated_payload!)}
                    className="flex items-center gap-1.5 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold rounded shadow transition-all active:scale-95"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Image (.png)</span>
                  </button>
                  <button
                    onClick={() => handleCopy(result.generated_payload!, 'dataurl')}
                    className="flex items-center gap-1.5 px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono rounded border border-zinc-700 transition-all active:scale-95"
                  >
                    {copiedKey === 'dataurl' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied! ✓</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Stego Data URL</span>
                      </>
                    )}
                  </button>
                  {onLoadPayloadIntoInput && (
                    <button
                      onClick={() => onLoadPayloadIntoInput(result.generated_payload!, 'analysis')}
                      className="flex items-center gap-1.5 px-3 py-1 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-400 text-xs font-mono rounded transition-all active:scale-95"
                      title="Send this generated stego image to input editor and switch to Analysis mode"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Load into Stego Decoder</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Image Preview Window */}
              <div className="flex flex-col sm:flex-row items-center gap-4 bg-[#09090c] p-3 rounded border border-zinc-800/80">
                <div className="p-2 bg-[radial-gradient(#27272a_1px,transparent_1px)] [background-size:10px_10px] bg-zinc-950 rounded-lg border border-zinc-800 flex items-center justify-center max-h-[140px] max-w-[200px] overflow-hidden">
                  <img
                    src={result.generated_payload}
                    alt="Synthesized Stego Carrier"
                    className="max-h-[120px] w-auto object-contain rounded"
                  />
                </div>
                <div className="text-xs font-mono text-zinc-400 space-y-1 flex-1">
                  <div className="text-zinc-200 font-bold">PNG Carrier with Appended Payload</div>
                  <div>Carrier contains secret bytes injected past official <span className="text-cyan-400">IEND</span> marker.</div>
                  <div className="text-[11px] text-zinc-500">
                    Payload size: ~{Math.round((result.generated_payload.length * 3) / 4).toLocaleString()} bytes (Base64 URL)
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* If there is a separate generated text payload (e.g. Ciphertext, Hash code) that wasn't already displayed as extracted_secret */}
          {!isImagePayload && result.generated_payload && result.generated_payload !== result.extracted_secret && (
            <div className="bg-zinc-950/90 border border-zinc-800 rounded-lg p-3">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5" />
                  Generated Output Payload:
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy(result.generated_payload!, 'payload')}
                    className="flex items-center gap-1.5 px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono rounded border border-zinc-700 transition-all active:scale-95"
                  >
                    {copiedKey === 'payload' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied! ✓</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Output Payload</span>
                      </>
                    )}
                  </button>
                  {onLoadPayloadIntoInput && (
                    <button
                      onClick={() => onLoadPayloadIntoInput(result.generated_payload!, 'analysis')}
                      className="flex items-center gap-1 px-2.5 py-1 bg-zinc-900 hover:bg-zinc-800 text-cyan-400 border border-zinc-700 text-xs font-mono rounded transition-colors"
                      title="Load into input editor"
                    >
                      <span>Load into Input</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>
              <pre className="text-xs font-mono text-zinc-300 bg-[#09090c] p-2.5 rounded border border-zinc-800/80 overflow-x-auto whitespace-pre-wrap break-all select-all">
                {result.generated_payload}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* LAYER 1: Executive Verdict & Severity */}
      <div className="bg-zinc-900/40 border border-zinc-800/90 rounded-xl p-4">
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider mb-3">
          <ShieldCheck className="w-4 h-4" />
          Layer 1: Executive Verdict &amp; Severity
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          <div className="md:col-span-1">
            <SeverityMeter score={result.risk_score} verdict={result.verdict} />
          </div>
          <div className="md:col-span-2">
            <p className="text-sm text-zinc-200 leading-relaxed font-sans">
              {result.summary}
            </p>
            {result.attack_objective && (
              <div className="mt-2.5 inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-800/80 border border-zinc-700/60 text-xs font-mono text-cyan-300">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>Objective:</span>
                <span className="font-semibold text-zinc-100">{result.attack_objective}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* LAYER 2: Technical Evidence Breakdown */}
      <div className="bg-zinc-900/40 border border-zinc-800/90 rounded-xl p-4">
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider mb-3">
          <Layers className="w-4 h-4" />
          Layer 2: Technical Evidence Breakdown
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-zinc-800 text-zinc-400">
                <th className="pb-2 font-semibold">Inspection Indicator</th>
                <th className="pb-2 font-semibold">Evaluated Value / Result</th>
                <th className="pb-2 font-semibold text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {result.technical_evidence.map((item, idx) => {
                const statusBadge = {
                  pass: <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">PASS</span>,
                  warning: <span className="px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/60">WARN</span>,
                  fail: <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-800/60">FAIL</span>,
                  info: <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">INFO</span>,
                }[item.status];

                return (
                  <tr key={idx} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="py-2.5 font-medium text-zinc-300 pr-3 align-top whitespace-nowrap">
                      {item.label}
                    </td>
                    <td className="py-2.5 text-zinc-400 pr-3 align-top">
                      <div className="text-zinc-200">{item.value}</div>
                      {item.description && (
                        <div className="text-[11px] text-zinc-500 mt-0.5 font-sans leading-normal">
                          {item.description}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 text-right align-top whitespace-nowrap">
                      {statusBadge}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* LAYER 3: Threat Impact ("Why It Matters") */}
      <div className="bg-zinc-900/40 border border-zinc-800/90 rounded-xl p-4">
        <div className="flex items-center gap-2 text-xs font-mono text-amber-400 font-bold uppercase tracking-wider mb-2">
          <AlertTriangle className="w-4 h-4" />
          Layer 3: Threat Impact ("Why It Matters")
        </div>
        <p className="text-xs text-zinc-300 leading-relaxed font-sans">
          {result.threat_impact}
        </p>
      </div>

      {/* LAYER 4: Actionable Remediation Playbook */}
      <div className="bg-zinc-900/40 border border-zinc-800/90 rounded-xl p-4">
        <div className="flex items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider">
            <Terminal className="w-4 h-4" />
            Layer 4: Actionable Remediation Playbook
          </div>
          <span className="text-[10px] font-mono text-zinc-500">1-Click Copy Ready</span>
        </div>

        {result.remediation_playbook.length === 0 ? (
          <div className="text-xs font-mono text-zinc-500 py-2">
            No emergency remediation required. System or artifact is within acceptable baseline parameters.
          </div>
        ) : (
          <div className="space-y-3">
            {result.remediation_playbook.map((cmd, idx) => (
              <div key={idx}>
                <CodeBlock code={cmd.command} title={cmd.title} platform={cmd.platform} />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* LAYER 5: Educational Deep Dive & Standards */}
      <div className="bg-zinc-900/40 border border-zinc-800/90 rounded-xl p-4">
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider mb-3">
          <BookOpen className="w-4 h-4" />
          Layer 5: Educational Deep Dive &amp; Standards
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {result.standards_and_references.map((std, idx) => (
            <div key={idx} className="p-3 rounded-lg bg-zinc-950/80 border border-zinc-800/80 hover:border-zinc-700 transition-colors">
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-cyan-400 border border-zinc-700">
                  {std.standard}
                </span>
                {std.url && (
                  <a
                    href={std.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] font-mono text-zinc-400 hover:text-emerald-400 flex items-center gap-1 transition-colors"
                  >
                    Reference <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
              <div className="text-xs font-mono font-bold text-zinc-200 mt-1">
                {std.reference_id}: {std.title}
              </div>
              <p className="text-xs text-zinc-400 mt-1 font-sans leading-normal">
                {std.summary}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
