import React, { useState, useEffect, useRef } from 'react';
import { 
  Bot, Send, X, Key, Sparkles, Terminal, Copy, Check, 
  ExternalLink, ArrowRight, Shield, AlertCircle
} from 'lucide-react';
import { askAssistantChat, ChatMessagePayload } from '../../lib/api';
import { SUITES_CATALOG } from '../../data/toolsRegistry';
import { ToolMetadata } from '../../types';

interface AIAssistantModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTool: (tool: ToolMetadata) => void;
  currentTool?: ToolMetadata;
}

interface DisplayMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  suggestedTools?: string[];
}

const PROMPT_CHIPS = [
  "How to detect jittered C2 beaconing?",
  "Explain Shannon Entropy thresholds",
  "How to generate YARA rules?",
  "Which tool parses out-of-order logs?",
  "How to calculate subnet routes?",
  "Explain the SHA-256 Audit Ledger"
];

// Helper to find tool IDs mentioned in markdown text
function findMentionedTools(text: string): string[] {
  const allToolIds = SUITES_CATALOG.flatMap(s => s.tools.map(t => t.id));
  const found: string[] = [];
  for (const tid of allToolIds) {
    if (text.includes(`\`${tid}\``) || text.includes(`(${tid})`) || text.includes(` ${tid} `)) {
      if (!found.includes(tid)) found.push(tid);
    }
  }
  return found;
}

export const AIAssistantModal: React.FC<AIAssistantModalProps> = ({
  isOpen,
  onClose,
  onSelectTool,
  currentTool
}) => {
  const [messages, setMessages] = useState<DisplayMessage[]>([
    {
      id: 'init',
      role: 'assistant',
      content: "👋 Greetings! I am **A.E.G.I.S.**, your defensive cybersecurity AI copilot.\n\nI can help you explore **all 80 tools across our 8 suites**, explain detection algorithms (such as Shannon entropy and beaconing variance), generate mitigation playbooks, or guide your forensic triage. How can I assist you today?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      suggestedTools: []
    }
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showKeyConfig, setShowKeyConfig] = useState(false);
  const [geminiKey, setGeminiKey] = useState(() => localStorage.getItem('CIPHERGUARD_GEMINI_KEY') || '');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [isOpen]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  const handleSaveKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (geminiKey.trim()) {
      localStorage.setItem('CIPHERGUARD_GEMINI_KEY', geminiKey.trim());
    } else {
      localStorage.removeItem('CIPHERGUARD_GEMINI_KEY');
    }
    setShowKeyConfig(false);
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend || inputQuery).trim();
    if (!query || isLoading) return;

    const userMsg: DisplayMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    setInputQuery('');
    setIsLoading(true);

    try {
      const payloadMessages: ChatMessagePayload[] = messages
        .concat(userMsg)
        .map(m => ({ role: m.role, content: m.content }));

      const res = await askAssistantChat(
        payloadMessages,
        currentTool?.id,
        geminiKey.trim() || undefined
      );

      const mentioned = findMentionedTools(res.reply);

      const assistantMsg: DisplayMessage = {
        id: `asst-${Date.now()}`,
        role: 'assistant',
        content: res.reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestedTools: mentioned
      };

      setMessages(prev => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: DisplayMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `⚠️ Error contacting assistant: ${err.message || 'Network error'}. Please check your connection or backend server.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleLaunchToolById = (toolId: string) => {
    const all = SUITES_CATALOG.flatMap(s => s.tools);
    const found = all.find(t => t.id === toolId);
    if (found) {
      onSelectTool(found);
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 md:p-6">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/80 backdrop-blur-md transition-opacity"
        onClick={onClose}
      />

      {/* Main Chat Container */}
      <div className="relative w-full max-w-3xl h-[85vh] bg-[#0c0c0f] border border-zinc-700/80 rounded-2xl shadow-[0_25px_70px_rgba(0,0,0,0.95)] overflow-hidden z-10 flex flex-col">
        {/* Header */}
        <div className="px-5 py-3.5 bg-zinc-950 border-b border-zinc-800 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Bot size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold font-mono text-zinc-100">
                  A.E.G.I.S. SOC AI Copilot
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-800 text-emerald-400 font-bold">
                  {geminiKey ? 'Gemini 2.5 Flash' : 'Built-in SOC Engine'}
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 font-mono">
                Guidance across all 80 tools, mathematical models & triage workflows
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowKeyConfig(!showKeyConfig)}
              className="p-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors text-xs font-mono flex items-center gap-1.5"
              title="Configure Gemini API Key"
            >
              <Key size={14} className={geminiKey ? "text-emerald-400" : "text-zinc-500"} />
              <span className="hidden sm:inline">API Key</span>
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900 transition-colors"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Optional Gemini API Key Drawer */}
        {showKeyConfig && (
          <div className="p-4 bg-zinc-900/90 border-b border-zinc-800 text-xs font-mono flex-shrink-0 animate-in fade-in duration-200">
            <form onSubmit={handleSaveKey} className="space-y-2 max-w-xl">
              <div className="flex items-center justify-between">
                <span className="font-bold text-zinc-200 flex items-center gap-1.5">
                  <Sparkles size={14} className="text-cyan-400" /> Custom Gemini API Key (Optional)
                </span>
                <span className="text-[11px] text-zinc-500">Stored in browser localStorage</span>
              </div>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={geminiKey}
                  onChange={(e) => setGeminiKey(e.target.value)}
                  placeholder="AIzaSy... (leave blank to use offline SOC engine)"
                  className="flex-1 px-3 py-2 rounded-lg bg-zinc-950 border border-zinc-700 text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500 text-zinc-950 font-bold hover:bg-cyan-400 transition-colors"
                >
                  Save
                </button>
              </div>
              <p className="text-[10px] text-zinc-500">
                Without a key, A.E.G.I.S. uses the built-in offline knowledge database covering all 80 tools.
              </p>
            </form>
          </div>
        )}

        {/* Message Thread */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4">
          {messages.map((msg) => {
            const isUser = msg.role === 'user';
            return (
              <div
                key={msg.id}
                className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'}`}
              >
                {!isUser && (
                  <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Bot size={16} />
                  </div>
                )}

                <div className={`max-w-[85%] rounded-2xl p-4 text-xs font-sans leading-relaxed ${
                  isUser
                    ? 'bg-zinc-850 text-zinc-100 border border-zinc-700'
                    : 'bg-zinc-900/90 text-zinc-200 border border-zinc-800/80 shadow-md'
                }`}>
                  <div className="flex items-center justify-between gap-4 mb-2 pb-1 border-b border-zinc-800/60 text-[10px] font-mono text-zinc-400">
                    <span className="font-bold text-zinc-300">
                      {isUser ? 'SOC Operator' : 'A.E.G.I.S. Copilot'}
                    </span>
                    <div className="flex items-center gap-2">
                      <span>{msg.timestamp}</span>
                      <button
                        onClick={() => handleCopy(msg.id, msg.content)}
                        className="hover:text-zinc-200"
                        title="Copy text"
                      >
                        {copiedId === msg.id ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>

                  {/* Render content as pre-formatted markdown-like block */}
                  <div className="space-y-2 whitespace-pre-wrap font-mono text-[12px] leading-relaxed select-text">
                    {msg.content}
                  </div>

                  {/* Mentioned Tool Quick Launch Buttons */}
                  {msg.suggestedTools && msg.suggestedTools.length > 0 && (
                    <div className="mt-3 pt-2.5 border-t border-zinc-800/80 flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-mono text-zinc-400 flex items-center gap-1">
                        <Terminal size={11} className="text-emerald-400" /> Detected Tools:
                      </span>
                      {msg.suggestedTools.map(tid => (
                        <button
                          key={tid}
                          onClick={() => handleLaunchToolById(tid)}
                          className="px-2 py-1 rounded bg-emerald-950/80 border border-emerald-600/60 text-emerald-300 text-[11px] font-mono font-bold hover:bg-emerald-900 transition-colors flex items-center gap-1 shadow-sm"
                        >
                          Launch {tid} <ExternalLink size={10} />
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {isLoading && (
            <div className="flex gap-3 justify-start">
              <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0">
                <Bot size={16} />
              </div>
              <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-400 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse delay-75" />
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse delay-150" />
                <span>Analyzing threat telemetry & tool intelligence...</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Suggested Prompt Chips */}
        <div className="px-4 py-2 border-t border-zinc-800/80 bg-zinc-950/80 flex items-center gap-2 overflow-x-auto scrollbar-none flex-shrink-0">
          <span className="text-[10px] font-mono text-zinc-500 whitespace-nowrap">Suggested:</span>
          {PROMPT_CHIPS.map(chip => (
            <button
              key={chip}
              onClick={() => handleSendMessage(chip)}
              className="px-2.5 py-1 rounded-full text-[11px] font-mono whitespace-nowrap bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-cyan-300 hover:border-cyan-500/40 hover:bg-zinc-850 transition-colors"
            >
              {chip}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-3 bg-zinc-950 border-t border-zinc-800 flex items-center gap-2 flex-shrink-0">
          <input
            ref={inputRef}
            type="text"
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSendMessage();
            }}
            placeholder="Ask about tool capabilities, algorithms, playbooks, or MITRE mapping..."
            className="flex-1 px-4 py-3 rounded-xl bg-zinc-900 border border-zinc-800 text-sm font-mono text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={!inputQuery.trim() || isLoading}
            className="p-3 rounded-xl bg-cyan-500 text-zinc-950 font-bold hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)]"
          >
            <Send size={16} />
          </button>
        </div>
      </div>
    </div>
  );
};
