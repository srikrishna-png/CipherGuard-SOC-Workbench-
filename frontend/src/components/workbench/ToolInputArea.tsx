import React, { useState, useRef, useEffect } from 'react';
import { 
  Play, 
  RotateCcw, 
  Sparkles, 
  Terminal, 
  FileText, 
  Image as ImageIcon, 
  UploadCloud, 
  Eye, 
  Code, 
  Trash2,
  Layers,
  Lock,
  Unlock,
  Key,
  ShieldCheck,
  Cpu,
  FileArchive,
  FileCode
} from 'lucide-react';
import { ToolMetadata } from '../../types';

interface ToolInputAreaProps {
  tool: ToolMetadata;
  inputText: string;
  onChangeInput: (text: string) => void;
  onRunAnalysis: (params?: Record<string, any>, overrideInput?: string) => void;
  isLoading: boolean;
  operationMode: 'generation' | 'analysis';
  onChangeOperationMode: (mode: 'generation' | 'analysis') => void;
}

interface ImageInfo {
  name: string;
  size: string;
  dimensions?: string;
  type: string;
}

export const ToolInputArea: React.FC<ToolInputAreaProps> = ({
  tool,
  inputText,
  onChangeInput,
  onRunAnalysis,
  isLoading,
  operationMode,
  onChangeOperationMode
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [imageInfo, setImageInfo] = useState<ImageInfo | null>(null);
  const [viewMode, setViewMode] = useState<'visual' | 'raw'>('visual');

  // Specific state for Stego generation
  const [stegoSecretText, setStegoSecretText] = useState('CONFIDENTIAL_FLAG{CYBER_STEGO_2026}');
  const [stegoPayloadType, setStegoPayloadType] = useState<'text' | 'zip' | 'webshell'>('text');

  // Specific state for AES decryption
  const [aesKey, setAesKey] = useState('');
  const [aesNonce, setAesNonce] = useState('');
  const [aesCiphertext, setAesCiphertext] = useState('');

  // Specific state for Crypto benchmark
  const [benchmarkAlgo, setBenchmarkAlgo] = useState('SHA-256');

  const isImageTool = tool.id === 'stego_detector' || tool.id === 'metadata_exif_extractor';
  const isHashTool = tool.id === 'file_hash_calculator';
  const isDataUrlImage = inputText.startsWith('data:image/');
  const isDualModeTool = ['stego_detector', 'aes_gcm_suite', 'crypto_benchmark', 'rsa_signature_suite', 'hmac_authenticator'].includes(tool.id);

  // Initialize view mode based on tool and input format
  useEffect(() => {
    if (isHashTool) {
      if (inputText.startsWith('data:')) {
        setViewMode('visual');
      } else {
        setViewMode('raw');
      }
    }
  }, [tool.id, isHashTool]);

  // Whenever inputText changes, inspect if it's a data URL image to calculate dimensions
  useEffect(() => {
    if (isDataUrlImage) {
      const img = new Image();
      img.onload = () => {
        const mimeMatch = inputText.match(/^data:(image\/[a-zA-Z+]+);base64,/);
        const mimeType = mimeMatch ? mimeMatch[1] : 'image/png';
        const byteLen = Math.round((inputText.length * 3) / 4);
        const formattedSize = byteLen > 1024 * 1024 
          ? `${(byteLen / (1024 * 1024)).toFixed(2)} MB` 
          : `${(byteLen / 1024).toFixed(1)} KB`;

        setImageInfo((prev) => ({
          name: prev?.name || 'carrier_payload.png',
          size: formattedSize,
          dimensions: `${img.naturalWidth} \u00d7 ${img.naturalHeight} px`,
          type: mimeType
        }));
      };
      img.src = inputText;
    } else if (!inputText && !isHashTool) {
      setImageInfo(null);
    }
  }, [inputText, isDataUrlImage, isHashTool]);

  const handleFileProcess = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const dataUrl = e.target?.result as string;
      if (dataUrl) {
        const formattedSize = file.size > 1024 * 1024
          ? `${(file.size / (1024 * 1024)).toFixed(2)} MB`
          : `${(file.size / 1024).toFixed(1)} KB`;

        setImageInfo({
          name: file.name,
          size: formattedSize,
          type: file.type || (isImageTool ? 'image/png' : 'application/octet-stream')
        });
        onChangeInput(dataUrl);
        setViewMode('visual');
      }
    };
    reader.readAsDataURL(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      handleFileProcess(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileProcess(e.target.files[0]);
    }
  };

  const handleSelectSample = (payload: string) => {
    onChangeInput(payload);
    if (payload.startsWith('data:image/') || (isHashTool && payload.startsWith('data:'))) {
      setViewMode('visual');
    } else {
      setViewMode('raw');
    }
  };

  const handleSubmit = () => {
    if (tool.id === 'stego_detector') {
      if (operationMode === 'generation') {
        onRunAnalysis({
          mode: 'encode',
          action: 'encode',
          secret_text: stegoSecretText,
          payload_type: stegoPayloadType
        }, inputText);
      } else {
        onRunAnalysis({
          mode: 'analyze',
          action: 'decode'
        }, inputText);
      }
    } else if (tool.id === 'aes_gcm_suite') {
      if (operationMode === 'generation') {
        onRunAnalysis({
          mode: 'encrypt',
          key: aesKey || undefined
        }, inputText);
      } else {
        let combinedInput = inputText;
        if (aesCiphertext || aesKey || aesNonce) {
          combinedInput = `Ciphertext: ${aesCiphertext}\nKey: ${aesKey}\nNonce: ${aesNonce}`;
        }
        onRunAnalysis({
          mode: 'decrypt',
          key: aesKey || undefined,
          nonce: aesNonce || undefined,
          ciphertext: aesCiphertext || undefined
        }, combinedInput);
      }
    } else if (tool.id === 'crypto_benchmark') {
      if (operationMode === 'generation') {
        const query = `Algorithm: ${benchmarkAlgo}, Input: "${inputText}"`;
        onRunAnalysis({
          mode: 'generation',
          algorithm: benchmarkAlgo
        }, query);
      } else {
        onRunAnalysis({
          mode: 'analysis'
        }, inputText);
      }
    } else if (tool.id === 'file_hash_calculator') {
      onRunAnalysis({
        filename: imageInfo?.name || undefined
      }, inputText);
    } else {
      onRunAnalysis({
        mode: operationMode
      }, inputText);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#0c0c0f] rounded-xl border border-zinc-800/80 overflow-hidden shadow-lg">
      {/* Header */}
      <div className="p-4 border-b border-zinc-800/80 bg-zinc-900/30">
        <div className="flex items-center justify-between gap-2 mb-1">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-emerald-950/60 border border-emerald-800/40 text-emerald-400">
              {isImageTool ? <ImageIcon className="w-4 h-4" /> : isHashTool ? <FileCode className="w-4 h-4" /> : <Terminal className="w-4 h-4" />}
            </div>
            <h2 className="font-mono font-bold text-base text-zinc-100">{tool.name}</h2>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-cyan-400 border border-zinc-700/60">
            {tool.suiteId.replace('suite', 'Suite ')}
          </span>
        </div>
        <p className="text-xs text-zinc-400 leading-relaxed mb-3">{tool.description}</p>

        {/* Dual Mode Switcher: Only render for dual-mode Cryptographic / Steganographic tools */}
        {isDualModeTool && (
          <div className="grid grid-cols-2 gap-1.5 p-1 bg-zinc-950/90 rounded-lg border border-zinc-800/90 shadow-inner">
            <button
              onClick={() => onChangeOperationMode('generation')}
              className={`flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-md text-xs font-mono font-bold transition-all ${
                operationMode === 'generation'
                  ? 'bg-emerald-500 text-zinc-950 shadow-[0_0_12px_rgba(16,185,129,0.35)]'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>⚡ Generation Mode (Encode)</span>
            </button>
            <button
              onClick={() => onChangeOperationMode('analysis')}
              className={`flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-md text-xs font-mono font-bold transition-all ${
                operationMode === 'analysis'
                  ? 'bg-cyan-500 text-zinc-950 shadow-[0_0_12px_rgba(6,182,212,0.35)]'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>🔍 Analysis Mode (Decode)</span>
            </button>
          </div>
        )}

        {/* Realistic Threat Sample Loaders */}
        {tool.sampleInputs && tool.sampleInputs.length > 0 && (
          <div className="mt-3 pt-3 border-t border-zinc-800/50 flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-mono text-zinc-400 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-emerald-400" />
              Presets:
            </span>
            {tool.sampleInputs.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => handleSelectSample(sample.payload)}
                className="text-xs font-mono px-2.5 py-1 rounded bg-zinc-800/80 text-zinc-300 hover:bg-emerald-950/60 hover:text-emerald-400 hover:border-emerald-700/60 border border-zinc-700/60 transition-all text-left truncate max-w-[220px]"
                title={sample.description}
              >
                {sample.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Editor / Visual Input Switcher Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800/60 bg-[#09090c] text-xs font-mono">
        <div className="flex items-center gap-2">
          {isImageTool && (
            <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5">
              <button
                onClick={() => setViewMode('visual')}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] transition-all ${
                  viewMode === 'visual'
                    ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/30'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <Eye className="w-3 h-3" />
                Image Carrier View
              </button>
              <button
                onClick={() => setViewMode('raw')}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] transition-all ${
                  viewMode === 'raw'
                    ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/30'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <Code className="w-3 h-3" />
                Raw Base64 / Hex
              </button>
            </div>
          )}
          {isHashTool && (
            <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5">
              <button
                onClick={() => setViewMode('visual')}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] transition-all ${
                  viewMode === 'visual'
                    ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/30'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <UploadCloud className="w-3 h-3 text-emerald-400" />
                Binary File Upload
              </button>
              <button
                onClick={() => setViewMode('raw')}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] transition-all ${
                  viewMode === 'raw'
                    ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/30'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <FileText className="w-3 h-3 text-cyan-400" />
                Hash Manifest / Text
              </button>
            </div>
          )}
          {!isImageTool && !isHashTool && (
            <span className="flex items-center gap-1.5 text-zinc-400 text-[11px]">
              {operationMode === 'generation' ? (
                <>
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  <span>PAYLOAD GENERATOR &amp; ENCODER</span>
                </>
              ) : (
                <>
                  <Unlock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>CIPHERTEXT &amp; TELEMETRY INSPECTOR</span>
                </>
              )}
            </span>
          )}
        </div>

        <div className="flex items-center gap-3 text-zinc-500 text-[11px]">
          {isDataUrlImage && imageInfo?.dimensions && (
            <span className="text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/30">
              {imageInfo.dimensions}
            </span>
          )}
          {isHashTool && imageInfo?.size && (
            <span className="text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/30">
              {imageInfo.size}
            </span>
          )}
          <span>{inputText.length.toLocaleString()} chars</span>
        </div>
      </div>

      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        accept={isImageTool ? "image/*,.png,.jpg,.jpeg,.gif,.bmp,.webp" : "*"}
        className="hidden"
        onChange={handleFileInputChange}
      />

      {/* Main Workspace Area */}
      <div className="flex-1 p-3 flex flex-col min-h-[260px] overflow-y-auto space-y-3">
        {/* SPECIALIZED UI FOR STEGANOGRAPHY DETECTOR & ENCODER */}
        {tool.id === 'stego_detector' ? (
          <div className="flex-1 flex flex-col space-y-3">
            {/* If in GENERATION / ENCODE Mode: Provide Secret Text & Carrier Image */}
            {operationMode === 'generation' ? (
              <div className="flex-1 flex flex-col space-y-3">
                {/* Secret Message Input Box */}
                <div className="bg-[#070709] border border-zinc-800/90 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5" />
                      Secret Message / Text to Hide:
                    </label>
                    <span className="text-[10px] font-mono text-zinc-500">Embedded past container EOF</span>
                  </div>
                  <textarea
                    value={stegoSecretText}
                    onChange={(e) => setStegoSecretText(e.target.value)}
                    placeholder="Enter secret message, passwords, or confidential notes..."
                    rows={3}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-2.5 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-500/70 resize-none leading-relaxed"
                  />
                  {/* Preset Payload Injectors */}
                  <div className="mt-2 flex flex-wrap items-center gap-1.5">
                    <span className="text-[10px] font-mono text-zinc-500">Presets:</span>
                    <button
                      type="button"
                      onClick={() => {
                        setStegoSecretText('CONFIDENTIAL_FLAG{CYBER_STEGO_2026}');
                        setStegoPayloadType('text');
                      }}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 hover:bg-emerald-950 hover:text-emerald-400 text-zinc-300 border border-zinc-700/60 transition-colors"
                    >
                      🚩 Secret Flag
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setStegoSecretText('user: admin | pass: Winter2026!# | token: sk_live_891273');
                        setStegoPayloadType('text');
                      }}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 hover:bg-emerald-950 hover:text-emerald-400 text-zinc-300 border border-zinc-700/60 transition-colors"
                    >
                      🔑 Credentials
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setStegoSecretText('PK_ARCHIVE_EXFILTRATION_DATA');
                        setStegoPayloadType('zip');
                      }}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 hover:bg-amber-950 hover:text-amber-400 text-zinc-300 border border-zinc-700/60 transition-colors"
                    >
                      📦 Polyglot ZIP
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setStegoSecretText('system($_GET[\'cmd\']);');
                        setStegoPayloadType('webshell');
                      }}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 hover:bg-red-950 hover:text-red-400 text-zinc-300 border border-zinc-700/60 transition-colors"
                    >
                      🐚 Web Shell Dropper
                    </button>
                  </div>
                </div>

                {/* Carrier Image Selection */}
                <div className="bg-[#070709] border border-zinc-800/90 rounded-lg p-3 flex-1 flex flex-col">
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs font-mono font-bold text-zinc-300 flex items-center gap-1.5">
                      <ImageIcon className="w-3.5 h-3.5 text-cyan-400" />
                      Carrier Image Container:
                    </label>
                    <span className="text-[10px] font-mono text-zinc-500">
                      {isDataUrlImage ? 'Custom Image Loaded' : 'Clean Default PNG Container'}
                    </span>
                  </div>

                  {isDataUrlImage ? (
                    <div className="flex-1 flex flex-col items-center justify-center p-3 bg-zinc-950 rounded-lg border border-zinc-800">
                      <img src={inputText} alt="Carrier" className="max-h-[110px] w-auto object-contain rounded mb-2" />
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono text-emerald-400">{imageInfo?.dimensions || 'Custom Container'}</span>
                        <button
                          type="button"
                          onClick={() => {
                            onChangeInput('');
                            setImageInfo(null);
                          }}
                          className="text-[11px] font-mono text-red-400 hover:text-red-300 ml-2"
                        >
                          Use Clean Default PNG
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div 
                      onClick={() => fileInputRef.current?.click()}
                      className="flex-1 min-h-[90px] border border-dashed border-zinc-800 hover:border-emerald-500/50 rounded-lg flex flex-col items-center justify-center p-3 cursor-pointer bg-zinc-950/60 transition-colors"
                    >
                      <UploadCloud className="w-5 h-5 text-emerald-400 mb-1" />
                      <span className="text-xs font-mono text-zinc-300 font-semibold">Clean 10x10 PNG Container Ready</span>
                      <span className="text-[10px] font-mono text-zinc-500">Click to upload your own custom carrier image (optional)</span>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              /* If in ANALYSIS / DECODE Mode: Inspect / Upload Image */
              isDataUrlImage && viewMode === 'visual' ? (
                <div className="flex-1 flex flex-col items-center justify-center p-4 bg-[#070709] border border-zinc-800/80 rounded-lg">
                  <div className="relative group max-w-full flex flex-col items-center">
                    <div className="p-2 bg-[radial-gradient(#27272a_1px,transparent_1px)] [background-size:12px_12px] bg-zinc-950 rounded-xl border border-zinc-800 shadow-2xl flex items-center justify-center max-h-[220px] max-w-[340px] overflow-hidden">
                      <img src={inputText} alt="Carrier Preview" className="max-h-[200px] w-auto object-contain rounded" />
                    </div>
                    <div className="mt-3 flex flex-wrap items-center justify-center gap-2 text-xs font-mono">
                      <span className="px-2.5 py-1 bg-zinc-900 border border-zinc-800 rounded-md text-zinc-300 flex items-center gap-1.5">
                        <Layers className="w-3.5 h-3.5 text-cyan-400" />
                        {imageInfo?.name || 'carrier_payload.png'}
                      </span>
                      {imageInfo?.dimensions && (
                        <span className="px-2 py-1 bg-emerald-950/50 border border-emerald-800/50 rounded-md text-emerald-400 font-semibold">
                          {imageInfo.dimensions}
                        </span>
                      )}
                      {imageInfo?.size && (
                        <span className="px-2 py-1 bg-zinc-900 border border-zinc-800 rounded-md text-zinc-400">
                          {imageInfo.size}
                        </span>
                      )}
                    </div>
                    <div className="mt-3 flex items-center gap-2">
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="flex items-center gap-1 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono rounded-lg transition-colors border border-zinc-700/60"
                      >
                        <UploadCloud className="w-3.5 h-3.5 text-emerald-400" />
                        Replace Image
                      </button>
                      <button
                        onClick={() => {
                          onChangeInput('');
                          setImageInfo(null);
                        }}
                        className="flex items-center gap-1 px-3 py-1.5 bg-red-950/40 hover:bg-red-900/60 text-red-400 text-xs font-mono rounded-lg transition-colors border border-red-800/40"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Remove
                      </button>
                    </div>
                  </div>
                </div>
              ) : viewMode === 'raw' ? (
                <textarea
                  value={inputText}
                  onChange={(e) => onChangeInput(e.target.value)}
                  placeholder="Paste raw Base64 data URL or hex container..."
                  className="flex-1 w-full bg-[#070709] border border-zinc-800/80 rounded-lg p-3 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-600/70 resize-none leading-relaxed"
                  spellCheck={false}
                />
              ) : (
                <div
                  onDrop={handleDrop}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onClick={() => fileInputRef.current?.click()}
                  className={`flex-1 flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-lg cursor-pointer transition-all ${
                    isDragging
                      ? 'border-emerald-500 bg-emerald-950/20 text-emerald-300'
                      : 'border-zinc-800 hover:border-emerald-600/60 bg-[#070709] hover:bg-zinc-900/40 text-zinc-400'
                  }`}
                >
                  <div className="p-3 rounded-full bg-zinc-900 border border-zinc-800 text-emerald-400 mb-3 shadow-inner">
                    <UploadCloud className="w-6 h-6 animate-pulse" />
                  </div>
                  <p className="font-mono text-xs font-bold text-zinc-200 mb-1">
                    Drop carrier image here, or click to browse
                  </p>
                  <p className="font-mono text-[11px] text-zinc-500 text-center max-w-xs mb-3">
                    Supports PNG, JPEG, GIF, BMP containers for trailing byte carving and steganography detection.
                  </p>
                  <span className="px-2.5 py-1 bg-zinc-800/80 rounded border border-zinc-700/50 text-[10px] font-mono text-cyan-400">
                    Auto Carve &amp; Signature Analysis
                  </span>
                </div>
              )
            )}
          </div>
        ) : isHashTool ? (
          /* Specialized Binary File Dropzone & Manifest Editor for Static File Hash Calculator */
          viewMode === 'visual' ? (
            imageInfo ? (
              <div className="flex-1 flex flex-col items-center justify-center p-4 bg-[#070709] border border-zinc-800/80 rounded-lg">
                <div className="p-5 bg-zinc-950 rounded-xl border border-zinc-800 max-w-sm w-full flex flex-col items-center text-center shadow-2xl">
                  <div className="p-3.5 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400 mb-3 shadow-inner">
                    <FileCode className="w-8 h-8" />
                  </div>
                  <div className="font-mono text-xs font-bold text-zinc-100 mb-1 truncate max-w-full">
                    {imageInfo.name}
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-zinc-400 mb-4">
                    <span className="px-2 py-0.5 bg-zinc-900 rounded border border-zinc-800 text-cyan-400 font-semibold">{imageInfo.size}</span>
                    <span className="text-zinc-600">•</span>
                    <span className="text-zinc-400">{imageInfo.type}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => fileInputRef.current?.click()}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono rounded-lg transition-colors border border-zinc-700/60"
                    >
                      <UploadCloud className="w-3.5 h-3.5 text-emerald-400" />
                      Replace File
                    </button>
                    <button
                      onClick={() => {
                        onChangeInput('');
                        setImageInfo(null);
                      }}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-red-950/40 hover:bg-red-900/60 text-red-400 text-xs font-mono rounded-lg transition-colors border border-red-800/40"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Remove
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onClick={() => fileInputRef.current?.click()}
                className={`flex-1 flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-lg cursor-pointer transition-all ${
                  isDragging
                    ? 'border-emerald-500 bg-emerald-950/20 text-emerald-300'
                    : 'border-zinc-800 hover:border-emerald-600/60 bg-[#070709] hover:bg-zinc-900/40 text-zinc-400'
                }`}
              >
                <div className="p-3.5 rounded-full bg-zinc-900 border border-zinc-800 text-emerald-400 mb-3 shadow-inner">
                  <UploadCloud className="w-7 h-7 animate-pulse" />
                </div>
                <p className="font-mono text-xs font-bold text-zinc-200 mb-1 text-center">
                  Drop any binary or file here to calculate cryptographic hashes
                </p>
                <p className="font-mono text-[11px] text-zinc-500 text-center max-w-sm mb-3">
                  Supports .exe, .dll, .bin, .pdf, .zip, .docx, images, or raw binary payloads.
                </p>
                <span className="px-2.5 py-1 bg-zinc-800/80 rounded border border-zinc-700/50 text-[10px] font-mono text-cyan-400">
                  Instant Multi-Digest Synthesis (SHA-256, MD5, SHA-1, SHA-512)
                </span>
              </div>
            )
          ) : (
            <textarea
              value={inputText}
              onChange={(e) => onChangeInput(e.target.value)}
              placeholder="Paste hash manifest (e.g. Algorithm: SHA-256, File: notepad.exe, Hash: ...) or raw string..."
              className="flex-1 w-full bg-[#070709] border border-zinc-800/80 rounded-lg p-3 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-600/70 resize-none leading-relaxed"
              spellCheck={false}
            />
          )
        ) : tool.id === 'aes_gcm_suite' && operationMode === 'analysis' ? (
          /* Specialized Multi-Input for AES Decrypt / Analysis */
          <div className="flex-1 flex flex-col space-y-2.5">
            <div className="bg-[#070709] border border-zinc-800/80 rounded-lg p-3 space-y-2.5">
              <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                <Unlock className="w-3.5 h-3.5" />
                AES-256-GCM Decryption Parameters:
              </span>
              <div>
                <label className="text-[11px] font-mono text-zinc-400 block mb-1">Ciphertext (Hex + 16-byte GCM Tag):</label>
                <input
                  type="text"
                  value={aesCiphertext}
                  onChange={(e) => setAesCiphertext(e.target.value)}
                  placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99..."
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <div>
                  <label className="text-[11px] font-mono text-zinc-400 block mb-1">Key (64-char Hex, 256-bit):</label>
                  <input
                    type="text"
                    value={aesKey}
                    onChange={(e) => setAesKey(e.target.value)}
                    placeholder="e.g. 0123456789abcdef..."
                    className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-mono text-zinc-400 block mb-1">Nonce (24-char Hex, 96-bit):</label>
                  <input
                    type="text"
                    value={aesNonce}
                    onChange={(e) => setAesNonce(e.target.value)}
                    placeholder="e.g. e0d1c2b3a495867768594a3b"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
              <div className="pt-2 border-t border-zinc-800/60 text-[11px] font-mono text-zinc-500">
                Or paste complete session bundle into Raw Input below:
              </div>
            </div>
            <textarea
              value={inputText}
              onChange={(e) => onChangeInput(e.target.value)}
              placeholder="Ciphertext: <hex>\nKey: <hex>\nNonce: <hex>"
              rows={4}
              className="w-full bg-[#070709] border border-zinc-800/80 rounded-lg p-3 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-cyan-500 resize-none leading-relaxed"
              spellCheck={false}
            />
          </div>
        ) : tool.id === 'crypto_benchmark' && operationMode === 'generation' ? (
          /* Specialized Algorithm Selection for Crypto Benchmark Generator */
          <div className="flex-1 flex flex-col space-y-3">
            <div className="bg-[#070709] border border-zinc-800/80 rounded-lg p-3">
              <label className="text-xs font-mono font-bold text-emerald-400 block mb-2">
                Select Hash Algorithm to Synthesize:
              </label>
              <div className="grid grid-cols-3 sm:grid-cols-5 gap-2">
                {['SHA-256', 'MD5', 'SHA-1', 'BLAKE2b', 'SHA-3'].map((algo) => (
                  <button
                    key={algo}
                    type="button"
                    onClick={() => setBenchmarkAlgo(algo)}
                    className={`py-1.5 px-2 rounded text-xs font-mono font-bold transition-all border ${
                      benchmarkAlgo === algo
                        ? 'bg-emerald-600 text-white border-emerald-500 shadow-sm'
                        : 'bg-zinc-900 text-zinc-400 border-zinc-800 hover:text-zinc-200 hover:bg-zinc-800'
                    }`}
                  >
                    {algo}
                  </button>
                ))}
              </div>
            </div>
            <textarea
              value={inputText}
              onChange={(e) => onChangeInput(e.target.value)}
              placeholder="Enter text string or credentials to compute cryptographic hash..."
              className="flex-1 w-full bg-[#070709] border border-zinc-800/80 rounded-lg p-3 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-600/70 resize-none leading-relaxed"
              spellCheck={false}
            />
          </div>
        ) : isImageTool && viewMode === 'visual' ? (
          /* General Image Carrier View */
          isDataUrlImage ? (
            <div className="flex-1 flex flex-col items-center justify-center p-4 bg-[#070709] border border-zinc-800/80 rounded-lg">
              <div className="relative group max-w-full flex flex-col items-center">
                <div className="p-2 bg-[radial-gradient(#27272a_1px,transparent_1px)] [background-size:12px_12px] bg-zinc-950 rounded-xl border border-zinc-800 shadow-2xl flex items-center justify-center max-h-[220px] max-w-[340px] overflow-hidden">
                  <img src={inputText} alt="Carrier Preview" className="max-h-[200px] w-auto object-contain rounded" />
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-center gap-2 text-xs font-mono">
                  <span className="px-2.5 py-1 bg-zinc-900 border border-zinc-800 rounded-md text-zinc-300 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-cyan-400" />
                    {imageInfo?.name || 'carrier_payload.png'}
                  </span>
                  {imageInfo?.dimensions && (
                    <span className="px-2 py-1 bg-emerald-950/50 border border-emerald-800/50 rounded-md text-emerald-400 font-semibold">
                      {imageInfo.dimensions}
                    </span>
                  )}
                  {imageInfo?.size && (
                    <span className="px-2 py-1 bg-zinc-900 border border-zinc-800 rounded-md text-zinc-400">
                      {imageInfo.size}
                    </span>
                  )}
                </div>
                <div className="mt-3 flex items-center gap-2">
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-1 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono rounded-lg transition-colors border border-zinc-700/60"
                  >
                    <UploadCloud className="w-3.5 h-3.5 text-emerald-400" />
                    Replace Image
                  </button>
                  <button
                    onClick={() => {
                      onChangeInput('');
                      setImageInfo(null);
                    }}
                    className="flex items-center gap-1 px-3 py-1.5 bg-red-950/40 hover:bg-red-900/60 text-red-400 text-xs font-mono rounded-lg transition-colors border border-red-800/40"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Remove
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => fileInputRef.current?.click()}
              className={`flex-1 flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-lg cursor-pointer transition-all ${
                isDragging
                  ? 'border-emerald-500 bg-emerald-950/20 text-emerald-300'
                  : 'border-zinc-800 hover:border-emerald-600/60 bg-[#070709] hover:bg-zinc-900/40 text-zinc-400'
              }`}
            >
              <div className="p-3 rounded-full bg-zinc-900 border border-zinc-800 text-emerald-400 mb-3 shadow-inner">
                <UploadCloud className="w-6 h-6 animate-pulse" />
              </div>
              <p className="font-mono text-xs font-bold text-zinc-200 mb-1">
                Drop carrier image here, or click to browse
              </p>
              <p className="font-mono text-[11px] text-zinc-500 text-center max-w-xs mb-3">
                Supports PNG, JPEG, GIF, BMP containers for trailing byte carving and steganography detection.
              </p>
              <span className="px-2.5 py-1 bg-zinc-800/80 rounded border border-zinc-700/50 text-[10px] font-mono text-cyan-400">
                Auto Base64 &amp; Container Analysis
              </span>
            </div>
          )
        ) : (
          /* General Raw Editor Textarea */
          <textarea
            value={inputText}
            onChange={(e) => onChangeInput(e.target.value)}
            placeholder={tool.inputPlaceholder}
            className="flex-1 w-full bg-[#070709] border border-zinc-800/80 rounded-lg p-3 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-600/70 resize-none leading-relaxed"
            spellCheck={false}
          />
        )}
      </div>

      {/* Action Footer */}
      <div className="p-3 bg-zinc-900/40 border-t border-zinc-800/80 flex items-center justify-between">
        <button
          onClick={() => {
            onChangeInput('');
            setImageInfo(null);
            setAesCiphertext('');
            setAesKey('');
            setAesNonce('');
          }}
          disabled={!inputText && !stegoSecretText && !aesCiphertext}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Clear
        </button>

        <button
          onClick={handleSubmit}
          disabled={isLoading || (tool.id === 'stego_detector' && operationMode === 'generation' ? !stegoSecretText.trim() : !inputText.trim() && !aesCiphertext.trim())}
          className={`flex items-center gap-2 px-5 py-2 rounded-lg font-mono font-bold text-xs shadow-lg transition-all transform active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed ${
            operationMode === 'generation'
              ? 'bg-emerald-500 hover:bg-emerald-400 text-zinc-950 shadow-[0_0_16px_rgba(16,185,129,0.35)]'
              : 'bg-cyan-500 hover:bg-cyan-400 text-zinc-950 shadow-[0_0_16px_rgba(6,182,212,0.35)]'
          }`}
        >
          {isLoading ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-zinc-950 border-t-transparent rounded-full animate-spin" />
              <span>Processing...</span>
            </>
          ) : isHashTool ? (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Calculate Cryptographic Hashes</span>
            </>
          ) : operationMode === 'generation' ? (
            <>
              <Sparkles className="w-3.5 h-3.5" />
              <span>{tool.id === 'stego_detector' ? 'Embed Secret & Generate Stego' : tool.id === 'aes_gcm_suite' ? 'Encrypt & Synthesize' : 'Generate & Synthesize'}</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{tool.id === 'stego_detector' ? 'Carve & Decode Stego' : tool.id === 'aes_gcm_suite' ? 'Authenticate & Decrypt' : 'Run Deep Analysis'}</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
