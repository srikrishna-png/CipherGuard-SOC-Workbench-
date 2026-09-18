import React, { useState, useEffect } from 'react';
import { ToolMetadata, FiveLayerAnalysisResult } from '../../types';
import { ToolInputArea } from './ToolInputArea';
import { FiveLayerResultCard } from './FiveLayerResultCard';
import { analyzeTool } from '../../lib/api';

interface WorkbenchProps {
  tool: ToolMetadata;
  onSelectToolById: (toolId: string) => void;
}

export const Workbench: React.FC<WorkbenchProps> = ({ tool, onSelectToolById }) => {
  const [inputText, setInputText] = useState('');
  const [analysisResult, setAnalysisResult] = useState<FiveLayerAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [operationMode, setOperationMode] = useState<'generation' | 'analysis'>('analysis');

  // Pre-fill input when tool changes if it has sample inputs
  useEffect(() => {
    if (tool.sampleInputs && tool.sampleInputs.length > 0) {
      setInputText(tool.sampleInputs[0].payload);
    } else {
      setInputText('');
    }
    setAnalysisResult(null);
    setErrorMessage(null);
    setOperationMode('analysis');
  }, [tool]);

  const handleRunAnalysis = async (customParams: Record<string, any> = {}, overrideInput?: string) => {
    const payloadInput = overrideInput !== undefined ? overrideInput : inputText;
    if (!payloadInput.trim() && !customParams.secret_text) return;
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const mergedParams = {
        mode: operationMode,
        ...customParams
      };
      const result = await analyzeTool(tool.id, payloadInput, mergedParams);
      setAnalysisResult(result);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to complete analysis. Check backend connectivity.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadPayloadIntoInput = (payload: string, targetMode?: 'generation' | 'analysis') => {
    setInputText(payload);
    if (targetMode) {
      setOperationMode(targetMode);
    }
  };

  return (
    <div className="flex-1 p-4 lg:p-6 lg:ml-72 mt-16 min-h-[calc(100vh-4rem)] bg-[#09090b]">
      {errorMessage && (
        <div className="mb-4 p-3 rounded-lg bg-red-950/60 border border-red-800/80 text-red-300 text-xs font-mono flex items-center justify-between">
          <span>Error: {errorMessage}</span>
          <button 
            onClick={() => setErrorMessage(null)} 
            className="text-red-400 hover:text-red-200 ml-2"
          >
            &times;
          </button>
        </div>
      )}

      {/* Split-Screen Workbench Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        {/* Left Pane: Input Editor (5 cols on XL) */}
        <div className="xl:col-span-5 h-[calc(100vh-6.5rem)] sticky top-20 flex flex-col">
          <ToolInputArea
            tool={tool}
            inputText={inputText}
            onChangeInput={setInputText}
            onRunAnalysis={handleRunAnalysis}
            isLoading={isLoading}
            operationMode={operationMode}
            onChangeOperationMode={setOperationMode}
          />
        </div>

        {/* Right Pane: 5-Layer Structured Result (7 cols on XL) */}
        <div className="xl:col-span-7 h-[calc(100vh-6.5rem)] flex flex-col">
          <FiveLayerResultCard
            result={analysisResult}
            isLoading={isLoading}
            onSelectToolById={onSelectToolById}
            onLoadPayloadIntoInput={handleLoadPayloadIntoInput}
          />
        </div>
      </div>
    </div>
  );
};
