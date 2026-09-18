import React, { useState, useEffect } from 'react';
import { SUITES_CATALOG, findToolById } from './data/toolsRegistry';
import { ToolMetadata } from './types';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { BottomNav } from './components/layout/BottomNav';
import { MobileSidebar } from './components/layout/MobileSidebar';
import { CommandPalette } from './components/layout/CommandPalette';
import { Workbench } from './components/workbench/Workbench';
import { AuditLedgerModal } from './components/audit/AuditLedgerModal';

export function App() {
  // Default tool is Deep URL & Phishing Link Analyzer (Suite 1, Tool 1)
  const [selectedTool, setSelectedTool] = useState<ToolMetadata>(SUITES_CATALOG[0].tools[0]);
  
  // Modal & Drawer states
  const [isAuditLedgerOpen, setIsAuditLedgerOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isMobileDrawerOpen, setIsMobileDrawerOpen] = useState(false);
  const [activeMobileView, setActiveMobileView] = useState<'workbench' | 'suites' | 'audit'>('workbench');

  // Handle global keyboard shortcuts (Ctrl+K / Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleSelectTool = (tool: ToolMetadata) => {
    setSelectedTool(tool);
    setActiveMobileView('workbench');
    setIsMobileDrawerOpen(false);
  };

  const handleSelectToolById = (toolId: string) => {
    const { tool } = findToolById(toolId);
    handleSelectTool(tool);
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 flex flex-col antialiased selection:bg-emerald-500/30">
      {/* Top Navbar */}
      <Navbar
        activeToolName={selectedTool.name}
        onOpenAuditLedger={() => setIsAuditLedgerOpen(true)}
        onOpenSearch={() => setIsSearchOpen(true)}
        onToggleMobileMenu={() => setIsMobileDrawerOpen(true)}
      />

      {/* Main Content Layout */}
      <div className="flex flex-1">
        {/* Desktop Left Sidebar (8 Suites / 80 Tools) */}
        <Sidebar
          selectedToolId={selectedTool.id}
          onSelectTool={handleSelectTool}
        />

        {/* Central Dual-Pane Workbench */}
        <main className="flex-1 flex flex-col pb-24 lg:pb-0">
          <Workbench
            tool={selectedTool}
            onSelectToolById={handleSelectToolById}
          />
        </main>
      </div>

      {/* Mobile Floating Glassmorphic Bottom Dock */}
      <BottomNav
        activeView={activeMobileView}
        onOpenWorkbench={() => {
          setActiveMobileView('workbench');
          setIsMobileDrawerOpen(false);
        }}
        onOpenMobileDrawer={() => {
          setActiveMobileView('suites');
          setIsMobileDrawerOpen(true);
        }}
        onOpenAuditLedger={() => {
          setActiveMobileView('audit');
          setIsAuditLedgerOpen(true);
        }}
        onOpenSearch={() => setIsSearchOpen(true)}
      />

      {/* Mobile Slide-out Drawer */}
      <MobileSidebar
        isOpen={isMobileDrawerOpen}
        onClose={() => {
          setIsMobileDrawerOpen(false);
          setActiveMobileView('workbench');
        }}
        selectedToolId={selectedTool.id}
        onSelectTool={handleSelectTool}
      />

      {/* Global Cmd+K Search Palette */}
      <CommandPalette
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        onSelectTool={handleSelectTool}
      />

      {/* Cryptographic Audit Ledger Modal */}
      <AuditLedgerModal
        isOpen={isAuditLedgerOpen}
        onClose={() => setIsAuditLedgerOpen(false)}
      />
    </div>
  );
}

export default App;
