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
import { Dashboard } from './components/dashboard/Dashboard';
import { LoginPage, UserProfile } from './components/auth/LoginPage';
import { AIAssistantModal } from './components/ai/AIAssistantModal';

const DEFAULT_USER: UserProfile = {
  username: 'srikrishna-png',
  role: 'Lead SOC Architect & Security Director',
  clearance: 'OMNI-TOP-SECRET // LEVEL 5',
  avatarInitials: 'SK',
  badgeColor: 'border-emerald-500 text-emerald-400 bg-emerald-950/60',
  loginTime: '09:00:00 AM'
};

export function App() {
  // Navigation views: dashboard | workbench | login
  const [currentView, setCurrentView] = useState<'dashboard' | 'workbench' | 'login'>('dashboard');

  // Currently active tool in workbench
  const [selectedTool, setSelectedTool] = useState<ToolMetadata>(SUITES_CATALOG[0].tools[0]);

  // User Profile Session
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => {
    try {
      const saved = localStorage.getItem('CIPHERGUARD_USER_PROFILE');
      return saved ? JSON.parse(saved) : DEFAULT_USER;
    } catch {
      return DEFAULT_USER;
    }
  });

  // Modals & Drawers
  const [isAuditLedgerOpen, setIsAuditLedgerOpen] = useState(false);
  const [isAIAssistantOpen, setIsAIAssistantOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isMobileDrawerOpen, setIsMobileDrawerOpen] = useState(false);
  const [activeMobileView, setActiveMobileView] = useState<'workbench' | 'suites' | 'audit'>('workbench');

  // Keyboard shortcut (Ctrl+K / Cmd+K)
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
    setCurrentView('workbench');
    setActiveMobileView('workbench');
    setIsMobileDrawerOpen(false);
  };

  const handleSelectToolById = (toolId: string) => {
    const { tool } = findToolById(toolId);
    handleSelectTool(tool);
  };

  const handleLoginSuccess = (profile: UserProfile) => {
    setCurrentUser(profile);
    try {
      localStorage.setItem('CIPHERGUARD_USER_PROFILE', JSON.stringify(profile));
    } catch {}
    setCurrentView('dashboard');
  };

  const handleLogout = () => {
    setCurrentUser(null);
    try {
      localStorage.removeItem('CIPHERGUARD_USER_PROFILE');
    } catch {}
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 flex flex-col antialiased selection:bg-emerald-500/30">
      {/* Top Navbar */}
      <Navbar
        currentView={currentView}
        onChangeView={setCurrentView}
        activeToolName={selectedTool.name}
        currentUser={currentUser}
        onLogout={handleLogout}
        onOpenAuditLedger={() => setIsAuditLedgerOpen(true)}
        onOpenAIAssistant={() => setIsAIAssistantOpen(true)}
        onOpenSearch={() => setIsSearchOpen(true)}
        onToggleMobileMenu={() => setIsMobileDrawerOpen(true)}
      />

      {/* Main Content Area based on current view */}
      {currentView === 'dashboard' && (
        <main className="flex-1 flex flex-col">
          <Dashboard
            onSelectTool={handleSelectTool}
            onOpenWorkbench={() => setCurrentView('workbench')}
            onOpenLedger={() => setIsAuditLedgerOpen(true)}
            onOpenAIAssistant={() => setIsAIAssistantOpen(true)}
            onOpenSearch={() => setIsSearchOpen(true)}
          />
        </main>
      )}

      {currentView === 'workbench' && (
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
      )}

      {currentView === 'login' && (
        <main className="flex-1 flex flex-col">
          <LoginPage
            onLoginSuccess={handleLoginSuccess}
            onCancel={() => setCurrentView('dashboard')}
          />
        </main>
      )}

      {/* Mobile Floating Bottom Nav */}
      <BottomNav
        activeView={activeMobileView}
        onOpenWorkbench={() => {
          setCurrentView('workbench');
          setActiveMobileView('workbench');
          setIsMobileDrawerOpen(false);
        }}
        onOpenMobileDrawer={() => {
          setCurrentView('workbench');
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

      {/* Global Cmd+K Search Palette (All 80 Tools) */}
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

      {/* Gemini AI SOC Copilot Modal */}
      <AIAssistantModal
        isOpen={isAIAssistantOpen}
        onClose={() => setIsAIAssistantOpen(false)}
        onSelectTool={handleSelectTool}
        currentTool={selectedTool}
      />
    </div>
  );
}

export default App;

