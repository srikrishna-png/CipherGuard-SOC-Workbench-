import React, { ReactNode } from 'react';
import { motion } from 'framer-motion';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface CyberButtonProps {
  children: ReactNode;
  onClick?: () => void;
  className?: string;
  variant?: 'primary' | 'secondary' | 'cyan' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
}

export const CyberButton: React.FC<CyberButtonProps> = ({
  children,
  onClick,
  className,
  variant = 'primary',
  size = 'md',
  disabled = false,
  type = 'button'
}) => {
  const baseStyles = "relative inline-flex items-center justify-center font-mono font-medium transition-all overflow-hidden rounded-md select-none";

  const sizeStyles = {
    sm: "px-3 py-1.5 text-xs gap-1.5",
    md: "px-5 py-2.5 text-sm gap-2",
    lg: "px-7 py-3.5 text-base gap-2.5 font-bold"
  };

  const variants = {
    primary: "bg-emerald-500 text-zinc-950 font-bold hover:bg-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.35)] hover:shadow-[0_0_25px_rgba(16,185,129,0.6)] border border-emerald-400/40",
    secondary: "bg-zinc-900/80 text-zinc-200 border border-zinc-700/80 hover:bg-zinc-800/90 hover:border-zinc-600 hover:text-white shadow-sm",
    cyan: "bg-cyan-500 text-zinc-950 font-bold hover:bg-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.35)] hover:shadow-[0_0_25px_rgba(6,182,212,0.6)] border border-cyan-400/40",
    danger: "bg-red-500/10 text-red-400 border border-red-500/40 hover:bg-red-500/20 hover:border-red-500/70 shadow-[0_0_15px_rgba(239,68,68,0.2)]",
    ghost: "bg-transparent text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/50"
  };

  return (
    <motion.button
      type={type}
      whileHover={{ scale: disabled ? 1 : 1.02 }}
      whileTap={{ scale: disabled ? 1 : 0.98 }}
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      className={cn(
        baseStyles,
        sizeStyles[size],
        variants[variant],
        disabled && "opacity-50 cursor-not-allowed",
        className
      )}
    >
      {/* Glitch Overlay Reflection Effect on Hover */}
      {!disabled && (variant === 'primary' || variant === 'cyan') && (
        <motion.div
          className="absolute inset-0 bg-white/25 -translate-x-[150%] skew-x-[-45deg]"
          whileHover={{
            x: ["-150%", "150%"],
            transition: { duration: 0.5, ease: "easeInOut" },
          }}
        />
      )}
      <span className="relative z-10 flex items-center gap-2">{children}</span>
    </motion.button>
  );
};
