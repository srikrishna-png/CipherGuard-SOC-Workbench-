import React, { useEffect, useState } from 'react';

interface GlitchTextProps {
  text: string;
  className?: string;
  delay?: number;
}

const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()<>/[]{}";

export const GlitchText: React.FC<GlitchTextProps> = ({ text, className = "", delay = 0 }) => {
  const [displayText, setDisplayText] = useState(text);
  const [isAnimating, setIsAnimating] = useState(false);

  useEffect(() => {
    let timeoutId: ReturnType<typeof setTimeout>;
    let intervalId: ReturnType<typeof setInterval>;

    timeoutId = setTimeout(() => {
      let iter = 0;
      intervalId = setInterval(() => {
        setDisplayText((prev) =>
          prev
            .split("")
            .map((letter, index) => {
              if (index < iter) return text[index] || "";
              return chars[Math.floor(Math.random() * chars.length)];
            })
            .join("")
        );

        if (iter >= text.length) {
          clearInterval(intervalId);
          setDisplayText(text);
        }
        iter += 1 / 2.5;
      }, 30);
    }, delay);

    return () => {
      clearTimeout(timeoutId);
      clearInterval(intervalId);
    };
  }, [text, delay]);

  const handleHover = () => {
    if (isAnimating) return;
    setIsAnimating(true);
    let iter = 0;
    const interval = setInterval(() => {
      setDisplayText((prev) =>
        prev
          .split("")
          .map((letter, index) => {
            if (index < iter) return text[index] || "";
            return chars[Math.floor(Math.random() * chars.length)];
          })
          .join("")
      );

      if (iter >= text.length) {
        clearInterval(interval);
        setDisplayText(text);
        setIsAnimating(false);
      }
      iter += 1 / 2; // Faster on hover
    }, 25);
  };

  return (
    <span
      onMouseEnter={handleHover}
      className={`inline-block font-mono cursor-default select-none ${className}`}
    >
      {displayText}
    </span>
  );
};
