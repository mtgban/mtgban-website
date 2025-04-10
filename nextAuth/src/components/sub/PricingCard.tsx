'use client';

import React, { useState, useRef, useEffect } from "react";

interface RenderProps {
    handleSubscribe: () => Promise<void>;
    isAnimating: boolean;
}

interface PricingCardProps {
  children: React.ReactNode | ((props: RenderProps) => React.ReactNode);
  onSubscribeClick: () => Promise<void>;
  isActive?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export default function PricingCard({
  children,
  onSubscribeClick,
  isActive = false,
  className = '',
  style = {},
}: PricingCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);

  useEffect(() => {
    let currentCard: HTMLElement | null = null;
    let animationFrameId: number | null = null;
    let lastMousePos = { x: 0, y: 0 };

    const updateCardEffect = () => {
      if (!cardRef.current) return;
      const rect = cardRef.current.getBoundingClientRect();
      const x = lastMousePos.x - rect.left;
      const y = lastMousePos.y - rect.top;
      cardRef.current.style.setProperty("--mouse-x", `${x}px`);
      cardRef.current.style.setProperty("--mouse-y", `${y}px`);
      setMousePosition({ x, y });
    };

    const handleMouseMove = (e: MouseEvent) => {
      if (isAnimating) return;
      lastMousePos = { x: e.clientX, y: e.clientY };
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
      animationFrameId = requestAnimationFrame(updateCardEffect);
    };

    const handleMouseEnter = () => {
      if (!cardRef.current || isAnimating) return;
      currentCard = cardRef.current;
      setIsHovered(true);
    };

    const handleMouseLeave = () => {
      if (!cardRef.current || isAnimating) return;
      currentCard = null;
      setIsHovered(false);

      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
        animationFrameId = null;
      }
    };

    if (cardRef.current) {
      cardRef.current.addEventListener("mouseenter", handleMouseEnter);
      cardRef.current.addEventListener("mouseleave", handleMouseLeave);
      cardRef.current.addEventListener("mousemove", handleMouseMove);
    }

    return () => {
      if (cardRef.current) {
        cardRef.current.removeEventListener("mouseenter", handleMouseEnter);
        cardRef.current.removeEventListener("mouseleave", handleMouseLeave);
        cardRef.current.removeEventListener("mousemove", handleMouseMove);
      }

      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
    };
  }, [isAnimating]);

  const handleSubscribe = async () => {
    setIsAnimating(true);
    setIsHovered(false);

    await new Promise((resolve) => setTimeout(resolve, 1500));
    await onSubscribeClick();
    setIsAnimating(false);
  };

  return (
    <div 
      ref={cardRef}
      className={`auth-container visible ${isActive ? 'active-plan' : ''} ${className}`}
      style={{
        transition: 'all 0.5s var(--transition-smooth)',
        transform: isHovered && !isAnimating ? 'translateY(-5px) scale(1.02)' : '',
        ...style
      }}
    >
      {isActive && (
        <div style={{
          position: 'absolute',
          top: '-15px',
          right: '-15px',
          background: 'var(--primary-gradient)',
          color: 'white',
          padding: '0.5rem 1rem',
          borderRadius: 'var(--border-radius)',
          fontWeight: 'bold',
          boxShadow: 'var(--box-shadow)',
          zIndex: 10,
          animation: 'pulseGlow 3s infinite alternate'
        }}>
          Current Plan
        </div>
      )}
      
      {/* Mouse follow effect */}
      {isHovered && !isAnimating && (
        <div
          className="absolute pointer-events-none"
          style={{
            left: `${mousePosition.x}px`,
            top: `${mousePosition.y}px`,
            width: '20rem',
            height: '20rem',
            transform: 'translate(-50%, -50%)',
            background: `radial-gradient(circle at center,
              rgba(var(--accent-hue), 90%, 55%, 0.3) 0%,
              rgba(var(--accent-hue), 90%, 55%, 0.1) 30%,
              transparent 70%
            )`,
            transition: 'opacity 0.2s ease',
            zIndex: 0
          }}
        />
      )}

      {/* Subscribe click animation */}
      {isAnimating && (
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background: `radial-gradient(circle at center,
              rgba(var(--primary-hue), 90%, 65%, 0.2) 0%,
              rgba(var(--primary-hue), 90%, 65%, 0.15) 50%,
              transparent 70%
            )`,
            animation: 'pulseGlow 2s infinite alternate'
          }}
        />
      )}

      {/* Content wrapper */}
      <div className="relative z-10">
        {typeof children === 'function'
          ? children({ handleSubscribe, isAnimating })
          : children
        }
      </div>
    </div>
  );
}