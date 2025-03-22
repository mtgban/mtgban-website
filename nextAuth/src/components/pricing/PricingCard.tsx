"use client";

import { useState, useRef, useEffect } from "react";

interface RenderProps {
    handleSubscribe: () => Promise<void>;
    isAnimating: boolean;
}

interface PricingCardProps {
    className?: string;
    isActive?: boolean;
    onSubscribeClick: () => Promise<void>;
    children: React.ReactNode | ((props: RenderProps) => React.ReactNode);
}

const PricingCard = ({
    className = "",
    children,
    isActive = false,
    onSubscribeClick,
}: PricingCardProps) => {
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
            className={`
                pricing-card group relative overflow-hidden
                backdrop-blur-xl bg-white/10 rounded-2xl
                border border-white/20
                transition-all duration-300
                ${isActive ? "border-red-500/50" : ""}
                ${className}
            `}
        >
            {/* Mouse follow effect */}
            {isHovered && !isAnimating && (
                <div
                    className="absolute pointer-events-none transition-opacity duration-200
                                w-[20rem] h-[20rem] -translate-x-1/2 -translate-y-1/2"
                    style={{
                        left: `${mousePosition.x}px`,
                        top: `${mousePosition.y}px`,
                        background: `radial-gradient(circle at center,
                            rgba(255,215,0,0.3) 0%,
                            rgba(255,175,0,0.1) 1%,
                            transparent 70%
                        )`,
                    }}
                />
            )}

            {/* Subscribe click animation */}
            {isAnimating && (
                <div
                    className="absolute inset-0 pointer-events-none animate-glow-transform"
                    style={{
                        background: `radial-gradient(circle at center,
                            rgba(255,215,0,0.2) 0%,
                            rgba(255,0,0,0.15) 50%,
                            transparent 70%
                        )`,
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
};

export default PricingCard;
