'use client';

import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { debounce } from 'lodash';
import AccessLink from './AccessLink';

// Types
type Point = { x: number; y: number };


interface Edge {
    id: string;
    start: Point;
    end: Point;
    length: number;
    startDistance: number;
    endDistance: number;
}

interface Hexagon {
    id: string;
    centerX: number;
    centerY: number;
    vertices: Point[];
    edges: Edge[];
    perimeter: number;
    pathData: string;
}

interface Pulse {
    id: number;
    hexId: string;
    startDistance: number;
    progress: number;
    fadeProgress: number;
}

// Constants
const CONSTANTS = {
    size: 210,
    sqrt3: Math.sqrt(3),
    pi3: Math.PI / 3,
    pi6: Math.PI / 6,
    cosAngles: Array.from({ length: 6 }, (_, i) => Math.cos(Math.PI / 3 * i - Math.PI / 6)),
    sinAngles: Array.from({ length: 6 }, (_, i) => Math.sin(Math.PI / 3 * i - Math.PI / 6)),
    pulseConfig: {
        width: 0.15,
        speed: 0.007,
        fadeThreshold: 0.7,
        fadeMultiplier: 3.33,
        maxActive: 3,
        mouseThreshold: 5,
        spawnDelay: {
            min: 1500,
            random: 1000
        }
    }
} as const;

// Compute derived constants
const DERIVED = {
    width: CONSTANTS.size * CONSTANTS.sqrt3,
    height: CONSTANTS.size * 2,
    verticalSpacing: CONSTANTS.size * 2 * 0.75,
    horizontalSpacing: CONSTANTS.size * CONSTANTS.sqrt3
} as const;

// Utility functions
const generateHexagonGeometry = (centerX: number, centerY: number, rowCol: string): Hexagon => {
    const vertices: Point[] = [];
    let pathData = '';

    // Compute vertices using pre-calculated angles
    for (let i = 0; i < 6; i++) {
        const x = centerX + CONSTANTS.size * CONSTANTS.cosAngles[i];
        const y = centerY + CONSTANTS.size * CONSTANTS.sinAngles[i];
        vertices.push({ x, y });
        pathData += `${i === 0 ? 'M' : 'L'}${x},${y}`;
    }
    pathData += 'Z';

    // Generate edges with accumulated distances
    let totalPerimeter = 0;
    const edges = vertices.map((start, i) => {
        const end = vertices[(i + 1) % 6];
        const length = Math.hypot(end.x - start.x, end.y - start.y);
        const edge = {
            id: `${rowCol}-${i}`,
            start,
            end,
            length,
            startDistance: totalPerimeter,
            endDistance: totalPerimeter + length
        };
        totalPerimeter += length;
        return edge;
    });

    return {
        id: rowCol,
        centerX,
        centerY,
        vertices,
        edges,
        perimeter: totalPerimeter,
        pathData
    };
};

const getGlowColor = (progress: number, intensity: number): string => {
    const green = Math.min(255, Math.floor(44 + (progress * 151)));
    return `rgba(255, ${green}, 0, ${intensity})`;
};

// Main component
export default function HexagonalBackground() {
    const [hexagons, setHexagons] = useState<Hexagon[]>([]);
    const [pulses, setPulses] = useState<Pulse[]>([]);
    const [activePulseHexagons, setActivePulseHexagons] = useState<Set<string>>(new Set());
    const [isVisible, setIsVisible] = useState(true);

    const frameRef = useRef<number | undefined>(undefined);
    const lastTimeRef = useRef<number>(0);
    const containerRef = useRef<HTMLDivElement>(null);

    // Intersection Observer setup
    useEffect(() => {
        const observer = new IntersectionObserver(
            ([entry]) => setIsVisible(entry.isIntersecting),
            { threshold: 0.1 }
        );

        if (containerRef.current) {
            observer.observe(containerRef.current);
        }

        return () => observer.disconnect();
    }, []);

    // Grid generation with resize handling
    const generateGrid = useCallback(() => {
        const { innerWidth, innerHeight } = window;
        const rows = Math.ceil(innerHeight / DERIVED.verticalSpacing) + 2;
        const cols = Math.ceil(innerWidth / DERIVED.horizontalSpacing) + 2;

        const newHexagons = Array.from({ length: rows * cols }, (_, index) => {
            const row = Math.floor(index / cols);
            const col = index % cols;
            const offset = row % 2 === 0 ? 0 : DERIVED.horizontalSpacing / 2;
            const centerX = (col * DERIVED.horizontalSpacing) + offset;
            const centerY = row * DERIVED.verticalSpacing;

            return generateHexagonGeometry(centerX, centerY, `${row}-${col}`);
        });

        setHexagons(newHexagons);
    }, []);

    useEffect(() => {
        generateGrid();
        const handleResize = debounce(generateGrid, 250);
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, [generateGrid]);

    // Pulse animation management
    const updatePulses = useCallback((timestamp: number) => {
        if (!isVisible) return;

        const deltaTime = timestamp - lastTimeRef.current;
        lastTimeRef.current = timestamp;

        setPulses(currentPulses => {
            const progressIncrement = CONSTANTS.pulseConfig.speed * (deltaTime / 16.67);

            const remainingPulses = currentPulses
                .map(pulse => ({
                    ...pulse,
                    progress: pulse.progress + progressIncrement,
                    fadeProgress: pulse.progress > CONSTANTS.pulseConfig.fadeThreshold
                        ? (pulse.progress - CONSTANTS.pulseConfig.fadeThreshold) * CONSTANTS.pulseConfig.fadeMultiplier
                        : 0
                }))
                .filter(pulse => pulse.progress < 1);

            setActivePulseHexagons(new Set(remainingPulses.map(p => p.hexId)));
            return remainingPulses;
        });

        frameRef.current = requestAnimationFrame(updatePulses);
    }, [isVisible]);

    useEffect(() => {
        if (isVisible) {
            frameRef.current = requestAnimationFrame(updatePulses);
        }
        return () => {
            if (frameRef.current) cancelAnimationFrame(frameRef.current);
        };
    }, [isVisible, updatePulses]);

    // Random pulse generation
    const createRandomPulse = useCallback(() => {
        if (!isVisible || activePulseHexagons.size >= CONSTANTS.pulseConfig.maxActive) return;

        const availableHexagons = hexagons.filter(hex => !activePulseHexagons.has(hex.id));
        if (availableHexagons.length === 0) return;

        const hex = availableHexagons[Math.floor(Math.random() * availableHexagons.length)];
        const edge = hex.edges[Math.floor(Math.random() * 6)];
        const param = Math.random();

        setPulses(prev => [...prev, {
            id: Date.now(),
            hexId: hex.id,
            startDistance: edge.startDistance + (param * edge.length),
            progress: 0,
            fadeProgress: 0
        }]);
    }, [hexagons, activePulseHexagons, isVisible]);

    useEffect(() => {
        if (!isVisible) return;

        const scheduleNext = () => {
            const delay = CONSTANTS.pulseConfig.spawnDelay.min +
                Math.random() * CONSTANTS.pulseConfig.spawnDelay.random;
            return setTimeout(() => {
                createRandomPulse();
                timeoutRef.current = scheduleNext();
            }, delay);
        };

        const timeoutRef = { current: scheduleNext() };
        return () => clearTimeout(timeoutRef.current);
    }, [createRandomPulse, isVisible]);

    // Mouse interaction
    const handleMouseMove = useCallback((e: React.MouseEvent) => {
        const { clientX, clientY } = e;

        hexagons.forEach(hexagon => {
            if (activePulseHexagons.has(hexagon.id)) return;

            for (const edge of hexagon.edges) {
                const { start, end } = edge;
                const A = clientX - start.x;
                const B = clientY - start.y;
                const C = end.x - start.x;
                const D = end.y - start.y;

                const dot = A * C + B * D;
                const lenSq = C * C + D * D;
                if (lenSq === 0) continue;

                const param = Math.max(0, Math.min(1, dot / lenSq));
                const hitX = start.x + param * C;
                const hitY = start.y + param * D;

                const distance = Math.hypot(clientX - hitX, clientY - hitY);

                if (distance < CONSTANTS.pulseConfig.mouseThreshold) {
                    setPulses(prev => [...prev, {
                        id: Date.now(),
                        hexId: hexagon.id,
                        startDistance: edge.startDistance + (param * edge.length),
                        progress: 0,
                        fadeProgress: 0
                    }]);
                    break;
                }
            }
        });
    }, [hexagons, activePulseHexagons]);

    // Memoized render functions
    const renderPulse = useMemo(() => (pulse: Pulse, hexagon: Hexagon) => {
        const pulseWidth = hexagon.perimeter * CONSTANTS.pulseConfig.width;
        const intensity = Math.max(0, 1 - pulse.fadeProgress);
        const glowColor = getGlowColor(pulse.progress, intensity);
        const baseProps = {
            d: hexagon.pathData,
            fill: "none",
            stroke: glowColor,
            strokeWidth: 2 + intensity * 2,
            strokeDasharray: `${pulseWidth} ${hexagon.perimeter}`,
            style: intensity > 0 ? {
                filter: `drop-shadow(0 0 ${intensity * 8}px ${glowColor})`
            } : undefined
        };

        return (
            <React.Fragment key={pulse.id}>
                <path
                    {...baseProps}
                    strokeDashoffset={-pulse.startDistance - (pulse.progress * hexagon.perimeter * 0.5)}
                />
                <path
                    {...baseProps}
                    strokeDashoffset={-pulse.startDistance + (pulse.progress * hexagon.perimeter * 0.5)}
                />
            </React.Fragment>
        );
    }, []);

    const renderHexagon = useMemo(() => (hexagon: Hexagon) => {
        const activePulses = pulses.filter(p => p.hexId === hexagon.id);

        return (
            <g key={hexagon.id}>
                <path
                    d={hexagon.pathData}
                    fill="#000000"
                    stroke="rgba(0, 0, 0, 0)"
                    strokeWidth="1"
                />
                {activePulses.map(pulse => renderPulse(pulse, hexagon))}
            </g>
        );
    }, [pulses, renderPulse]);

    return (
        <div ref={containerRef} className="relative w-screen h-screen bg-black overflow-hidden">
            <div
                className="absolute inset-0 w-full h-full"
                onMouseMove={handleMouseMove}
            >
                <svg className="w-full h-full">
                    {hexagons.map(renderHexagon)}
                </svg>
            </div>

            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <section className="pricing-section w-full">
                    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div className="flex flex-col items-center space-y-16">
                            <h1 className="gradient-text text-3xl font-extrabold text-center sm:text-5xl pointer-events-auto">
                                MTGBAN
                            </h1>
                            <p className="text-lg text-zinc-400 text-center sm:text-2xl max-w-3xl pointer-events-auto">
                                Join an elite network of TCG market professionals. <br />
                                Utilize advanced data analysis, granular market coverage and keen industry insight
                                to reveal opportunity others overlook.<br /> Whether you're scaling up or starting out,
                                our platform delivers proven value at every level.
                            </p>
                            <AccessLink />
                        </div>
                    </div>
                </section>
            </div>
        </div>
    );
}