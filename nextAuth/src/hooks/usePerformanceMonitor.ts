"use client"

import { useEffect, useRef } from 'react'

interface PerformanceMetrics {
  componentName: string
  renderTime?: number
  interactionTime?: number
}

/**
 * Hook to monitor component performance
 * @param componentName Name of the component being monitored
 * @param enabled Whether monitoring is enabled
 */
export function usePerformanceMonitor(
  componentName: string, 
  enabled: boolean = process.env.NODE_ENV === 'development'
): {
  measureRender: () => void
  measureInteraction: (name: string) => () => void
} {
  const startTimeRef = useRef<number>(0)
  const metricsRef = useRef<PerformanceMetrics>({ componentName })

  // Reset timer on each render
  useEffect(() => {
    if (!enabled) return
    
    startTimeRef.current = performance.now()
    
    return () => {
      const renderTime = performance.now() - startTimeRef.current
      metricsRef.current.renderTime = renderTime
      
      // Log render time for component
      console.log(`[Performance] ${componentName} rendered in ${renderTime.toFixed(2)}ms`)
    }
  })

  // Function to measure interaction time
  const measureInteraction = (name: string) => {
    if (!enabled) return () => {}
    
    const startTime = performance.now()
    
    return () => {
      const duration = performance.now() - startTime
      metricsRef.current.interactionTime = duration
      
      // Log interaction time
      console.log(`[Performance] ${componentName} - ${name} completed in ${duration.toFixed(2)}ms`)
    }
  }
  
  // Function to measure render time
  const measureRender = () => {
    if (!enabled) return
    
    const renderTime = performance.now() - startTimeRef.current
    console.log(`[Performance] ${componentName} render method executed in ${renderTime.toFixed(2)}ms`)
  }

  return { measureRender, measureInteraction }
}

export default usePerformanceMonitor