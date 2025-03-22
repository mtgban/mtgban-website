"use client"

import * as React from "react"
import { useEffect, useRef } from "react"
import type { PriceChartProps } from "../../types/search"

// Fix component type
function PriceChart({ chartID, axisLabels = [], datasets = [] }: PriceChartProps) {
  const chartRef = useRef<HTMLDivElement>(null)

  // Initialize chart when component mounts
  useEffect(() => {
    // Use Chart.js injected by Go backend
    if (typeof window !== "undefined" && window.Chart && chartRef.current) {
      const canvas = document.createElement("canvas")
      canvas.id = chartID
      chartRef.current.appendChild(canvas)

      // Create chart with data from props
      new window.Chart(canvas, {
        type: "line",
        data: {
          labels: axisLabels,
          datasets: datasets.map((ds) => ({
            label: ds.name,
            data: ds.data,
            borderColor: ds.color,
            hidden: ds.hidden,
            fill: false,
            tension: 0.1,
          })),
        },
        options: window.getChartOpts?.(axisLabels.length) || {},
      })
    }

    // Clean up
    return () => {
      if (chartRef.current) {
        chartRef.current.innerHTML = ""
      }
    }
  }, [chartID, axisLabels, datasets])

  return <div className="price-chart" ref={chartRef} />
}

export default PriceChart

