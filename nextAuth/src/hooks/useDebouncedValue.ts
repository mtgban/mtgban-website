"use client"

import { useState, useEffect } from 'react'

/**
 * Hook that returns a debounced version of the provided value
 * @param value The value to debounce
 * @param delay The delay in milliseconds
 */
export function useDebouncedValue<T>(value: T, delay: number = 300): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value)
  
  useEffect(() => {
    // Update debounced value after specified delay
    const timeoutId = setTimeout(() => {
      setDebouncedValue(value)
    }, delay)
    
    // Cancel the timeout if value changes or component unmounts
    return () => {
      clearTimeout(timeoutId)
    }
  }, [value, delay])
  
  return debouncedValue
}

export default useDebouncedValue