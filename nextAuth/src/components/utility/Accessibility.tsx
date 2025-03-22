"use client"

import React, { useEffect, useRef, ReactNode } from 'react'

/**
 * VisuallyHidden component for screen reader content
 */
export const VisuallyHidden: React.FC<{ children: ReactNode }> = ({ children }) => {
  return (
    <span 
      className="sr-only" 
      style={{
        border: 0,
        clip: 'rect(0 0 0 0)',
        height: '1px',
        margin: '-1px',
        overflow: 'hidden',
        padding: 0,
        position: 'absolute',
        width: '1px',
        whiteSpace: 'nowrap',
        wordWrap: 'normal'
      }}
    >
      {children}
    </span>
  )
}

interface LiveRegionProps {
  children: ReactNode;
  ariaLive?: 'polite' | 'assertive' | 'off';
  ariaAtomic?: boolean;
  ariaRelevant?: 'additions' | 'additions text' | 'all' | 'removals' | 'text';
  role?: 'status' | 'alert' | 'log' | 'timer' | 'marquee' | 'progressbar';
  className?: string;
}

/**
 * Component that creates a live region for screen readers
 * to announce changes and updates to the user
 */
export function LiveRegion({
  children,
  ariaLive = 'polite',
  ariaAtomic = true,
  ariaRelevant = 'additions text',
  role = 'status',
  className = '',
}: LiveRegionProps) {
  return (
    <div
      className={`sr-only ${className}`}
      aria-live={ariaLive}
      aria-atomic={ariaAtomic}
      aria-relevant={ariaRelevant}
      role={role}
    >
      {children}
    </div>
  )
}

/**
 * FocusTrap component to trap focus within a modal or dialog
 */
export const FocusTrap: React.FC<{
  children: ReactNode
  active?: boolean
  initialFocus?: React.RefObject<HTMLElement>
}> = ({ children, active = true, initialFocus }) => {
  const rootRef = useRef<HTMLDivElement>(null)
  
  useEffect(() => {
    if (!active) return
    
    const root = rootRef.current
    if (!root) return
    
    // Get all focusable elements
    const focusableElements = root.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    
    if (focusableElements.length === 0) return
    
    const firstElement = focusableElements[0]
    const lastElement = focusableElements[focusableElements.length - 1]
    
    // Set initial focus if provided
    if (initialFocus && initialFocus.current) {
      initialFocus.current.focus()
    } else {
      firstElement.focus()
    }
    
    // Handle tab key to trap focus
    const handleTabKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      
      // Shift + Tab
      if (e.shiftKey) {
        if (document.activeElement === firstElement) {
          e.preventDefault()
          lastElement.focus()
        }
      } 
      // Tab
      else {
        if (document.activeElement === lastElement) {
          e.preventDefault()
          firstElement.focus()
        }
      }
    }
    
    // Store previously focused element
    const previouslyFocused = document.activeElement as HTMLElement
    
    // Add event listener
    document.addEventListener('keydown', handleTabKey)
    
    // Cleanup
    return () => {
      document.removeEventListener('keydown', handleTabKey)
      // Restore focus when component unmounts
      if (previouslyFocused) {
        previouslyFocused.focus()
      }
    }
  }, [active, initialFocus])
  
  return <div ref={rootRef}>{children}</div>
}

interface SkipLinkProps {
  href: string;
  children: ReactNode;
  className?: string;
}

/**
 * Component that provides a skip link for keyboard users
 * to bypass navigation and go directly to main content
 */
export function SkipLink({
  href,
  children,
  className = '',
}: SkipLinkProps) {
  return (
    <a
      href={href}
      className={`skip-link ${className}`}
    >
      {children}
    </a>
  )
}

/**
 * Announce function to create ARIA announcements
 */
export function createAnnouncer() {
  let announcer: HTMLElement | null = null
  
  // Create or get the announcer element
  const getAnnouncer = () => {
    if (announcer) return announcer
    
    announcer = document.createElement('div')
    announcer.setAttribute('aria-live', 'polite')
    announcer.setAttribute('aria-atomic', 'true')
    announcer.className = 'sr-only'
    document.body.appendChild(announcer)
    
    return announcer
  }
  
  // Announce a message
  const announce = (message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const announcer = getAnnouncer()
    announcer.setAttribute('aria-live', priority)
    
    // Clear previous announcement
    announcer.textContent = ''
    
    // Add new announcement after a short delay to ensure it's announced
    setTimeout(() => {
      announcer.textContent = message
    }, 50)
  }
  
  // Clear announcement
  const clear = () => {
    if (announcer) {
      announcer.textContent = ''
    }
  }
  
  // Cleanup function
  const cleanup = () => {
    if (announcer && document.body.contains(announcer)) {
      document.body.removeChild(announcer)
      announcer = null
    }
  }
  
  return { announce, clear, cleanup }
}

export const globalAnnouncer = typeof window !== 'undefined' ? createAnnouncer() : null

export default {
  VisuallyHidden,
  LiveRegion,
  FocusTrap,
  SkipLink,
  createAnnouncer,
  globalAnnouncer
}