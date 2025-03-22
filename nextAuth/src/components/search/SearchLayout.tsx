"use client"

import React, { useEffect } from 'react'
import { useRouter } from 'next/router'
import Navbar from './Navbar'
import { CardContextProvider } from '@/context/CardContext'
import { SkipLink } from '@/components/utility/Accessibility'
import usePerformanceMonitor from '@/hooks/usePerformanceMonitor'

interface SearchLayoutProps {
  children: React.ReactNode
  title?: string
  isSealed?: boolean
  initialImgUrl?: string
}

/**
 * Main layout component for search pages
 */
const SearchLayout: React.FC<SearchLayoutProps> = ({ 
  children, 
  title = "MTG Card Search",
  isSealed = false,
  initialImgUrl = ""
}) => {
  const router = useRouter()
  const { measureInteraction } = usePerformanceMonitor('SearchLayout')
  
  // Performance monitoring for page navigations
  useEffect(() => {
    const handleRouteChangeStart = () => {
      const endMeasurement = measureInteraction('route-change')
      
      const cleanup = () => {
        endMeasurement()
        router.events.off('routeChangeComplete', cleanup)
        router.events.off('routeChangeError', cleanup)
      }
      
      router.events.on('routeChangeComplete', cleanup)
      router.events.on('routeChangeError', cleanup)
    }
    
    router.events.on('routeChangeStart', handleRouteChangeStart)
    
    return () => {
      router.events.off('routeChangeStart', handleRouteChangeStart)
    }
  }, [router.events, measureInteraction])
  
  return (
    <CardContextProvider 
      initialState={{ 
        isSealed, 
        firstImg: initialImgUrl
      }}
    >
      <div className="app-container">
        <SkipLink href="#main-content">Skip to main content</SkipLink>
        
        <header className="app-header">
          <Navbar />
        </header>
        
        <main id="main-content" className="app-main">
          <h1 className="page-title">{title}</h1>
          
          <div className="content-container">
            {children}
          </div>
        </main>
        
        <footer className="app-footer">
          <div className="footer-content">
            <p>&copy; {new Date().getFullYear()} MTGBAN. All rights reserved.</p>
            <p>Card images and data &copy; Wizards of the Coast</p>
          </div>
        </footer>
      </div>
    </CardContextProvider>
  )
}

export default SearchLayout