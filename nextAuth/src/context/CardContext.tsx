"use client"

import React, { createContext, useState, useContext, useCallback, ReactNode } from 'react'

// Define the context state interface
interface CardContextState {
  // Card image and details
  firstImg: string
  firstPrint: string
  firstProduct: string
  
  // Chart and display options
  chartID: string
  isSealed: boolean
  
  // UI state
  isFilterPanelOpen: boolean
}

// Define context actions interface
interface CardContextActions {
  setFirstImg: (img: string) => void
  setFirstPrint: (print: string) => void
  setFirstProduct: (product: string) => void
  setChartID: (id: string) => void
  setIsSealed: (isSealed: boolean) => void
  toggleFilterPanel: () => void
  closeFilterPanel: () => void
  openFilterPanel: () => void
}

// Combined context type
type CardContextType = CardContextState & CardContextActions

// Create the context with a default value
const CardContext = createContext<CardContextType | undefined>(undefined)

// Provider props interface
interface CardContextProviderProps {
  children: ReactNode
  initialState?: Partial<CardContextState>
}

// Create a provider component
export const CardContextProvider: React.FC<CardContextProviderProps> = ({ 
  children, 
  initialState = {} 
}) => {
  // Initialize state with default values or provided initialState
  const [state, setState] = useState<CardContextState>({
    firstImg: '',
    firstPrint: '',
    firstProduct: '',
    chartID: '',
    isSealed: false,
    isFilterPanelOpen: false,
    ...initialState
  })
  
  // Define actions as callbacks to prevent unnecessary re-renders
  const setFirstImg = useCallback((img: string) => {
    setState(prev => ({ ...prev, firstImg: img }))
  }, [])
  
  const setFirstPrint = useCallback((print: string) => {
    setState(prev => ({ ...prev, firstPrint: print }))
  }, [])
  
  const setFirstProduct = useCallback((product: string) => {
    setState(prev => ({ ...prev, firstProduct: product }))
  }, [])
  
  const setChartID = useCallback((id: string) => {
    setState(prev => ({ ...prev, chartID: id }))
  }, [])
  
  const setIsSealed = useCallback((isSealed: boolean) => {
    setState(prev => ({ ...prev, isSealed }))
  }, [])
  
  const toggleFilterPanel = useCallback(() => {
    setState(prev => ({ ...prev, isFilterPanelOpen: !prev.isFilterPanelOpen }))
  }, [])
  
  const closeFilterPanel = useCallback(() => {
    setState(prev => ({ ...prev, isFilterPanelOpen: false }))
  }, [])
  
  const openFilterPanel = useCallback(() => {
    setState(prev => ({ ...prev, isFilterPanelOpen: true }))
  }, [])
  
  // Combine state and actions to provide context value
  const contextValue: CardContextType = {
    ...state,
    setFirstImg,
    setFirstPrint,
    setFirstProduct,
    setChartID,
    setIsSealed,
    toggleFilterPanel,
    closeFilterPanel,
    openFilterPanel
  }
  
  return (
    <CardContext.Provider value={contextValue}>
      {children}
    </CardContext.Provider>
  )
}

// Custom hook to use the card context
export function useCardContext() {
  const context = useContext(CardContext)
  
  if (context === undefined) {
    throw new Error('useCardContext must be used within a CardContextProvider')
  }
  
  return context
}

export default CardContext