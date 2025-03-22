"use client"

import { useCallback } from 'react'
import { SubscriptionTiers } from '@/types/auth'  
import { useGoData } from '@/context/GoDataContext'

/**
 * Hook for accessing user authentication and feature flags
 */
export function useAuth() {
  const { user, features } = useGoData()
  
  // Check if a feature is enabled for the current user
  const hasFeature = (featureName: string): boolean => {
    return !!features?.[featureName]
  }
  
  // Check if user is logged in
  const isLoggedIn = !!user?.isLoggedIn
  
  // Get user tier
  const userTier = user?.tier || 'free'
  
  // Get user email
  const userEmail = user?.email || ''
  
  // Get Go backend status
  const isGoBackend = !!features?.goBackend
  
  /**
   * Check if the user's tier meets the minimum required tier
   * Tier order: guest < free < supporter < premium
   */
  const hasTier = (requiredTier: string): boolean => {
    if (!isLoggedIn) return false
    const tiers = Object.keys(SubscriptionTiers)
    const userIndex = tiers.indexOf(userTier)
    const requiredIndex = tiers.indexOf(requiredTier)
    return userIndex >= requiredIndex && requiredIndex !== -1
  }
  
  // Logout function
  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      window.location.href = '/'
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }
  
  return {
    isLoggedIn,
    userTier,
    userEmail,
    hasFeature,
    hasTier,
    isGoBackend,
    logout
  }
}

export default useAuth;