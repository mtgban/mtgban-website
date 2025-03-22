import React, { useState, useEffect, useRef } from "react"
import Link from "next/link"
import { useRouter } from "next/router"
import { useGoData } from "@/context/GoDataContext"
import { useAuth } from "@/hooks/useAuth"
import { NavItem } from "@/types/pageVars"

// Define types for navigation links from backend
interface NavLink {
  Name: string   // Go backend uses uppercase field names
  URL: string
  Icon?: string
  RequiresAuth?: boolean
}

const Navbar: React.FC = () => {
  const router = useRouter()
  const { pageData } = useGoData()
  const { isLoggedIn, userTier, logout } = useAuth()
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [isDropdownOpen, setIsDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Get navigation links from Go backend
  const navLinks = pageData?.Nav || []
  const extraNavLinks = pageData?.ExtraNav || []

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false)
      }
    }

    document.addEventListener("mousedown", handleClickOutside)
    return () => {
      document.removeEventListener("mousedown", handleClickOutside)
    }
  }, [])

  // Close menu when route changes
  useEffect(() => {
    const handleRouteChange = () => {
      setIsMenuOpen(false)
    }

    router.events.on("routeChangeComplete", handleRouteChange)
    return () => {
      router.events.off("routeChangeComplete", handleRouteChange)
    }
  }, [router.events])

  return (
    <nav className="navbar" role="navigation" aria-label="Main Navigation">
      <div className="navbar-container">
        {/* Logo */}
        <Link href="/" className="navbar-logo" aria-label="MTGBAN Home">
          MTGBAN
        </Link>

        {/* Mobile Menu Toggle */}
        <button
          className="mobile-menu-toggle"
          onClick={() => setIsMenuOpen(!isMenuOpen)}
          aria-expanded={isMenuOpen}
          aria-controls="main-menu"
          aria-label={isMenuOpen ? "Close menu" : "Open menu"}
        >
          {isMenuOpen ? "✕" : "☰"}
        </button>

        {/* Main Navigation */}
        <div id="main-menu" className={`nav-menu ${isMenuOpen ? "active" : ""}`}>
          <ul className="nav-links">
            {navLinks.map((link: NavItem) => (
              <li key={link.Link} className="nav-item">
                <Link 
                  href={link.Link}
                  className={`nav-link ${router.pathname === link.Link ? "active" : ""}`}
                  aria-current={router.pathname === link.Link ? "page" : undefined}
                >
                  {link.Short && <span className="nav-icon">{link.Short}</span>}
                  <span className="nav-text">{link.Name}</span>
                </Link>
              </li>
            ))}

            {/* Extra nav links, often for authenticated users only */}
            {extraNavLinks.length > 0 && (
              <>
                {extraNavLinks.map((link: NavItem) => (
                  <li key={link.Link} className="nav-item extra-nav-item">
                    <Link 
                      href={link.Link}
                      className={`nav-link ${router.pathname === link.Link ? "active" : ""}`}
                      aria-current={router.pathname === link.Link ? "page" : undefined}
                    >
                      {link.Short && <span className="nav-icon">{link.Short}</span>}
                      <span className="nav-text">{link.Name}</span>
                    </Link>
                  </li>
                ))}
              </>
            )}
          </ul>

          {/* User section */}
          <div className="nav-user">
            {isLoggedIn ? (
              <div className="user-dropdown" ref={dropdownRef}>
                <button
                  className="user-button"
                  onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                  aria-expanded={isDropdownOpen}
                  aria-haspopup="true"
                  aria-controls="user-menu"
                >
                  <span className="user-tier">{userTier}</span>
                  <span className="user-icon">👤</span>
                </button>
                
                {isDropdownOpen && (
                  <div id="user-menu" className="dropdown-menu">
                    <Link href="/profile" className="dropdown-item">Profile</Link>
                    <Link href="/settings" className="dropdown-item">Settings</Link>
                    <Link href="/subscription" className="dropdown-item">Subscription</Link>
                    <hr className="dropdown-divider" />
                    <button 
                      className="dropdown-item logout-button" 
                      onClick={logout}
                    >
                      Log Out
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="auth-buttons">
                <Link href="/login" className="btn login">Log In</Link>
                <Link href="/signup" className="btn signup">Sign Up</Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  )
}

export default Navbar