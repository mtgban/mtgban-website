'use client'

import { useAuth } from '@/hooks/useAuth'

interface InstructionsProps {
  promoTags?: string[];
}

/**
 * Component to display search instructions and tips
 */
export default function Instructions({ promoTags = [] }: InstructionsProps) {
  const { isLoggedIn, userTier } = useAuth()
  
  return (
    <div className="search-instructions">
      <div className="instructions-card">
        <h2>Search for Magic: The Gathering Cards</h2>
        
        <div className="search-section">
          <h3>Basic Search</h3>
          <p>Enter a card name in the search box above to find prices from various stores.</p>
          <ul>
            <li>Search for <code>Lightning Bolt</code> to find all versions of that card</li>
            <li>Search for <code>Jace</code> to find all cards with "Jace" in the name</li>
            <li>Search for <code>Dominaria Booster</code> to find sealed products</li>
          </ul>
        </div>
        
        <div className="search-section">
          <h3>Advanced Search</h3>
          <p>Use search operators for more specific queries:</p>
          <ul>
            <li><code>name:"Liliana of the Veil"</code> - Exact name match</li>
            <li><code>t:goblin</code> - Search by card type</li>
            <li><code>o:flying</code> - Search oracle text for "flying"</li>
            <li><code>c:red</code> or <code>c:r</code> - Search by color</li>
            <li><code>e:dom</code> - Search in Dominaria set</li>
            <li><code>r:mythic</code> - Search by rarity</li>
          </ul>
        </div>
        
        <div className="search-section">
          <h3>Combined Search</h3>
          <p>Combine multiple operators for precision:</p>
          <ul>
            <li><code>o:destroy t:instant c:black</code> - Black instants that destroy</li>
            <li><code>t:creature c:red o:haste</code> - Red creatures with haste</li>
            <li><code>e:znr r:mythic</code> - Zendikar Rising mythics</li>
          </ul>
        </div>
        
        {promoTags && promoTags.length > 0 && (
          <div className="promo-tags">
            <h3>Popular Searches</h3>
            <div className="tags">
              {promoTags.map((tag, index) => (
                <a 
                  key={index} 
                  href={`/search?q=${encodeURIComponent(tag)}`}
                  className="tag"
                >
                  {tag}
                </a>
              ))}
            </div>
          </div>
        )}
        
        {!isLoggedIn && (
          <div className="login-prompt">
            <h3>Create an Account</h3>
            <p>Sign up for a free account to access additional features:</p>
            <ul>
              <li>Save your favorite searches</li>
              <li>Track price history</li>
              <li>Create and manage your collection</li>
            </ul>
            <div className="buttons">
              <a href="/login" className="button primary">Log In</a>
              <a href="/register" className="button secondary">Sign Up</a>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

