/**
 * Utilities to bridge Go backend with Next.js frontend
 * These utilities help extract data from Go templates and make them available to React components
 */

/**
 * Extract Go template variables from the DOM
 * Goes template embeds data as data attributes or hidden fields
 */
export function extractGoTemplateVars() {
    if (typeof window === 'undefined') {
      return {}
    }
    
    // Some Go implementations store data in meta tags
    const metaData: Record<string, string> = {};
    const metaTags = document.querySelectorAll('meta[name^="go-"]');
    metaTags.forEach(tag => {
      const name = tag.getAttribute('name')?.replace('go-', '');
      const content = tag.getAttribute('content');
      if (name && content) {
        metaData[name] = content;
      }
    });
    
    // Some Go implementations store data in hidden input fields
    const hiddenInputs = document.querySelectorAll('input[type="hidden"][name^="go-"]');
    hiddenInputs.forEach(input => {
      const name = (input as HTMLInputElement).name.replace('go-', '');
      const value = (input as HTMLInputElement).value;
      metaData[name] = value;
    });
    
    // Some implementations use data attributes on the body or a specific div
    const dataContainer = document.querySelector('[data-go-vars]') || document.body;
    if (dataContainer) {
      const dataAttrs = dataContainer.getAttributeNames().filter(name => name.startsWith('data-go-'));
      dataAttrs.forEach(attr => {
        const name = attr.replace('data-go-', '');
        const value = dataContainer.getAttribute(attr);
        if (value) {
          metaData[name] = value;
        }
      });
    }
    
    // Extract embedded JSON data if present
    const jsonScript = document.getElementById('go-template-data');
    if (jsonScript && jsonScript.textContent) {
      try {
        const jsonData = JSON.parse(jsonScript.textContent);
        Object.assign(metaData, jsonData);
      } catch (e) {
        console.error('Failed to parse embedded JSON data', e);
      }
    }
    
    return metaData;
  }
  
  /**
   * Initialize global variables from Go template for React components to use
   * Go templates may inject important data like user authentication, permissions, etc.
   */
  export function initializeFromGoTemplate() {
    if (typeof window === 'undefined') {
      return;
    }
    
    const templateVars = extractGoTemplateVars();
    
    // Set up auth variables
    window.__USER_EMAIL__ = templateVars['user-email'] || '';
    window.__USER_TIER__ = templateVars['user-tier'] || '';
    window.__IS_LOGGED_IN__ = templateVars['is-logged-in'] || 'false';
    
    // Set up feature flags
    const featureFlags: Record<string, string> = {};
    Object.keys(templateVars).forEach(key => {
      if (key.startsWith('feature-')) {
        const featureName = key.replace('feature-', '');
        featureFlags[featureName] = templateVars[key];
      }
    });
    window.__FEATURE_FLAGS__ = JSON.stringify(featureFlags);
    
    // Log initialization in dev mode
    if (process.env.NODE_ENV === 'development') {
      console.log('Initialized from Go template:', {
        auth: {
          email: window.__USER_EMAIL__,
          tier: window.__USER_TIER__,
          isLoggedIn: window.__IS_LOGGED_IN__
        },
        features: featureFlags
      });
    }
  }
  
  /**
   * Parse search parameters from URL in Go-compatible format
   */
  export function parseSearchParams(): Record<string, string | string[]> {
    if (typeof window === 'undefined') {
      return {};
    }
    
    const params = new URLSearchParams(window.location.search);
    const result: Record<string, string | string[]> = {};
    
    // Go's HTTP package handles duplicate keys as arrays
    params.forEach((value, key) => {
      if (key in result) {
        // If already exists, convert to array or add to existing array
        if (Array.isArray(result[key])) {
          (result[key] as string[]).push(value);
        } else {
          result[key] = [result[key] as string, value];
        }
      } else {
        result[key] = value;
      }
    });
    
    return result;
  }
  
  /**
   * Call a Go backend function safely
   * This is useful for when Go injects functions into the window object
   */
  export function callGoFunction<T>(functionName: string, ...args: any[]): T | undefined {
    if (typeof window === 'undefined') {
      return undefined;
    }
    
    const fn = (window as any)[functionName];
    if (typeof fn === 'function') {
      try {
        return fn(...args) as T;
      } catch (error) {
        console.error(`Error calling Go function ${functionName}:`, error);
        return undefined;
      }
    } else {
      console.warn(`Go function ${functionName} not found`);
      return undefined;
    }
  }
  
  /**
   * Inject React components into Go template placeholders
   * This is useful for gradually migrating Go templates to React
   */
  export function injectReactComponents(componentMap: Record<string, React.ComponentType<any>>) {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }
    
    import('react-dom/client').then(({ createRoot }) => {
      Object.entries(componentMap).forEach(([selector, Component]) => {
        const containers = document.querySelectorAll(selector);
        containers.forEach(container => {
          // Extract data attributes to pass as props
          const props: Record<string, any> = {};
          Array.from(container.attributes)
            .filter(attr => attr.name.startsWith('data-'))
            .forEach(attr => {
              const propName = attr.name
                .replace('data-', '')
                // Convert kebab-case to camelCase
                .replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
                
              // Try to parse as JSON if possible
              try {
                props[propName] = JSON.parse(attr.value);
              } catch {
                props[propName] = attr.value;
              }
            });
            
          // Create React root and render component
          const root = createRoot(container);
          root.render(<Component {...props} />);
        });
      });
    });
  }
  
  /**
   * Get a value from the Go backend
   * This is useful for accessing values injected by Go templates
   */
  export function getGoValue<T>(propertyName: string, defaultValue: T): T {
    if (typeof window === 'undefined') {
      return defaultValue;
    }
    
    const value = (window as any)[propertyName];
    return value !== undefined ? value as T : defaultValue;
  }
  
  /**
   * Check if the page is rendered by the Go backend
   * This is useful for conditional logic based on whether we're in Go or Next.js mode
   */
  export function isGoBackend(): boolean {
    if (typeof window === 'undefined') {
      return false;
    }
    
    // Check for specific Go-injected flags
    return !!(
      (window as any).__GO_VERSION__ || 
      (window as any).__HASH__ ||
      document.querySelector('meta[name="go-version"]')
    );
  }
  
  export default {
    extractGoTemplateVars,
    initializeFromGoTemplate,
    parseSearchParams,
    callGoFunction,
    injectReactComponents,
    getGoValue,
    isGoBackend
  };