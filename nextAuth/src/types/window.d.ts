// Type definitions for Window interface extensions

interface Window {
  // Authentication-related
  __USER_EMAIL__?: string;
  __USER_TIER__?: string;
  __IS_LOGGED_IN__?: boolean;
  __FEATURE_FLAGS__?: Record<string, boolean>;
  
  // Go-specific functions
  autocomplete?: (id: string, value: string) => void;
  copyAndBlink?: (id: string) => void;
  getLastSold: (uuid: string) => void;
  filterPageContent: () => void;
  loadForm: (formId: string, storageKey: string) => void;
  saveForm: (formId: string, storageKey: string) => void;
  clearForm: (storageKey: string) => void;
  selectAll: (storageKey: string) => void;
  loadRadio: (radioId: string, storageKey: string) => void;
  saveRadio: (radioId: string, storageKey: string) => void;
  loadDropdown: (dropdownId: string, storageKey: string) => void;
  saveDropdown: (dropdownId: string, storageKey: string) => void;
  submit_go_form?: (formId: string) => void;
  filter_content?: (id: string, q: string) => void;
  update_auth?: (email: string, tier: string) => void;
  apply_filter?: (filter: string, value: string) => void;
  remove_from_table?: (id: string) => void;
  
  // Search functionality
  search_cards?: (query: string) => Promise<any>;
  search_sealed?: (query: string) => Promise<any>;
  
  // Chart-related functions
  Chart?: {
    new(ctx: CanvasRenderingContext2D, config: any): any;
  };
  get_chart_options?: (chartId: string) => any;
  
  // Price-related functions
  tcg_market_price?: (searchQuery: string) => Promise<number>;
  
  // Other utility functions
  getShopifyInstance?: () => any;
  createWidget?: (container: HTMLElement, options: any) => any;
} 