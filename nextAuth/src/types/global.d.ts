// Global window properties injected by Go server
interface Window {
  // Authentication-related
  __USER_EMAIL__?: string;
  __USER_TIER__?: string;
  __IS_LOGGED_IN__?: string;
  __FEATURE_FLAGS__?: string;
  
  // Go-specific functions
  autocomplete: (form: HTMLFormElement, input: HTMLInputElement, isSealed: string) => void;
  copyAndBlink: (element: HTMLElement | null, text: string) => void;
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
  
  // Chart-related functions
  Chart: any;
  getChartOpts: (numLabels: number) => any;
  
  // Price-related functions
  tcg_market_price: (cardId: string) => number;
  
  // Types for objects provided by Go
  fs: {
    readFile: (filepath: string, options?: { encoding?: string }) => Promise<Uint8Array | string>;
  }
}

// Go backend specific types for search
interface GenericCard {
  ImageURL: string;
  Printings: string;
  Products: string;
  SetCode: string;
  Title: string;
  Name: string;
  Variant: string;
  Flag: string;
  Reserved: boolean;
  Stocks: boolean;
  SypList: boolean;
  Sealed: boolean;
  Booster: boolean;
  HasDeck: boolean;
  UUID: string;
  SearchURL: string;
  DeckboxURL: string;
  CKRestockURL: string;
  ScryfallURL: string;
  TCGId: string;
  SourceSealed: string[];
  Date: string;
  Keyrune: string;
  RarityColor: string;
  Foil: boolean;
}

interface SearchEntry {
  ScraperName: string;
  Country: string;
  URL: string;
  Price: number;
  Secondary?: number;
  Quantity: number;
  NoQuantity: boolean;
  BundleIcon: string;
  Shorthand: string;
  Ratio: number;
  Credit: number;
  ExtraValues?: {
    iqr: number;
    stdDev: number;
  }
}

interface EditionEntry {
  Name: string;
  Code: string;
  Keyrune: string;
}

interface ChartDataset {
  name: string;
  data: number[];
  hidden: boolean;
  color: string;
}

// Declare global variables used by Go template
declare const ScraperNames: Record<string, string>;
declare const colorValues: Record<string, string>;