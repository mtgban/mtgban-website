declare interface PageVars {
    Nav: NavItem[];
    ExtraNav: NavItem[];
    ShowLogin: boolean;
    Hash: string;
    Embed: {
        OEmbedURL: string;
        PageURL: string;
        Title: string;
        Contents: string;
        ImageURL: string;
        ImageCropURL: string;
        Description: string;
        RetailPrice: number;
        BuylistPrice: number;
    };
    Title: string;
    ErrorMessage: string;
    WarningMessage: string;
    InfoMessage: string;
    LastUpdate: string;
    AllKeys: string[];
    SearchQuery: string;
    SearchBest: boolean;
    SearchSort: string;
    CondKeys: string[];
    FoundSellers: { [key: string]: { [key: string]: SearchEntry[]}};
    FoundVendors: { [key: string]: { [key: string]: SearchEntry[]}};
    Metadata: { [key: string]: GenericCard};
    PromoTags: string[];
    NoSort: boolean;
    HasAvailable: boolean;
    CardBackURL: string;
    ShowUpsell: boolean;
    CanShowAll: boolean;
    CleanSearchQuery: string;
    ScraperShort: string;
    HasAffiliate: boolean;
    CanDownloadCSV: boolean;
    ShowSYP: boolean;
    Arb: Arbitrage[];
    ArbitOptKeys: string[];
    ArbitOptConfig: { [key: string]: FilterOpt};
    ArbitFilters: { [key: string]: boolean};
    ArbitOptTests: { [key: string]: boolean};
    SortOption: string;
    GlobalMode: boolean;
    ReverseMode: boolean;
    Page: string;
    Subtitle: string;
    ToC: NewspaperPage[];
    Headings: Heading[];
    Cards: GenericCard[];
    Table: string[][];
    HasReserved: boolean;
    HasStocks: boolean;
    HasSypList: boolean;
    IsOneDay: boolean;
    CanSwitchDay: boolean;
    SortDir: string;
    LargeTable: boolean;
    OffsetCards: number;
    FilterSet: string;
    Editions: string[];
    FilterRarity: string;
    Rarities: string[];
    CardHashes: string[];
    EditionsMap: { [key: string]: EditionEntry};
    PageMessage: string;
    PageType: string;
    CanFilterByPrice: boolean;
    FilterMinPrice: number;
    FilterMaxPrice: number;
    CanFilterByPercentage: boolean;
    FilterMinPercChange: number;
    FilterMaxPercChange: number;
    Sleepers: { [key: string]: string[]};
    SleepersKeys: string[];
    SleepersColors: string[];
    Headers: string[];
    OtherHeaders: string[];
    OtherTable: string[][];
    CurrentTime: string;
    Uptime: string;
    DiskStatus: string;
    MemoryStatus: string;
    LatestHash: string;
    Tiers: string[];
    DemoKey: string;
    SelectableField: boolean;
    DisableLinks: boolean;
    DisableChart: boolean;
    AxisLabels: string[];
    Datasets: (Dataset | undefined)[];
    ChartID: string;
    Alternative: string;
    StocksURL: string;
    AltEtchedId: string;
    EditionSort: string[];
    EditionList: { [key: string]: EditionEntry[]};
    IsSealed: boolean;
    IsSets: boolean;
    TotalSets: number;
    TotalCards: number;
    TotalUnique: number;
    ScraperKeys: string[];
    IndexKeys: string[];
    SellerKeys: string[];
    VendorKeys: string[];
    UploadEntries: UploadEntry[];
    IsBuylist: boolean;
    TotalEntries: { [key: string]: number};
    EnabledSellers: string[];
    EnabledVendors: string[];
    CanBuylist: boolean;
    CanChangeStores: boolean;
    RemoteLinkURL: string;
    TotalQuantity: number;
    Optimized: { [key: string]: OptimizedUploadEntry[]};
    OptimizedTotals: { [key: string]: number};
    HighestTotal: number;
    MissingCounts: { [key: string]: number};
    MissingPrices: { [key: string]: number};
    ResultPrices: { [key: string]: { [key: string]: number}};
    IsLoggedIn: boolean;
    UserEmail: string;
    UserTier: string;
}

export interface NavItem {
  Active: boolean;
  Class: string;
  Link: string;
  Name: string;
  Short: string;
  Page: string;
  AlwaysOnForDev: boolean;
  CanPOST: boolean;
  SubPages: string[];
  NoAuth: boolean;
}

export interface Arbitrage {
  Card: GenericCard
  Seller: SearchEntry
  Vendor: SearchEntry
  Profit: number
  Percentage: number
}

export interface FilterOpt {
  Name: string
  Description: string
  Default: boolean
}

export interface NewspaperPage {
  Title: string
  URL: string
}

export interface Heading {
  Title: string
  Level: number
}

export interface Dataset {
  name: string
  data: number[]
  hidden: boolean
  color: string
}

export interface UploadEntry {
  Name: string
  Quantity: number
  Price: number
  Condition: string
  Language: string
  IsFoil: boolean
  IsEtched: boolean
}

export interface OptimizedUploadEntry extends UploadEntry {
  Store: string
  StoreURL: string
  StorePrice: number
}

export interface GenericCard {
  ImageURL: string
  Printings: string
  Products: string
  SetCode: string
  Title: string
  Name: string
  Variant: string
  Flag: string
  Reserved: boolean
  Stocks: boolean
  SypList: boolean
  Sealed: boolean
  Booster: boolean
  HasDeck: boolean
  UUID: string
  SearchURL: string
  DeckboxURL: string
  CKRestockURL: string
  ScryfallURL: string
  TCGId: string
  SourceSealed: string[]
  Date: string
  Keyrune: string
  RarityColor: string
  Foil: boolean
}

export interface SearchEntry {
  ScraperName: string
  Country: string
  URL: string
  Price: number
  Secondary?: number
  Quantity: number
  NoQuantity: boolean
  BundleIcon: string
  Shorthand: string
  Ratio: number
  Credit: number
  ExtraValues?: {
    iqr: number
    stdDev: number
  }
}

export interface EditionEntry {
  Name: string
  Code: string
  Keyrune: string
}

export interface ChartDataset {
  name: string
  data: number[]
  hidden: boolean
  color: string
}

export default PageVars;