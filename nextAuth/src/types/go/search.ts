interface SearchEntry {
    ScraperName: string;
    Shorthand: string;
    Price: number;
    Credit: number;
    Ratio: number;
    Quantity: number;
    URL: string;
    NoQuantity: boolean;
    BundleIcon: string;
    Country: string;
    Secondary: number;
    ExtraValues: Record<string, number>;
}

interface FilterOpt {
    Title: string;
    Func: (opts: any) => void;
    ArbitOnly: boolean;
    GlobalOnly: boolean;
    BetaFlag: boolean;
    NoSealed: boolean;
    SealedOnly: boolean;
}

export type { SearchEntry, FilterOpt };