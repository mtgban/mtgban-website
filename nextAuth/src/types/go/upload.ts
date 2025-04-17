interface InputCard {
    Id: string;
    Name: string;
    Variation: string;
    Edition: string;
    Foil: boolean;
    beyondBaseSet: boolean;
    promoWildcard: boolean;
    originalName: string;
    Language: string;
}

interface UploadEntry {
    Card: InputCard;
    CardId: string;
    MismatchError: Error;
    MismatchAlias: boolean;
    OriginalPrice: number;
    OriginalCondition: string;
    HasQuantity: boolean;
    Quantity: number;
    Notes: string;
}

interface OptimizedUploadEntry {
    CardId: string;
    Condition: string;
    Price: number;
    Spread: number;
    BestPrice: number;
    Quantity: number;
    VisualPrice: number;
    Profitability: number;
}

export type { InputCard, UploadEntry, OptimizedUploadEntry };