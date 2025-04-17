interface GenericCard {
    UUID: string;
    Name: string;
    Edition: string;
    SetCode: string;
    Number: string;
    Variant: string;
    Keyrune: string;
    ImageURL: string;
    Foil: boolean;
    Etched: boolean;
    Reserved: boolean;
    Title: string;
    SearchURL: string;
    SypList: boolean;
    Stocks: boolean;
    StocksURL: string;
    Printings: string;
    Products: string;
    TCGId: string;
    Date: string;
    Sealed: boolean;
    Booster: boolean;
    HasDeck: boolean;
    Flag: string;
    RarityColor: string;
    ScryfallURL: string;
    DeckboxURL: string;
    CKRestockURL: string;
    SourceSealed: string[];
}

export type { GenericCard };