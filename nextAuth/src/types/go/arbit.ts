interface Arbitrage {
    Name: string;
    Key: string;
    Arbit: any[];
    CreditMultiplier: number;
    HasNoCredit: boolean;
    HasNoQty: boolean;
    HasNoConds: boolean;
    HasNoPrice: boolean;
    HasNoArbit: boolean;
    SussyList: Record<string, number>;
}

export type { Arbitrage };