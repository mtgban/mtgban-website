interface EditionEntry {
    Name: string;
    Code: string;
    Date: Date;
    Keyrune: string;
    Size: number;
    FmtDate: string;
    Special: boolean;
    ShowFin: boolean;
    HasReg: boolean;
    HasFoil: boolean;
    Rarities: string[];
    Colors: string[];
}

export type { EditionEntry };