interface NavElem {
    Active: boolean;
    Class: string;
    Link: string;
    Name: string;
    Short: string;
    Handle: (w: any, r: any) => void;
    Page: string;
    AlwaysOnForDev: boolean;
    CanPOST: boolean;
    SubPages: string[];
    NoAuth: boolean;
}

export type { NavElem };