interface NewspaperPage {
    Title: string;
    Desc: string;
    Option: string;
    Query: string;
    Sort: string;
    Head: Heading[];
    Large: boolean;
    Offset: number;
    Priced: string;
    PercChanged: string;
}

interface Heading {
    Title: string;
    CanSort: boolean;
    Field: string;
    IsDollar: boolean;
    IsPerc: boolean;
    IsHidden: boolean;
    ConditionalSort: boolean;
}

export type { NewspaperPage, Heading };