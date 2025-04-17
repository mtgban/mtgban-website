interface Window {
    __INITIAL_DATA__?: {
      user?: User | null;
      csrf_token?: string | null;
    };
  }

declare module '*.module.css' {
    const classes: { [key: string]: string };
    export default classes;
}

declare module 'styled-jsx' {
    import * as React from 'react';

    export interface StyleProps {
        jsx?: boolean;
        global?: boolean;
    }

    export const css: (strings: TemplateStringsArray) => string;
    export default function Style(props: StyleProps): React.ReactElement;
}