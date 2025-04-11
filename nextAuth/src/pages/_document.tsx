'use client';

import { Html, Head, Main, NextScript } from 'next/document';
import type { DocumentProps } from 'next/document';
import React from 'react';

export default function Document(props: DocumentProps) {
  return (
    <Html lang="en">
      <Head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}