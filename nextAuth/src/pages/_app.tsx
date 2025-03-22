import { useState } from 'react'
import { AppProps } from 'next/app'
import { QueryClient, QueryClientProvider } from 'react-query'
import { ReactQueryDevtools } from 'react-query/devtools'
import { GoDataProvider } from '@/context/GoDataContext'
import { AuthProvider } from '@/context/AuthContext'
import '../../public/globals.css'

export default function MyApp({ Component, pageProps }: AppProps) {
  // Create a QueryClient instance for React Query
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        staleTime: 60000, // 1 minute
        retry: 1,
      },
    },
  }))

  return (
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <GoDataProvider>
          <Component {...pageProps} />
          </GoDataProvider>
        {process.env.NODE_ENV !== 'production' && <ReactQueryDevtools />}
      </QueryClientProvider>
    </AuthProvider>
  )
}