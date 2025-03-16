/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typescript: {
    ignoreBuildErrors: true,
  },
  output: 'export',
  distDir: 'out',
  trailingSlash: false,
  images: {
    unoptimized: true
  },

  eslint: {
    ignoreDuringBuilds: true,
  },
  exportPathMap: async function () {
    return {
      '/': { page: '/' },
      '/login': { page: '/login' },
      '/signup': { page: '/signup' },
      '/forgot-password': { page: '/forgot-password' },
      '/reset-password': { page: '/reset-password' },
      '/signup-success': { page: '/signup-success' },
      '/confirmation': { page: '/confirmation' },
    };
  },
};

module.exports = nextConfig;