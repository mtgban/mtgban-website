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
  }
};

module.exports = nextConfig;