/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/api/scan/zip",
        destination: process.env.NEXT_PUBLIC_API_URL
          ? `${process.env.NEXT_PUBLIC_API_URL}/scan/zip`
          : "http://backend:8000/scan/zip",
      },
      {
        source: "/api/scan",
        destination: process.env.NEXT_PUBLIC_API_URL
          ? `${process.env.NEXT_PUBLIC_API_URL}/scan`
          : "http://backend:8000/scan",
      },
    ];
  },
};

export default nextConfig;