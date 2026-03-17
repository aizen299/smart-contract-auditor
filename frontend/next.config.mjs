/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/scan",
        destination: process.env.BACKEND_URL
          ? `${process.env.BACKEND_URL}/scan`
          : "http://localhost:8000/scan",
      },
    ];
  },
};

export default nextConfig;