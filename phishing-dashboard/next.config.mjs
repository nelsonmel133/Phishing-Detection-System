/** @type {import('next').NextConfig} */
const nextConfig = {
  // Required for the Docker multi-stage build to produce a minimal runtime image
  output: "standalone",
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
  },
};

export default nextConfig;
