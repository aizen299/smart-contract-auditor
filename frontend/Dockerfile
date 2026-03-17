FROM node:18-alpine AS builder
WORKDIR /app

# Install deps fresh (no npm ci — avoids native binding arch mismatch)
COPY package.json ./
RUN npm install

COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# Disable font optimization so it doesn't call Google Fonts at build time
ENV NEXT_FONT_GOOGLE_DISABLED=1
RUN npm run build

FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000

CMD ["node", "server.js"]