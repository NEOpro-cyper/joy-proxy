# Official Node.js 20 LTS image
FROM node:20-alpine

WORKDIR /app

# Install only production dependencies (express was unused, undici is the new one)
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY server.js ./

ENV NODE_ENV=production \
    PORT=3000 \
    CACHE_MB=512

EXPOSE 3000

# Run as non-root
USER node

CMD ["node", "server.js"]
