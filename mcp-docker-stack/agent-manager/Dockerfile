FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY rotator.js .
CMD ["node", "rotator.js"]
