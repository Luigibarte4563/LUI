FROM node:latest
ENV NODE_ENV=development
ENV DB_PASSWORD=secret123
COPY . /app
WORKDIR /app
RUN npm install
EXPOSE 22
EXPOSE 3000
CMD ["node", "server.js"]
