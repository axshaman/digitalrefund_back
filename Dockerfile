FROM node:18

WORKDIR /app

COPY . .

RUN npm install

EXPOSE 8497

CMD ["npm", "start"]
