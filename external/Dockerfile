FROM node:current-alpine

ENV PORT=80
LABEL org.opencontainers.image.title="App1!" \
      org.opencontainers.image.description="Demo application"

WORKDIR /usr/src/app1

CMD ["sh", "-c", "export HOSTNAME=$(curl -s http://169.254.169.254/latest/meta-data/local-hostname)"]

RUN echo '{ "name": "app1", "version": "1.0.0", "main": "app.js", "dependencies": { "express": "^4.17.1" } }' > package.json \
    && npm install \
    && echo 'const express = require("express"); \
               const app = express(); \
               const port = process.env.PORT; \
               const hostname = process.env.HOSTNAME; \
               app.get("/", (req, res) => res.send(`Hello, world from ${hostname}!`)); \
               app.listen(port, () => console.log(`App runs on ${hostname} port ${port}`));' > app.js \
    && apk --no-cache add curl

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://$HOSTNAME:$PORT || exit 1

EXPOSE $PORT

ENTRYPOINT ["node", "app.js"]