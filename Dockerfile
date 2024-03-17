FROM golang:1.19 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /mtgbantu-website

FROM alpine:3.19

# Updating APK and installing dependencies
RUN apk update && apk add --no-cache ca-certificates jq curl bash

WORKDIR /app/bantu

# Copying necessary files and directories from the build stage
COPY --from=build /mtgbantu-website ./mtgbantu-website
COPY templates ./templates
COPY css ./css
COPY js ./js
COPY img ./img

# Creating and setting up scripts directory and entrypoint script
RUN mkdir /scripts \
    && echo '#!/bin/sh' > /scripts/get-mtgjson.sh \
    && echo 'curl -O https://mtgjson.com/api/v5/AllPrintings.json.xz' >> /scripts/get-mtgjson.sh \
    && chmod +x /scripts/get-mtgjson.sh

RUN echo '#!/bin/sh' > /entrypoint.sh \
    && echo 'sh /scripts/get-mtgjson.sh' >> /entrypoint.sh \
    && echo 'if [ -z "$PORT" ]; then PORT=8080; fi' >> /entrypoint.sh \
    && echo 'exec ./mtgbantu-website' >> /entrypoint.sh \
    && chmod +x /entrypoint.sh

# Setting PATH environment variable to include /scripts directory
ENV PATH="/scripts:${PATH}"

# Setting the entrypoint to the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
