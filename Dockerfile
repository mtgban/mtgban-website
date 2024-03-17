# First stage: build the Go binary
FROM golang:1.19 AS build

WORKDIR /src

# Copy mod files first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /mtgbantu-website

# Second stage: Prepare the runtime container
FROM alpine:3.19

RUN apk update && apk add --no-cache ca-certificates jq curl bash xz

WORKDIR /app/bantu

# Copy the binary from the build stage
COPY --from=build /mtgbantu-website ./mtgbantu-website
COPY templates ./templates
COPY css ./css
COPY js ./js
COPY img ./img

# Add/create get-mtgjson script to PATH
RUN echo '#!/bin/sh' > /usr/local/bin/get-mtgjson.sh \
    && echo 'curl -O "https://mtgjson.com/api/v5/AllPrintings.json.xz"' >> /usr/local/bin/get-mtgjson.sh \
    && echo 'xz -dc AllPrintings.json.xz | jq > /tmp/allprintings5.json.new' >> /usr/local/bin/get-mtgjson.sh \
    && echo 'if [ $? -eq 0 ]; then mv /tmp/allprintings5.json.new ./allprintings5.json; fi' >> /usr/local/bin/get-mtgjson.sh \
    && echo 'rm AllPrintings.json.xz' >> /usr/local/bin/get-mtgjson.sh \
    && chmod +x /usr/local/bin/get-mtgjson.sh

# Expose variable port
EXPOSE 8080

# Define entrypoint and CMD
ENTRYPOINT ["/bin/sh", "-c", "get-mtgjson.sh && ./mtgbantu-website"]