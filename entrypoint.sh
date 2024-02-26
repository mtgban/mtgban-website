#!/bin/sh
if [ -z "$PORT" ]; then
    PORT=8080
fi
exec /app/bantu/mtgbantu-website -port $PORT
