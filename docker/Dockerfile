FROM alpine:3.17 AS builder

RUN apk update && apk add --no-cache cmake make git gcc \
  musl-dev linux-headers openssl-dev json-c-dev libevent-dev zlib-dev \
  openssl-libs-static libevent-static zlib-static

WORKDIR /xfrpc
COPY . .
WORKDIR /xfrpc/build
RUN rm * -rf && cmake -D STATIC_BUILD=ON ../ && make

FROM scratch AS export-stage
COPY --from=builder /xfrpc/build/xfrpc .
