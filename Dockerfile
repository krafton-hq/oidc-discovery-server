FROM golang:1.20.5-bullseye AS BUILDER

WORKDIR /app

COPY . .

RUN go build -o oidc-discovery-server

FROM ubuntu:22.04 AS RUNTIME

USER root
WORKDIR /root

RUN apt update && \
    apt install -y ca-certificates && \
    apt clean

COPY --from=BUILDER /app/oidc-discovery-server .
COPY config.yaml .

ENTRYPOINT ["./oidc-discovery-server"]
