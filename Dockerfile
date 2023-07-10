FROM golang:1.20.5-bullseye AS BUILDER

WORKDIR /oidc-discovery-server

COPY . .

RUN go build -o oidc-discovery-server

FROM ubuntu:22.04 AS RUNTIME

USER root
WORKDIR /oidc-discovery-server

RUN apt update && \
    apt install -y ca-certificates && \
    apt clean

COPY --from=BUILDER /oidc-discovery-server .

ENTRYPOINT ["./oidc-discovery-server"]
