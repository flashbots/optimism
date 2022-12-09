# syntax=docker/dockerfile:1
FROM golang:1.18.0-alpine3.15 as builder

ARG GITCOMMIT=docker
ARG GITDATE=docker
ARG GITVERSION=docker
ARG LDFLAGS
RUN apk add make jq git gcc musl-dev linux-headers

WORKDIR /app

ADD . /app/

RUN go build -ldflags "${LDFLAGS}" -v -o ./bin/proxyd ./cmd/proxyd

FROM alpine:3.15

COPY ./entrypoint.sh /bin/entrypoint.sh

RUN apk update && \
    apk add ca-certificates && \
    chmod +x /bin/entrypoint.sh

EXPOSE 8080

COPY --from=builder /app/bin/proxyd /bin/proxyd
COPY --from=builder /app/proxyd.toml /etc/proxyd/proxyd.toml

ENTRYPOINT ["/bin/entrypoint.sh"]
CMD ["/bin/proxyd", "/etc/proxyd/proxyd.toml"]
