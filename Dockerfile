FROM golang:1.12.3 as builder
RUN mkdir /app
COPY . /app/
WORKDIR /app
ARG CI_COMMIT_SHORT_SHA
RUN make build

FROM alpine:3.9.2
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main ./app
COPY --from=builder /app/.env.yaml .env.yaml
EXPOSE 8080

ENTRYPOINT ./app
