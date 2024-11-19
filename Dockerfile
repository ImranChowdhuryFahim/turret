FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git build-base

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o turret

FROM alpine:3.19

WORKDIR /app

RUN apk update && apk add --update git bash openssh && rm -rf /var/cache/apk/*

RUN mkdir -p /app/.ssh /app/.repos /app/secrets /app/access

COPY --from=builder /app/turret .

RUN chmod +x /app/turret

EXPOSE 23235

CMD ["./turret"]


