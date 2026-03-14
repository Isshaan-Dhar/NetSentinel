FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o test-backend .

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/test-backend .
EXPOSE 9000
CMD ["./test-backend"]