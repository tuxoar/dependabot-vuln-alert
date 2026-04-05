FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /dependabot-vuln-alert .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /dependabot-vuln-alert /usr/local/bin/
ENTRYPOINT ["dependabot-vuln-alert"]
