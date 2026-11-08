FROM node:24-alpine AS ui
WORKDIR /src
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM golang:1.26 AS backend
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/issuer-lib/ third_party/issuer-lib/
RUN go mod download
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /signet ./cmd/signet

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=backend /signet /app/signet
COPY --from=ui /src/dist /app/ui
COPY LICENSE NOTICE /app/
COPY third_party/issuer-lib/LICENSE /app/licenses/issuer-lib-LICENSE
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/signet"]
