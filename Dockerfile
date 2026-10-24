FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ts-ssh-agent ./cmd/ts-ssh-agent \
    && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ts-ssh-agent /usr/local/bin/ts-ssh-agent
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/ts-ssh-agent
VOLUME /var/lib/ts-ssh-agent
ENTRYPOINT ["/usr/local/bin/ts-ssh-agent"]
CMD ["server"]
