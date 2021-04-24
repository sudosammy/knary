# We know knary works well in Golang 1.16
FROM golang:1.16-alpine as builder
RUN apk add --no-cache --upgrade git ca-certificates
WORKDIR /go/src/app
COPY . /go/src/app
# Build knary
RUN go get .
RUN CGO_ENABLED=0 go install -tags timetzdata

# Use a scratch container for production
FROM scratch

# Move compiled knary from builder image to production image
COPY --from=builder /go/bin/knary /knary
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Production container should be ~10MB :D
WORKDIR /
ENTRYPOINT ["/knary"]