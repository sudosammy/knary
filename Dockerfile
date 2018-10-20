FROM golang:1.11.0-alpine3.7 as build-env

RUN apk add --no-cache --upgrade git ca-certificates

WORKDIR /go/src/app

COPY . /go/src/app

RUN go get ./
RUN go build -o knary main.go

FROM alpine:3.7
ENV GOPATH /knary
RUN mkdir /knary
RUN mkdir /knary/certs
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build-env /go/src/app/.env /knary/.env
COPY --from=build-env /go/src/app/knary /knary/knary
COPY --from=build-env /go/src/app/certs/* /knary/certs/

WORKDIR /knary
ENTRYPOINT ["/knary/knary"]
