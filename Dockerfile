FROM golang:1.15.5

ENV PKG github.com/yuuki/golib-conntracer
WORKDIR /go/src/$PKG
