FROM golang:1.15.5

ENV PKG github.com/yuuki/gobpflib-conntracer
WORKDIR /go/src/$PKG
