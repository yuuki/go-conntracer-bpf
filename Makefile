DOCKER_IMAGE_NAME = yuuki/gobpflib-conntracer

.PHONY: docker/build
docker/build:
	docker build -t $(DOCKER_IMAGE_NAME) .
