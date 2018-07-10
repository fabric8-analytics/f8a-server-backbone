ifeq ($(TARGET),rhel)
  DOCKERFILE := Dockerfile.rhel
  REGISTRY := quay.io
  REPOSITORY := openshiftio/rhel-fabric8-analytics-f8a-server-backbone
else
  DOCKERFILE := Dockerfile
  REGISTRY := quay.io
  REPOSITORY := openshiftio/fabric8-analytics-f8a-server-backbone
endif

DEFAULT_TAG=latest

.PHONY: all docker-build fast-docker-build test get-image-name get-image-repository

all: fast-docker-build

docker-build:
	docker build --no-cache -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .

fast-docker-build:
	docker build -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .

test:
	./runtests.sh

get-image-name:
	@echo $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG)

get-image-repository:
	@echo $(REPOSITORY)

get-push-registry:
	@echo $(REGISTRY)
