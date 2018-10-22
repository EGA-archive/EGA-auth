SHELL := /bin/bash

.PHONY: all run kill log exec restart

all: run

run:
	docker run -d \
	-h ega-inbox-oidc \
	--name inbox-oidc \
	-p 2223:9000 \
	-p 9090:9001 \
	-v $(shell pwd):/ega \
	--entrypoint /bin/bash \
	nbisweden/ega-inbox:latest /ega/entrypoint.sh

kill:
	-docker kill inbox-oidc
	docker rm inbox-oidc

log:
	docker logs -f inbox-oidc

exec:
	docker exec -it inbox-oidc bash

restart:
	docker restart inbox-oidc
