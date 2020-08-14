VERSION := $(shell git describe --always --tags --abbrev=0 | tail -c +2)
RELEASE := $(shell git describe --always --tags | awk -F- '{ if ($$2) dot="."} END { printf "1%s%s%s%s\n",dot,$$2,dot,$$3}')

.PHONY: build test

default: clean test build

test:
	go test -timeout 60s ./...

clean:
	rm -rf build

build:
	mkdir -p build/usr/bin
	go build -ldflags "-X main.VERSION=${VERSION}-${RELEASE}" -o build/usr/bin/oauth2-proxy .

rpm:
	fpm -t rpm \
		-s "dir" \
		--description "OAuth2-proxy" \
		-C ./build/ \
		--vendor "SKB Kontur" \
		--name "oauth2-proxy" \
		--version "${VERSION}" \
		--iteration "${RELEASE}" \
		-p build

default: build

run: clean build
	./build/usr/bin/oauth2-proxy -provider=passport -config etc/oauth2_proxy.cfg

docker:
	docker-compose build

up: docker
	docker-compose up -d
