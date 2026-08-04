.PHONY: build test check release package clean

VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X main.version=$(VERSION)
SOURCE_DATE_EPOCH ?= $(shell git show -s --format=%ct HEAD)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o portclue ./cmd/portclue

test:
	go test ./...

check:
	@unformatted="$$(gofmt -l cmd internal)"; if [ -n "$$unformatted" ]; then printf "Unformatted Go files:\n%s\n" "$$unformatted"; gofmt -d $$unformatted; exit 1; fi
	go mod verify
	go test -race ./...
	go vet ./...

release:
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || (echo "VERSION must be a release version such as 0.1.0" >&2; exit 1)
	@test "$(VERSION)" != "0.1.0-dev" || (echo "VERSION must not be 0.1.0-dev for a release" >&2; exit 1)
	@test -z "$$(git status --porcelain)" || (echo "release requires a clean Git worktree" >&2; exit 1)
	rm -rf dist
	mkdir -p dist
	$(MAKE) package GOARCH=amd64
	$(MAKE) package GOARCH=arm64
	cd dist && sha256sum portclue-$(VERSION)-linux-amd64.tar.gz portclue-$(VERSION)-linux-arm64.tar.gz > SHA256SUMS

package:
	@case "$(GOARCH)" in amd64|arm64) ;; *) echo "GOARCH must be amd64 or arm64" >&2; exit 1;; esac
	mkdir -p dist/portclue-$(VERSION)-linux-$(GOARCH)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags="$(LDFLAGS)" -o dist/portclue-$(VERSION)-linux-$(GOARCH)/portclue ./cmd/portclue
	cp README.md LICENSE THIRD_PARTY_NOTICES dist/portclue-$(VERSION)-linux-$(GOARCH)/
	tar --sort=name --mtime="@$(SOURCE_DATE_EPOCH)" --owner=0 --group=0 --numeric-owner --use-compress-program="gzip -n" -C dist -cf dist/portclue-$(VERSION)-linux-$(GOARCH).tar.gz portclue-$(VERSION)-linux-$(GOARCH)
	rm -rf dist/portclue-$(VERSION)-linux-$(GOARCH)

clean:
	rm -f portclue
	rm -rf dist
