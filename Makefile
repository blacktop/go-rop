REPO=blacktop
NAME=go-rop
VERSION=$(shell cat VERSION)
MESSAGE?="New release ${VERSION}"

# TODO remove \|/templates/\|/api
SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=

GIT_COMMIT=$(git rev-parse HEAD)
GIT_DIRTY=$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)
GIT_DESCRIBE=$(git describe --tags)

.PHONY: test
test: ## Run all the tests
	@echo " > not implimented yet..."

cover: test ## Run all the tests and opens the coverage report
	go tool cover -html=coverage.txt

fmt: ## gofmt and goimports all go files
	find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done

lint: ## Run all the linters
	gometalinter --vendor --disable-all \
		--enable=deadcode \
		--enable=ineffassign \
		--enable=gosimple \
		--enable=staticcheck \
		--enable=gofmt \
		--enable=goimports \
		--enable=dupl \
		--enable=misspell \
		--enable=errcheck \
		--enable=vet \
		--enable=vetshadow \
		--deadline=10m \
		./...
		markdownfmt -w README.md

.PHONY: dry_release
dry_release:
	goreleaser --skip-publish --rm-dist --skip-validate

.PHONY: bump
bump: ## Incriment version patch number
	@echo " > Bumping VERSION"
	@hack/bump/version -p $(shell cat VERSION) > VERSION
	@git commit -am "bumping version to $(VERSION)"
	@git push

.PHONY: release
release: bump ## Create a new release from the VERSION
	@echo " > Creating Release"
	@hack/make/release $(shell cat VERSION)
	@goreleaser --rm-dist

destroy: ## Remove release from the VERSION
	@echo " > Deleting Release"
	rm -rf dist
	git tag -d ${VERSION}
	git push origin :refs/tags/${VERSION}

ci: lint test ## Run all the tests and code checks

lzssdec.so: lzssdec.cpp
    clang++ -o lzssdec.so lzssdec.cpp -std=c++17 -O3 -Wall -Wextra -fPIC -shared

build: ## Build a beta version of malice
	@echo " > Building Binaries"
	goreleaser --skip-publish --rm-dist --skip-validate

clean: ## Clean up artifacts
	@scripts/reset.sh
	@rm -rf dist/ || true
	@rm launchpad.db || true
	@rm go-rop || true

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help