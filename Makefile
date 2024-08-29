GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

build:
	$(GOBUILD) -o bin/confide_acl .

test:
	$(GOTEST) -v ./... -coverprofile=coverage.out -covermode=atomic