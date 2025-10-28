VERSION ?= 0.1.0
COMMIT  := $(shell git rev-parse --short HEAD)
DATE    := $(shell date -u +%Y-%m-%d)
build:
	go build -ldflags "-X 'github.com/Shunsuiky0raku/redcheck/cmd.BuildVersion=$(VERSION)' -X 'github.com/Shunsuiky0raku/redcheck/cmd.BuildCommit=$(COMMIT)' -X 'github.com/Shunsuiky0raku/redcheck/cmd.BuildDate=$(DATE)'" -o redcheck .
clean: ; rm -f redcheck out.json out.html

