#!/bin/bash
set -e

rm -f ./zzmnemonics.generated.go
rm -f ./zzpatterns.generated.go
rm -f ./zzencodings.generated.go
rm -f ./lookup/zzlookup.generated.go

go build -o ./gen/gen ./gen/gen.go
./gen/gen "mnemonics" > ./zzmnemonics.generated.go
./gen/gen "patterns" > ./zzpatterns.generated.go
./gen/gen "encodings" > ./zzencodings.generated.go
./gen/gen "lookup" > ./lookup/zzlookup.generated.go

gofmt -w ./zzmnemonics.generated.go
gofmt -w ./zzpatterns.generated.go
gofmt -w ./zzencodings.generated.go
gofmt -w ./lookup/zzlookup.generated.go

go vet
