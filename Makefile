# Go build flags
LDFLAGS=-ldflags "-s -w"

default:
	go build ${LDFLAGS} -o "Starmap" cmd/Starmap.go

# Compile Server - Windows x64
windows:
	export GOOS=windows;export GOARCH=amd64;go build ${LDFLAGS} -o "Starmap.exe" cmd/Starmap.go

# Compile Server - Linux x64
linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o "Starmap" cmd/Starmap.go

# Compile Server - Darwin x64
darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o "Starmap" cmd/Starmap.go

# clean
clean:
	rm -rf ${DIR}
