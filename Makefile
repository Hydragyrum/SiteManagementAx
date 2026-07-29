all: clean
	@ echo "    * Building service_filehost plugin"
	@ mkdir -p dist
	@ cp config.yaml ./dist/
	@ cp ax_config.axs ./dist/
	@ go mod tidy
	@ GOEXPERIMENT=jsonv2,greenteagc CGO_ENABLED=1 go build -buildmode=plugin -ldflags="-s -w" -o ./dist/service_filehost.so pl_main.go handler.go oneliner.go token_crypto.go
	@ echo "      done..."

clean:
	@ rm -rf dist
