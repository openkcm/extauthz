SERVICE_NAME = extauthz

.PHONY: build
build: clean
	go build -o $(SERVICE_NAME) ./cmd/$(SERVICE_NAME)
	sha256sum $(SERVICE_NAME)

.PHONY: clean
clean:
	rm -f cover.out cover.html $(SERVICE_NAME)
	rm -rf cover/

.PHONY: docker-build
docker-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(SERVICE_NAME) ./cmd/$(SERVICE_NAME)
	docker build --no-cache -t localhost/$(SERVICE_NAME):latest -f Dockerfile.dev .

.PHONY: helm-install
helm-install:
	kubectl apply -f examples/trustedSubjectsConfigmap.yaml
	helm install $(SERVICE_NAME) ./charts \
		--set image.registry=localhost \
		--set image.tag=latest

.PHONY: helm-uninstall
helm-uninstall:
	helm uninstall --ignore-not-found $(SERVICE_NAME)
	kubectl delete --ignore-not-found -f examples/trustedSubjectsConfigmap.yaml

.PHONY: lint
lint:
	golangci-lint run -v --fix ./...

.PHONY: test
test: clean
	mkdir -p cover/integration cover/unit
	go clean -testcache

	# unit tests
	go test -count=1 -race -cover ./... -args -test.gocoverdir="${PWD}/cover/unit"

	# integration tests
	GOCOVERDIR="${PWD}/cover/integration" go test -count=1 -race --tags=integration ./integration

	# merge coverage
	go tool covdata textfmt -i=./cover/unit,./cover/integration -o cover.out
	go tool cover -func=cover.out

	# On a Mac, you can use the following command to open the coverage report in the browser
	# go tool cover -html=cover.out -o cover.html && open cover.html

.PHONY: helm-test
helm-test: helm-unit-test helm-integration-test

.PHONY: helm-unit-test
helm-unit-test:
	cd ./helm-tests/unit && go test -v -count=1 -race .

.PHONY: helm-integration-test
helm-integration-test: docker-build
	kubectl config current-context
	cd ./helm-tests/integration && go test -v -count=1 -race .
