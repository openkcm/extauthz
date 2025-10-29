SERVICE_NAME = extauthz
K3D_CLUSTER_NAME = extauthz

.PHONY: build
build: clean
	go build -o $(SERVICE_NAME) ./cmd/$(SERVICE_NAME)
	sha256sum $(SERVICE_NAME)

.PHONY: clean
clean:
	rm -f cover.out cover.html $(SERVICE_NAME)
	rm -rf cover/

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
helm-integration-test:
	# we are explicit here to ensure that teardown really runs twice
	$(MAKE) k3d-teardown
	$(MAKE) k3d-setup
	$(MAKE) helm-integration-test-run
	$(MAKE) k3d-teardown

.PHONY: k3d-setup
k3d-setup:
	k3d cluster create $(K3D_CLUSTER_NAME) -p "30083:30083@server:0" --api-port 127.0.0.1:6443
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(SERVICE_NAME) ./cmd/$(SERVICE_NAME)
	docker build --no-cache -t localhost/$(SERVICE_NAME):latest -f Dockerfile.dev .
	k3d image import localhost/$(SERVICE_NAME):latest -c $(K3D_CLUSTER_NAME)

.PHONY: helm-integration-test-run
helm-integration-test-run:
	kubectl config current-context
	cd ./helm-tests/integration && go test -v -count=1 -race .

.PHONY: k3d-teardown
k3d-teardown:
	k3d cluster delete $(K3D_CLUSTER_NAME)
