.PHONY: help build test scanner-test python-test scan-secure scan-insecure monitor serve demo clean

BIN := bin/phi-scan
PY  := python

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the Go scanner into bin/phi-scan
	@mkdir -p bin
	cd scanner && go build -o ../$(BIN) .

test: scanner-test python-test ## Run all tests

scanner-test: ## Run Go scanner tests
	cd scanner && go vet ./... && go test ./...

python-test: ## Run Python tests
	$(PY) -m pytest

scan-secure: build ## Scan the secure Terraform plan fixture (expect exit 0)
	./$(BIN) -plan scanner/testdata/secure.plan.json -fail-on high

scan-insecure: build ## Scan the insecure Terraform plan fixture (expect exit 1)
	./$(BIN) -plan scanner/testdata/insecure.plan.json -fail-on high || true

monitor: ## Score the sample PHI access events for exfiltration
	$(PY) -m phi_guardian.phi_monitor.cli samples/phi_access_events.json || true

serve: ## Run the JIT access broker API on :8000
	$(PY) -m uvicorn phi_guardian.jit_access.app:app --reload

demo: ## Run the full end-to-end demo
	./demo.sh

clean: ## Remove build artifacts
	rm -rf bin dist build *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
