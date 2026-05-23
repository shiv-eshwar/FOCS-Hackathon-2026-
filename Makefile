PYTHON ?= python3
IMAGE ?= nginx:1.14

.PHONY: install scan demo ci-check report test lint typecheck demo-local demo-setup landing

install:
	$(PYTHON) -m pip install -e ".[dev]"
	@command -v syft >/dev/null || (echo "syft not found" && exit 1)
	@command -v grype >/dev/null || (echo "grype not found" && exit 1)

scan:
	$(PYTHON) main.py --image $(IMAGE) --output terminal

demo:
	bash demo/demo.sh

ci-check:
	$(PYTHON) main.py --image $(IMAGE) --output json --report-file report.json --fail-on critical

report:
	$(PYTHON) main.py --image $(IMAGE) --output html --report-file report.html

test:
	pytest

lint:
	ruff check .

typecheck:
	mypy scanner main.py

demo-local:
	bash run-local-demo.sh

demo-setup:
	bash setup-demo.sh

landing:
	docker build -t vaultshield-app:landing .
	docker run --rm -p 8080:80 vaultshield-app:landing
