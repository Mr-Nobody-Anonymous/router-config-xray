.PHONY: test lint demo clean help

PYTHON ?= python3

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

test: ## Run the unit test suite
	$(PYTHON) -m unittest discover -s tests -v

lint: ## Byte-compile the scanner to catch syntax errors
	$(PYTHON) -m py_compile router_config_xray.py

selftest: ## Run built-in checks
	$(PYTHON) router_config_xray.py --self-test

demo: ## Run the safe bundled demo
	$(PYTHON) router_config_xray.py --demo

clean: ## Remove Python bytecode caches
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
