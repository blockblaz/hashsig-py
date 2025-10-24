.PHONY: help install test clean format lint build release

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package in development mode
	maturin develop

install-release: ## Install the package in release mode
	maturin develop --release

test: ## Run all tests
	cargo test
	python test_basic.py
	python simple_example.py

test-python: ## Run Python tests only
	python test_basic.py
	python simple_example.py

test-rust: ## Run Rust tests only
	cargo test

format: ## Format code
	cargo fmt
	black *.py

lint: ## Run linters
	cargo clippy -- -D warnings
	cargo fmt -- --check
	ruff check *.py

clean: ## Clean build artifacts
	cargo clean
	rm -rf target/
	rm -rf *.egg-info/
	rm -rf dist/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: ## Build the package
	maturin build

build-release: ## Build the package in release mode
	maturin build --release

check: ## Check if code compiles
	cargo check

bench: ## Run benchmarks
	cargo bench

docs: ## Generate documentation
	cargo doc --open

setup: ## Setup development environment
	pip install -r requirements-dev.txt
	rustup component add rustfmt clippy
