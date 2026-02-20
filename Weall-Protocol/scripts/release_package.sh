SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

help:
	@echo ""
	@echo "WeAll Protocol - Dev Utilities"
	@echo ""
	@echo "Targets:"
	@echo "  make clean      - remove caches/build artifacts/compose backups"
	@echo "  make release    - build a clean release zip into Windows Downloads (WSL)"
	@echo ""

clean:
	@./scripts/clean_repo.sh

release: clean
	@./scripts/release_package.sh
