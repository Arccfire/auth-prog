
lint:
	uv run ruff check .

format:
	uv run ruff format .

types:
	uv run mypy .

tests:
	uv run pytest


check: lint format types tests


clean:
	rm -rf __pycache__ outputs/* .ruff_cache .pytest_cache .mypy_cache


.PHONY: tests clean lint format types check
