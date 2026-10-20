.PHONY: install test lint docker-config docker-smoke

install:
	python -m pip install -r requirements.txt

test:
	PYTHONPATH=src python -m pytest

lint:
	PYTHONPATH=src python -m compileall -q api cli src tests

docker-config:
	docker compose config


docker-smoke:
	./scripts/docker-smoke.sh
