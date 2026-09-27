.PHONY: init up down reset test lint

init:
	whaxon init

up:
	whaxon up

down:
	whaxon down

reset:
	whaxon down --keep-msfrpcd
	docker-compose down -v
	rm -f data/whaxon.pid data/whaxon.env data/scope.json

test:
	pytest tests/

lint:
	ruff check src/
