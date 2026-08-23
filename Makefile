
test:
	python3 -m unittest discover -s tests -v

lint:
	python3 -m flake8 --max-line-length=120 jebenaclient/ tests/

smoke-test:
	@# Talks to a live server, so JEBENA_API_* must be set in your shell.
	echo 'query { me { person { displayName } } }' | python3 -m jebenaclient
	echo '{ "query": "query getDisplayName { me { person { displayName } } }",  "variables": {"foo": "bar"},  "operationName": "getDisplayName" }' | python3 -m jebenaclient

.PHONY: test lint smoke-test
