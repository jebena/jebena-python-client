
test:
	@# For now, this is a very simple smoke test that the client runs end-to-end.
	@# It talks to a live server, so JEBENA_API_* must be set in your shell.
	echo 'query { me { person { displayName } } }' | python3 -m jebenaclient
	echo '{ "query": "query getDisplayName { me { person { displayName } } }",  "variables": {"foo": "bar"},  "operationName": "getDisplayName" }' | python3 -m jebenaclient

lint:
	python3 -m flake8 --max-line-length=120 jebenaclient/

.PHONY: test lint
