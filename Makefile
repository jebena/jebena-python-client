
test:
	@# For now, this is a very simple test for verifying that the client can run
	@# in both Python 2.7 and 3.x.
	echo 'query { me { person { displayName } } }' | python2.7 -m jebenaclient
	echo 'query { me { person { displayName } } }' | python3 -m jebenaclient
