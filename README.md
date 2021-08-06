![Buna the Corgi](./documentation/buna-the-corgi.svg)
# Jebena Client for Python

This packages implements a simple python client for accessing the Jebena server. 
Our client handles basic retry logic and error handling, and supports usage via both command-line and importing in python code.
  

## Usage

 1. **Create your API Key** on your Jebena server. You will need all _three_ parts (`JEBENA_API_ENDPOINT`, `JEBENA_API_KEY_NAME`, and `JEBENA_API_SECRET_KEY`).

    1. Log in via web browser, and go to the upper-right user menu.
       Select "Manage API Keys" and follow the instructions there to create your key.
       If you need write-access, make sure to enable writes for the API key.

    1. Store your API key *securely*!
       Anyone who has access to your API Keys can access and modify data as though they were you.
       **API Keys should not be shared with other users; they should create their own API keys.**

       * On MacOS: create an encrypted disk image using Disk Utility (File -> New Image -> Blank Image; set Encryption to 256-bit). 
         Inside it create a file name `./jebena-keys.sh`.
         Edit the file to have your API values like below. 
         You can then `src /Volumes/<disk-name>/jebena-keys.sh` to load your API keys into a shell when you need. 
         (If you reboot, re-open the .img file to re-mount the encrypted disk image.)
          ```
          export JEBENA_API_KEY_NAME=jeb00000...
          export JEBENA_API_SECRET_KEY=<sensitive>
          export JEBENA_API_ENDPOINT=https://api-hostname.example.com/v1/
          ```

 1. **Install the `jebenaclient` package.** There are two different methods for this.
 
    * `pip` method: If you have a virtualenv, 
        run `pip install https://github.com/jebena/jebena-python-client/archive/main.zip`
    * `.py` file method: Alternatively, you can directly snag this .py file, which can then be checked into your own repo.
       ```
       curl -o jebenaclient.py https://raw.githubusercontent.com/jebena/jebena-python-client/main/jebenaclient/jebenaclient.py
       chmod +x jebenaclient.py
      ```

  1. **Run your GQL query** — either via command line or via python code.
     Remember to `source /path/to/jebena-keys.sh` in your shell first.
     For documentation on GQL schema, visit the URL given in your `JEBENA_API_ENDPOINT`, click GraphiQL, and on the right side, expand "< Docs".
   
        * Command line method: for pip, run `python3 -m jebenaclient`; for .py file, run `./jebenaclient.py` and then enter your query at the prompt.
            * If your query is in a file, you can pipe your query in:
               * `cat some-query.txt | python -m jebenaclient`
               * `echo "query { me { person { displayName } } }" | python -m jebenaclient`
    
        * Python code method: import the client and call `jebenaclient.run_query` (see below for additional details).
             ```
            import logging
            import jebenaclient
            
            LOGGER = logging.getLogger(__name__)
            
            try:
                results = jebenaclient.run_query("query { me { person { displayName } } }")
                print(results['data']['me']['person']['displayName'])
            except jebenaclient.JebenaCliGQLException as exc:
                LOGGER.error("The query was invalid (%s)", exc)
            except jebenaclient.JebenaCliException as exc:
                LOGGER.error("The request could not be processed (%s).", exc)
            ```

### Passing GQL Variables

There are two ways to pass variables in your query: programmatically or via wrapped query.

**Programmatically in function call.** This method only applies to python code.
```
import jebenaclient
example_query = "query theQuery($someUUID: String!) { project(uuid: $someUUID) { name shortName } }"
example_variables = {
    "someUUID":"c893bf7f-2bb0-e153-c2a2-6699b847e584"
}
response = jebenaclient.run_query(example_query, variables=example_variables)
print(response["data"]["project"])
```

**Wrapped Query Method.** Your GQL query can include both `query` and `variable` keys, for a "wrapped" query.

For example, in the shell (the "heredoc" can be replace with a file, e.g. `cat query.txt | ./jebenaclient.py`):
```
source /path/to/jebena-keys.sh
cat <<'EOF' | ./jebenaclient.py
{
  "query": "query theQuery($someUUID: String!) { project(uuid: $someUUID) { name shortName } }",
  "variables": {
    "someUUID":"c893bf7f-2bb0-e153-c2a2-6699b847e584"
  }
}
EOF
```

The same example, as python code:
```
import jebenaclient
example_query = '''
{
  "query": "query theQuery($someUUID: String!) { project(uuid: $someUUID) { name shortName } }",
  "variables": {
    "someUUID":"c893bf7f-2bb0-e153-c2a2-6699b847e584"
  }
}
'''
response = jebenaclient.run_query(example_query)
print(response["data"]["project"])
``` 



### Setting API keys programmatically

The `run_query()` function accepts these optional parameters for use cases 
where loading secrets in the ENV is not practical.

   * `api_endpoint`: The URL of your Jebena API server. When not passed, the
       ENV variable JEBENA_API_ENDPOINT is accessed.

   * `api_key_name`: Your Jebena API key name. When not passed, the
    ENV variable JEBENA_API_KEY_NAME is accessed. This value is not sensitive.

   * `api_secret_key`: The secret key associated with your API key name.
    When not passed, ENV variable JEBENA_API_SECRET_KEY is read. This value must
    be kept securely stored!


### Working with Jebena Trace IDs

The Jebena API Server provides a "Jebena Trace ID" that can be used for tracing
the backend server's logs for any given request. This is provided as an HTTP header to clients.

Calling `jebenaclient.get_last_run_trace_id()` after any call to `jebenaclient.run_query()` will provide the Jebena Trace ID,
which can then be used by server developers (e.g. `jebena aws logs trace <id>`)
