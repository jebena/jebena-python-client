from distutils.core import setup
setup(
  name = 'jebena-python-client',
  packages = ['jebenaclient'],
  version = '0.9.1',
  license='mpl-2.0',
  description = 'Simple Python Client for the Jebena API Server',
  author = 'Jeff Potter',
  author_email = 'jeffpotter+jebenaclient@jebena.org',
  url = 'https://github.com/jebena',
  download_url = 'https://github.com/jebena/jebena-python-client/archive/main.zip',
  keywords = [],
  install_requires = [],
  classifiers=[
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'Topic :: Software Development :: API Client',
    'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
  ],
)
