ATA is a helper to access twitter REST api.

With the new twitter authentication model in place, ATA can help you make twitter API calls easily.
One needs to create an instance of ata.Main for every new application.
It supports both app-user and app-only, authentication based twitter REST API requests.
For app-user requests access tokens should be provided.

Twitter oauth: https://dev.twitter.com/docs/auth/oauth

Needs oauth2 library: https://github.com/brosner/python-oauth2

Installation instructions:
--------------------------
1. git clone https://github.com/brosner/python-oauth2
2. install oauth2 (from oauth2 directory run command, python setup.py install)
3. git clone https://github.com/vandanab/ata.git
4. install ata (from ata directory run command, python setup.py install)


