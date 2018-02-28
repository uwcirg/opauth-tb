Opauth-Truenth
=============
[Opauth][1] strategy for Truenth authentication.

Implemented based on http://developer.github.com/v3/oauth/ using OAuth2.

Opauth is a multi-provider authentication framework for PHP.

Demo: http://opauth.org/#github

Getting started
----------------
1. Install Opauth-Truenth:
   ```bash
   cd app/Plugin/Opauth/Strategy 
   git clone https://github.com/uwcirg/opauth-truenth.git Truenth
   ```

2. Register the Truenth application/intervention at the appropriate
   Truenth Portal URL, i.e. `https://truenth-demo.cirg.washington.edu/client`
   - Enter Authorized URL: (i.e. the callback URL for the
     application/intervention being install i.e.
     `http://fqdn/application-path/truenth/oauth2callback`
   
3. Configure Opauth-Truenth strategy with `client_id` and `client_secret` 
   returned from the portal `/client` request.

4. Direct user to `http://fqdn/application-path/truenth` to authenticate


Strategy configuration
----------------------

Required parameters:

```php
<?php
'GitHub' => array(
	'authorize_url' => 'PORTAL AUTHORIZE URL',
	'access_token_url' => 'PORTAL TOKEN URL',
	'base_url' => 'PORTAL API URL',
	'client_id' => 'YOUR CLIENT ID',
	'client_secret' => 'YOUR CLIENT SECRET'
)
```

Optional parameters:
`scope`, `state`

License
---------
Opauth-Truenth is MIT Licensed  
Copyright © 2015 University of Washington 

[1]: https://github.com/uzyn/opauth
