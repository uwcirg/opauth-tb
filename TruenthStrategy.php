<?php
/**
 * Truenth strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2015 University of Washington
 * @package      Opauth.TruenthStrategy
 * @license      MIT License
 */

/**
 * Truenth strategy for Opauth
 * based on https://developers.google.com/accounts/docs/OAuth2
 *
 * @package         Opauth.Truenth
 */
App::uses('HttpSocket', 'Network/Http');
App::uses('DatabaseSessionPlusUserId', 'Datasource/Session');
class TruenthStrategy extends OpauthStrategy{

    /**
     * Compulsory config keys, listed as unassociative arrays
     */
    public $expects = array('authorize_url', 'access_token_url',
            'base_url', 'client_id');

    /**
     * Optional config keys, without predefining any default values.
     */
    public $optionals = array('redirect_uri', 'scope', 'state', 'access_type', 'approval_prompt');

    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
        'scope' => 'email'
    );

    public $hasRefresh = true;

    /**
     * Auth request
     */
    public function request(){
        CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), just entered. Final Try Hi!!');

        $url = $this->strategy['authorize_url'];
        $params = array(
            'client_id' => $this->strategy['client_id'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            //'next' => Router::url("/", true),
            'response_type' => 'code',
            'scope' => $this->strategy['scope']
        );
        CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(); url: ' . $url . '; params for strategy: ' . print_r($params, true));

        foreach ($this->optionals as $key){
            if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
        }

        $this->clientGet($url, $params);
        CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), done');
    }

    /**
     * Validate signed requests from central services and return JSON data if valid
     */
    public static function validate_request($signed_request){
        list($encoded_sig, $encoded_data) = explode('.', $signed_request);

        $decoded_data = base64_decode(strtr($encoded_data, '-_', '+/'));

        $correct_decoded_sig = hash_hmac(
            'sha256',
            $encoded_data,
            Configure::read('Opauth.Strategy.Truenth.client_secret'),
            true
        );
        $correct_encoded_sig = strtr(base64_encode($correct_decoded_sig), '+/', '-_');

        if ($correct_encoded_sig !== $encoded_sig){
            CakeLog::write(LOG_ERROR, 'Request signature invalid');
            return false;
        }
        return json_decode($decoded_data, true);
    }

    /**
     * Internal callback, after OAuth
     */
    public function oauth2callback(){
	CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), just entered callback method!');
	CakeLog::write(LOG_DEBUG, print_r($_GET, true));
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
            $code = $_GET['code'];
            $url = $this->strategy['access_token_url'];
            $params = array(
                'code' => $code,
                'client_id' => $this->strategy['client_id'],
                'client_secret' => $this->strategy['client_secret'],
                'redirect_uri' => $this->strategy['redirect_uri'],
                'grant_type' => 'authorization_code'
            );

	    CakeLog::write(LOG_DEBUG, print_r($params, true));
	    CakeLog::write(LOG_DEBUG, print_r($url, true));
	    set_error_handler(array($this, "serverPostHandler"), E_WARNING);
            $response = $this->serverPost($url, $params, null, $headers);
            restore_error_handler();
            CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), response serverPost:' . print_r($response, true));

            $results = json_decode($response);

            CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), results from json_decode(response):' . print_r($results, true));

            if (!empty($results) && !empty($results->access_token)){
                CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), !empty($results) && !empty($results->access_token)');
		CakeSession::write('OPAUTH_ACCESS_TOKEN', $results->access_token);

		CakeLog::write(LOG_DEBUG, "AHHHHHH!");
		CakeLog::write(LOG_DEBUG, print_r($results, true));

#                CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), userinfo:' . print_r($userinfo, true));

                $this->auth = array(
                    'uid' => $results->user_id,
                    'info' => array(),
                    'credentials' => array(
                        'token' => $results->access_token,
                        'expires' => date('c', time() + $results->expires_in)
                    ),
                    'raw' => array()
                );

                if (!empty($results->refresh_token))
                {
                    $this->auth['credentials']['refresh_token'] = $results->refresh_token;
                }
		CakeLog::write(LOG_DEBUG, print_r($this->auth, true));
                $this->callback();
            }
            else{
                $error = array(
                    'code' => 'access_token_error',
                    'message' => 'Failed when attempting to obtain access token',
                    'raw' => array(
                        'response' => $response,
                        'headers' => $headers
                    )
                );
		CakeLog::write(LOG_DEBUG, print_r($error, true));
                $this->errorCallback($error);
            }
        }
        else{
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET
            );

            $this->errorCallback($error);
	}
        CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(), done');
    }// public function oauth2callback(){

    /**
     * Handler to catch warning generated during a logout edge case, and avoid redirection to cPRO login page (vs portal's) https://www.pivotaltracker.com/story/show/103820322
     */
    function serverPostHandler($errno, $errstr, $errfile, $errline){
        CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . "(); errstr:$errstr, redirecting to " . Router::url("/", true));
        self::redirect(Router::url("/", true));
    }

    /**
     * Generic CS to intervention callback. Note that you'll need to write this function name to the CS's clients table's callback_url field, eg https://p3p-dev.cirg.washington.edu/usa-self-mgmt/auth/truenth/eventcallback
     */
    public function eventcallback(){

        $data = self::validate_request($_POST['signed_request']);

        // CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(); data after json_decode:' . print_r($data, true));
        /** example
            [issued_at] => 1442959000
            [user_id] => 10015
            [event] => logout
            [algorithm] => HMAC-SHA256
        */

        if ($data['event'] == 'logout'){
            //CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(); data[event] == "logout"');
            $sessionObj = new DatabaseSessionPlusUserId();
            $deleteResult = $sessionObj->deleteByUserId($data['user_id']);
            //CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . "(); just did logout, heres deleteResult: $deleteResult");
         }
        //else CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(); data[event] != "logout"');

        //CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(); done.');
    }// public function eventcallback


    /**
     * Convenience method for serverPost()
     * Includes OAuth headers by default
     */
    public function post($url, $data, $access_token = null){
        CakeLog::write(LOG_DEBUG, __CLASS__ . '.' . __FUNCTION__ . '(); url:' . $url . '; data:' . print_r($data, true));

        if ($access_token === null)
            $access_token = CakeSession::read('OPAUTH_ACCESS_TOKEN');

        $default_headers = array(
            'Content-Type' => 'application/json',
            'Authorization' => 'Bearer ' . $access_token,
        );

        $headers = array();
        foreach($default_headers as $header => $value){
            array_push($headers, "$header: $value");
        }

		$options = array('http' => array(
            'method' => 'POST',
            'header' => implode($headers, "\r\n"),
            'content' => json_encode($data),
        ));

        $response = $this->httpRequest(
            $url,
            $options,
            $response_headers
        );

        $results = json_decode($response);

        if (
            !property_exists($results, 'ok') or
            $results->ok != true or

            !property_exists($results, 'valid') or
            $results->valid != true
        ){
            CakeLog::write(LOG_ERROR, __CLASS__ . '.' . __FUNCTION__ . '(), POST error; data:' . print_r($data, true));
            CakeLog::write(LOG_ERROR, __CLASS__ . '.' . __FUNCTION__ . '(), response:' . print_r($response, true));
            CakeLog::write(LOG_ERROR, __CLASS__ . '.' . __FUNCTION__ . '(), response headers:' . print_r($response_headers, true));

            throw new InternalErrorException('Error POSTing to CS');
        }

        return $results;
    }// public function post


    /**
     * Generic PUT
     */
    public function put($url, $data, $access_token = null){

        if ($access_token == null)
            $access_token = CakeSession::read('OPAUTH_ACCESS_TOKEN');

        $HttpSocket = new HttpSocket();
        $response = $HttpSocket->put(
            $url,
            json_encode($data),
            array(
                'header' => array(
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $access_token,
                ),
            )
        );

        if ($response->code == 200){
            return json_decode($response->body, true);
        }

        $error = array(
            'message' => "Error with PUT to $url",
            'code' => $response->code,
            'raw' => array(
                'response' => $response,
                'headers' => $response->headers,
            ),
        );

        CakeLog::write(LOG_ERROR, "Error in put(). URL: $url. Data: " . print_r($data, true) . ". Error: " . print_r($error,1));

        $this->errorCallback($error);
        switch ($response->code){
            case 404:
                throw new NotFoundException($error['message']);
                break;
        }
        return $error;
    }
}
