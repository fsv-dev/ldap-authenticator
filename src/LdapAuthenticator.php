<?php

/*
 * This file is part of project rest-api
 * API for faculty of social sciences
 * @author Kraus Vaclav <krauva@gmail.com>
 */

namespace App\Model;

use Nette\Security as NS;
use Nette;

/**
 * Description of LdapSecurityAuthenticator
 *
 * @author krausv
 */
class LdapAuthenticator extends Nette\Object implements NS\IAuthenticator {

    private $host, $port, $base;

    //TODO prozatim odebrana databaze
    public function __construct($host, $port, $base) {
	$this->host = $this->detectValue($host);
	$this->port = $this->detectValue($port);
	$this->base = $this->detectValue($base);
    }

    /**
     * Performs an authentication.
     * 
     * @param array $credentials
     * @return \Nette\Security\Identity
     * @throws \Exception
     * @throws Nette\Security\AuthenticationException
     */
    public function authenticate(array $credentials) {
	list($username, $password) = $credentials;

	//TODO potrebuji username, heslo
	$ldap = \ldap_connect($this->host, $this->port);
	//Protocol
	\ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

	$res = \ldap_bind($ldap);
	if (!$res) {
	    throw new \Exception('Failed to bind to LDAP server');
	}
	$res = \ldap_search($ldap, $this->base, $this->searchString($username), array('dn'));

	if (\ldap_count_entries($ldap, $res) != 1) {
	    throw new Nette\Security\AuthenticationException('Neplatné uživatelské jméno.', self::IDENTITY_NOT_FOUND);
	}
	// Pokud uzivatel existuje v LDAPu ...
	$detect = TRUE;

	$entry = \ldap_first_entry($ldap, $res);
	$dn = \ldap_get_dn($ldap, $entry);

	//bind na prihlasovaneho uzivatele
	$res = @ldap_bind($ldap, $dn, $password);
	if (!$res) {
	    throw new Nette\Security\AuthenticationException('Neplatné heslo.', self::INVALID_CREDENTIAL);
	}
	
	// Load data from database
	
	return new NS\Identity($username);
    }

    /**
     * Modify filter based on login name string|number
     * @param string $string
     * @return string
     */
    private function searchString($string) {
	if (is_numeric($string)) {
	    return "(cunipersonalid=$string)";
	}
	return "(uid=$string)";
    }

    /**
     * Detect config values
     * @param $value
     */
    private function detectValue($value) {
	if ($value == "") {
	    throw new \Exception('Value of LdapAuthenticator config not be empty');
	}
	return $value;
    }

}
