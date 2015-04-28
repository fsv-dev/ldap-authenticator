<?php

/*
 * This file is part of project rest-api
 * API for faculty of social sciences
 * @author Kraus Vaclav <krauva@gmail.com>
 */

namespace Ldap;

use Nette\Security as NS;
use Nette;
use App\Model;

/**
 * Description of LdapSecurityAuthenticator
 *
 * @author Vaclav Kraus <krauva@gmail.com>
 */
class LdapAuthenticator extends Nette\Object implements NS\IAuthenticator {

    private $host, $port, $base, $db;

    const
	    ERROR_MESSAGE_AUTH_USER = 'Neplatné uživatelské jméno.',
	    ERROR_MESSAGE_AUTH_PASS = 'Neplatné heslo.',
	    ERROR_MESSAGE_CONF_DETECT = 'Value of LdapAuthenticator config not be empty',
	    ERROR_MESSAGE_LDAP_BIND = 'Failed to bind to LDAP server',
	    TABLE_NAME = 'users',
	    TABLE_ROLE = 'role',
	    TABLE_USERNAME = 'username';

    //TODO prozatim odebrana databaze
    public function __construct(Nette\Database\Context $db, $host, $port, $base) {
	$this->host = $this->detectValue($host);
	$this->port = $this->detectValue($port);
	$this->base = $this->detectValue($base);
	$this->db = $db;
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
	    throw new \Exception(self::ERROR_MESSAGE_LDAP_BIND);
	}
	$res = \ldap_search($ldap, $this->base, $this->searchString($username), array('dn'));

	if (\ldap_count_entries($ldap, $res) != 1) {
	    throw new Nette\Security\AuthenticationException(self::ERROR_MESSAGE_AUTH_USER, self::IDENTITY_NOT_FOUND);
	}
	// Pokud uzivatel existuje v LDAPu ...
	$detect = TRUE;

	$entry = \ldap_first_entry($ldap, $res);
	$dn = \ldap_get_dn($ldap, $entry);

	//bind na prihlasovaneho uzivatele
	$res = @ldap_bind($ldap, $dn, $password);
	if (!$res) {
	    throw new Nette\Security\AuthenticationException(self::ERROR_MESSAGE_AUTH_PASS, self::INVALID_CREDENTIAL);
	}

	// Database perform
	if ($this->databaseDetect($username) == TRUE) {
	    return new NS\Identity($username, $this->getRole($username));
	}
	throw new Nette\Security\AuthenticationException(self::IDENTITY_NOT_FOUND);

	//return new NS\Identity($username);
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

    private function getRole($username) {
	return $this->db->table(self::TABLE_NAME)->select(self::TABLE_ROLE)->where(self::TABLE_USERNAME, $username);
    }

    /**
     * Detect config values
     * @param $value
     */
    private function detectValue($value) {
	if ($value == "") {
	    throw new \Exception(self::ERROR_MESSAGE_CONF_DETECT);
	}
	return $value;
    }

    /**
     * Detect if user exist in database (???)
     * 
     * @param string $username
     * @return boolean
     */
    private function databaseDetect($username) {
	$temp = $this->db->table(self::TABLE_NAME)->count('*')->where('username = ?', $username);

	// If user exist in database
	if ($temp > 0) {
	    return TRUE;
	}
	return FALSE;
    }

    /**
     * Add new user to the database and set default role(guest)
     * 
     * @param string $username
     * @throws Exception
     */
    private function add($username) {
	$data = [
	    'username' => $username,
	    'role' => 'guest',
	    'registred' => new Date,
	];

	try {
	    $this->db->table(self::TABLE_NAME)->insert($data);
	} catch (\Exception $ex) {
	    throw new \Exception('Error: ', $ex->getMessage);
	}
    }

}
