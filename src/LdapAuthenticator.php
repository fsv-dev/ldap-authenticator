<?php
/**
 * This file is part of the fsv-dev/ldap-authenticator
 *
 * Copyright (c) 2015 Vaclav Kraus (krauva@gmail.com)
 *
 * For the full copyright and license information, please view the file license.txt that was distributed with this
 * source code.
 */

namespace Ldap;

use Nette\Database\Context;
use Nette\Security as NS;
use Nette;


/**
 * Description of SecurityAuthenticator
 *
 * @author Vaclav Kraus <krauva@gmail.com>
 */
class Authenticator extends Nette\Object implements NS\IAuthenticator
{
	private $server, $port, $dn, $db, $ldap, $dbManager, $createDatabase, $authenticateOption;

	const
		ERROR_MESSAGE_AUTH_USER = 'Neplatne uzivatelske jmeno.',
		ERROR_MESSAGE_AUTH_PASS = 'Neplatne heslo.',
		ERROR_MESSAGE_CONF_DETECT = 'Value of LdapAuthenticator config not be empty',
		ERROR_MESSAGE_LDAP_BIND = 'Failed to bind to LDAP server',
		ERROR_MESSAGE_DB_USER_NOT_FOUND = 'Nemate opravneni k pristupu do teto aplikace.',
		TABLE_NAME = 'users',
		TABLE_ROLE = 'role',
		TABLE_DATA = 'data',
		TABLE_USERNAME = 'uid',
		TABLE_USER_ID = 'cuniPersonalId';

	/**
	 * @param DatabaseManager $dbManager
	 * @param Ldap $ldap
	 * @param Context $db
	 */
	public function __construct(DatabaseManager $dbManager, Ldap $ldap, Context $db)
	{
		$this->db = $db;
		$this->ldap = $ldap;
		$this->dbManager = $dbManager;
	}

	public function setServer($server)
	{
		$this->server = $server;
	}

	public function setPort($port)
	{
		$this->port = $port;
	}

	public function setDn($dn)
	{
		$this->dn = $dn;
	}

	public function setCreateDatabase($createDatabase)
	{
		$this->createDatabase = $createDatabase;
	}

	public function setAuthenticateOption($option)
	{
		$this->authenticateOption = $option;
	}

	/**
	 * Performs an authentication.
	 *
	 * @param array $credentials
	 *
	 * @return NS\Identity
	 * @throws NS\AuthenticationException
	 * @throws \Exception
	 */
	public function authenticate(array $credentials)
	{
		list($username, $password) = $credentials;

		if ($this->createDatabase == TRUE) { // Generate SQL table for users
			if ($this->dbManager->tableDetect() == FALSE) {
				$this->dbManager->create();
			}
		}

		$ldap = $this->ldap->ldap_connect($this->server, $this->port);
		$this->ldap->ldap_set_option($ldap); //Set LDAP_OPT_PROTOCOL_VERSION (default 3)

		$res = $this->ldap->ldap_bind($ldap);
		if (!$res) {
			throw new \Exception(self::ERROR_MESSAGE_LDAP_BIND);
		}

		$res = $this->ldap->ldap_search($ldap, $this->dn, $this->searchString($username));
		if ($this->ldap->ldap_count_entries($ldap, $res) != 1) {
			throw new Nette\Security\AuthenticationException(self::ERROR_MESSAGE_AUTH_USER, self::IDENTITY_NOT_FOUND);
		}

		$entry = $this->ldap->ldap_first_entry($ldap, $res);
		$dn = $this->ldap->ldap_get_dn($ldap, $entry);

		//bind na prihlasovaneho uzivatele
		$res = $this->ldap->ldap_bind($ldap, $dn, $password);
		if (!$res) {
			throw new Nette\Security\AuthenticationException(self::ERROR_MESSAGE_AUTH_PASS, self::INVALID_CREDENTIAL);
		}

		// Full authenticate process
		if ($this->authenticateOption == FALSE) {
			if ($this->databaseDetect($username) == TRUE) {
				return new NS\Identity($username, $this->getRole($username)['role'], $this->getData($username));
			}
			throw new Nette\Security\AuthenticationException(self::ERROR_MESSAGE_DB_USER_NOT_FOUND, self::IDENTITY_NOT_FOUND);
		}
		// Skipping database
		if ($this->authenticateOption == "skipDatabase") {
			return new NS\Identity($username, 'guest');
		}
		// Only privileges
		if ($this->authenticateOption == "onlyPrivilegedUsers") {
			if ($this->databaseDetect($username) == TRUE) {
				return new NS\Identity($username, $this->getRole($username)['role'], $this->getData($username));
			}
			return new NS\Identity($username, 'guest');
		}
	}

	/**
	 * Modify filter based on login name string|number
	 *
	 * @param string $string
	 *
	 * @return string
	 */
	private function searchString($string)
	{
		if (is_numeric($string)) {
			return "(cunipersonalid=$string)";
		}
		return "(uid=$string)";
	}

	/**
	 * Return role for current user.
	 *
	 * @param string|int $username
	 *
	 * @return array
	 */
	private function getRole($username)
	{
		if (is_numeric($username)) {
			return $this->db->table(self::TABLE_NAME)->select(self::TABLE_ROLE)->where(self::TABLE_USER_ID, $username)->fetch();
		}
		return $this->db->table(self::TABLE_NAME)->select(self::TABLE_ROLE)->where(self::TABLE_USERNAME, $username)->fetch();
	}

	/**
	 * Return data for current user.
	 *
	 * @param string|int $username
	 *
	 * @return array
	 */
	private function getData($username)
	{
		if (is_numeric($username)) {
			$temp = $this->db->table(self::TABLE_NAME)->select(self::TABLE_DATA)->where(self::TABLE_USER_ID, $username)->fetch();
		} else {
			$temp = $this->db->table(self::TABLE_NAME)->select(self::TABLE_DATA)->where(self::TABLE_USERNAME, $username)->fetch();
		}

		return explode(',', $temp['data']);
	}

	/**
	 * Detect if user exist in database (???)
	 *
	 * @param string $username
	 *
	 * @return boolean
	 */
	private function databaseDetect($username)
	{
		if (is_numeric($username)) {
			$temp = $this->db->table(self::TABLE_NAME)->where('cuniPersonalId = ?', $username)->count();
		} else {
			$temp = $this->db->table(self::TABLE_NAME)->where('uid = ?', $username)->count();
		}

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
	 *
	 * @throws \Exception
	 */
	private function add($username)
	{
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
