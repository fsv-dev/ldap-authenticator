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


class Ldap
{
	/**
	 * @param $server
	 * @param $port
	 *
	 * @return resource
	 */
	public function ldap_connect($server, $port)
	{
		return \ldap_connect($server, $port);
	}

	/**
	 * @param $ldap
	 * @param int $version default 3
	 *
	 * @return bool
	 */
	public function ldap_set_option($ldap, $version = 3)
	{
		return \ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, $version);
	}

	/**
	 * @param $ldap
	 *
	 * @param null $dn
	 * @param null $password
	 *
	 * @return bool
	 */
	public function ldap_bind($ldap, $dn = NULL, $password = NULL)
	{
		return \ldap_bind($ldap, $dn, $password);
	}

	/**
	 * @param $ldap
	 * @param $dn
	 * @param $username
	 *
	 * @return resource
	 */
	public function ldap_search($ldap, $dn, $username)
	{
		return \ldap_search($ldap, $dn, $username);
	}

	public function ldap_count_entries($ldap, $res)
	{
		return \ldap_count_entries($ldap, $res);
	}

	public function ldap_first_entry($ldap, $res)
	{
		return \ldap_first_entry($ldap, $res);
	}

	public function ldap_get_dn($ldap, $entry)
	{
		return \ldap_get_dn($ldap, $entry);
	}
}