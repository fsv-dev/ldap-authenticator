<?php
/**
 * This file is part of the ldap-authentificator
 *
 * Copyright (c) 2015 Vaclav Kraus (krauva@gmail.com)
 *
 * For the full copyright and license information, please view the file license.txt that was distributed with this
 * source code.
 */

namespace Ldap;

use Nette;

class DatabaseManager extends Nette\Object
{
	private $db;

	public function __construct(\Nette\Database\Context $db)
	{
		$this->db = $db;
	}

	/**
	 * Create table if not exist.
	 */
	public function create()
	{
		$query = "
				CREATE TABLE IF NOT EXISTS users  (
  					id INT(11) NOT NULL AUTO_INCREMENT,
  					uid VARCHAR(100) COLLATE utf8_czech_ci NOT NULL,
  					cuniPersonalId INT(10) NOT NULL,
  					email VARCHAR(100) COLLATE utf8_czech_ci NOT NULL,
  					role VARCHAR(100) COLLATE utf8_czech_ci NOT NULL,
  					PRIMARY KEY (id),
  					UNIQUE KEY uid (uid)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_czech_ci
				";
		$this->db->query($query);
	}

	public function tableDetect()
	{
		$result = $this->db->query("SHOW TABLES LIKE 'users'")->fetch();

		if($result == FALSE){
			return FALSE;
		}
		return TRUE;
	}
}