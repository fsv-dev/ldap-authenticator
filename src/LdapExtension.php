<?php
/**
 * This file is part of the fsv-dev/ldap-authenticator
 *
 * Copyright (c) 2015 Vaclav Kraus (krauva@gmail.com)
 *
 * For the full copyright and license information, please view the file license.txt that was distributed with this
 * source code.
 */

namespace Ldap\DI;

use Nette;


class LdapExtension extends Nette\DI\CompilerExtension
{
	/** @var array Default values */
	private $default = [
		'port' => 636,
		'authenticateOption' => FALSE,
		'createDatabase' => FALSE,
	];

	public function loadConfiguration()
	{
		$config = $this->getConfig($this->default);

		$builder = $this->getContainerBuilder();
		$builder->addDefinition($this->prefix('ldap'))
			->setClass('Ldap\Authenticator')
			->addSetup('setServer', array($config['server']))
			->addSetup('setPort', array($config['port']))
			->addSetup('setDn', array($config['dn']))
			->addSetup('setAuthenticateOption', array($config['authenticateOption']))
			->addSetup('setCreateDatabase', array($config['createDatabase']))
			->setInject(FALSE);

		$builder->addDefinition($this->prefix('ldapLib'))
			->setClass('Ldap\Ldap');

		$builder->addDefinition($this->prefix('ldapDatabaseManager'))
			->setClass('Ldap\DatabaseManager');
	}
}