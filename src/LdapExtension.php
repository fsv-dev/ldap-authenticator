<?php
/**
 * Created by PhpStorm.
 * User: Vasek
 * Date: 3.8.2015
 * Time: 23:53
 */

namespace Ldap\DI;

use Nette;


class LdapExtension extends Nette\DI\CompilerExtension
{
	/** @var array Default values */
	private $default = [
		'skipDatabase' => false
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
			->addSetup('setSkipDatabase', array($config['skipDatabase']))
			->setInject(FALSE);

		$builder->addDefinition($this->prefix('ldapLib'))
			->setClass('Ldap\Ldap');
	}
}