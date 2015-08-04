# ldap-authentificator
[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://img.shields.io/badge/license-GPLv2-blue.svg)

Nette\DI extension for provide LDAP authenticate

## Install
```sh
$ composer require fsv-dev/ldap-authenticator
```

## Configuration

### config.neon
```php

extensions:
	ldap: Ldap\DI\LdapExtension
	
	ldap:
    	server: 'ldaps://ldap.com'
    	port: 636 // Optional (default 636)
    	dn: 'dc=cz'
    	skipDatabase: TRUE // Optional (default FALSE)
    	createDatabase: TRUE // Optional (default FALSE)
    	
```

### Parameters
**skipDatabase** - default value FALSE. If is set TRUE, Ldap\Authenticator provide authentication only via LDAP server. All
users set as guest role

**createDatabase** - default value is FALSE. If is set TRUE, Ldap\DatabaseManager detect if table [users] exists and if not, create it.
