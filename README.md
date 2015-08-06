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
    	authenticateOption: 'strict' // Optional (default FALSE)
    	createDatabase: FALSE // Optional (default FALSE)
    	
```

### Parameters
**authenticateOption**

Value | Description
------------ | -------------
skipDatabase | For authorization is required only LDAP. Ldap\Authenticator set for all users role guest
onlyPrivilegedUsers | Require LDAP authorization and if user also exist in local database, Ldap\Authenticator load user's role. For others set role guest
strict (default value) | Require both LDAP and database authorization. Roles load from database


**createDatabase** - default value is FALSE. If is set TRUE, Ldap\DatabaseManager detect if table [users] exists and if not, create it.
