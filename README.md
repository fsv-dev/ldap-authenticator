# ldap-authentificator
[![License](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://img.shields.io/badge/license-GPLv2-blue.svg)
[![Build Status](https://travis-ci.org/fsv-dev/ldap-authenticator.svg?branch=master)](https://travis-ci.org/fsv-dev/ldap-authenticator)
[![Latest stable](https://img.shields.io/packagist/v/fsv-dev/ldap-authenticator.svg)](https://packagist.org/packages/fsv-dev/ldap-authenticator)

Nette\DI extension for provide LDAP authenticate via ldap servers on Charles University in Prague

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
    user: 'username' 
    password: 'passWorD'
```