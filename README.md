# ldap-authentificator
Nette\DI extension for provide LDAP authenticate

## Install:
<pre>
composer require fsv-dev/ldap-authenticator
</pre>

## Configuration:

### config.neon
<pre>
extensions:
	ldap: Ldap\DI\LdapExtension
	
	ldap:
    	server: 'ldaps://ldap.com'
    	port: 636 // Optional (default 636)
    	dn: 'dc=cz'
    	skipDatabase: TRUE // Optional (default FALSE)
</pre>

### Parameters
**skipDatabase** - default value FALSE. If is set TRUE, Ldap\Authenticator provide authentication only via LDAP server. All
users set as guest role