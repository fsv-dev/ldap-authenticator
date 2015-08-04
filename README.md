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
    	server: 'ldaps://ldap.cuni.cz'
    	port: 636
    	dn: 'dc=cuni,dc=cz'
    	skipDatabase: TRUE
</pre>

### Parameters
**skipDatabase** - default value FALSE. If is set TRUE, Ldap\Authenticator provide authentication only via LDAP server. All
users set as guest role