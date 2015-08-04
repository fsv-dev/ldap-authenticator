# ldap-authentificator
Nette\DI extension for provide LDAP authenticate

Install:
--------
<pre>
composer require ----
</pre>

Configuration:
--------------

config.neon
===========
<pre>
extensions:
	ldap: Ldap\DI\LdapExtension
	
	ldap:
    	server: 'ldaps://ldap.cuni.cz'
    	port: 636
    	dn: 'dc=cuni,dc=cz'
    	skipDatabase: TRUE
</pre>

Parameters
==========
skipDatabase - default value FALSE. If isset TRUE, Ldap\Authenticator provide authentication only via LDAP server. All
users set as guest role