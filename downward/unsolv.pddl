( define  (domain network_final)
(:requirements :strips :typing)
(:types server software version file code connection config adversary accesstoken request location functionality buffer response attack function path pathname)
(:predicates 
                                                              ;Common Predicates;

 (access-web ?Acc4 - accesstoken)
 (access-db ?Acc1 - accesstoken)
 (access-ftp ?Acc2 - accesstoken)
 (access-dns ?Acc5 - accesstoken)
 (access-admin ?Acc3 - accesstoken)
 (attacker ?Attacker - adversary)
 (remote-access ?Internet - connection)
 (main-server ?server - server)
 (safe-server ?server - server)
 (compromised-server ?CompServ - server)

 
                                                      ;;;;;;;;;; Predicates for Web Server ;;;;;;;;;;;;

 (configuration ?config - config)
 (reach-to-web ?Server - server)
 (connected-to-web ?Server - server)
 (execute-file-in-config ?File - file ?config - config)
 (access-to-web-software ?software - software ?Attacker - adversary)
 (execute-code ?server - server ?Code - code)
 (web-file ?File - file)
 (web-server ?Server - server)
 (web-code ?Code - code)
 (web-software ?Software - software)
 (web-version ?Version - version)
 (access-to-server ?server - server ?Attacker - adversary ?Internet - connection)
                                                       ;;;;;;;;;; Predicates for Database Server ;;;;;;;;;;;;;
 (sql-injection ?File - file ?Software - software)
 (login-page)
 (login-field)
 (use-software ?Software - software ?Attacker - adversary)
 (execute-code-in-login-feild ?Code - code)
 (move-to-database ?server - server)
 (access-granted-to-db ?server - server ?Acc1 - accesstoken)
 (access-to-sql-software ?software - software ?Attacker - adversary)
 (reach-to-db ?Server - server)
 (connected-to-db ?Server - server)
 (sql-file ?File - file)
 (sql-server ?Server - server)
 (sql-code ?Code - code)
 (sql-software ?Software - software)
 (sql-version ?Version - version)
)


(:action Web-Server-Compromised
:parameters (?c1 - code ?serv1 - server)
:precondition
(and
( safe-server ?serv1 )
( main-server ?serv1 )
( execute-code ?serv1 ?c1 )

)
:effect
(and
( compromised-server ?serv1 )

)
)

(:action CVE-2014-1466-connected-to-Database-Software
:parameters (?serv2 - server ?s2 - software ?v2 - version ?f2 - file ?Attacker - adversary ?Internet - connection ?Access - accesstoken)
:precondition
(and
( access-granted-to-db ?serv2 ?Access )
( sql-version ?v2 )
( attacker ?Attacker )
( main-server ?serv2 )
( sql-file ?f2 )
( sql-software ?s2 )
( safe-server ?serv2 )
( move-to-database ?serv2 )
( remote-access ?Internet )

)
:effect
(and
( access-to-sql-software ?s2 ?Attacker )
( access-to-server ?serv2 ?Attacker ?Internet )

)
)

(:action Compromised-Database-Server
:parameters ()
:precondition
(and
( attacker ?Attacker )
( execute-code-in-login-feild ?c2 )

)
:effect
(and
( compromised-server ?serv2 )

)
)

(:action Connected-to-Web-Server
:parameters (?serv1 - server)
:precondition
(and
( connected-to-web ?serv1 )

)
:effect
(and
( reach-to-web ?serv1 )

)
)

(:action CVE-2014-1466-Attacker-moves-to-database-server
:parameters (?serv1 - server ?serv2 - server ?s1 - software ?v1 - version ?s2 - software ?v2 - version ?Access - accesstoken)
:precondition
(and
( web-software ?s1 )
( compromised-server ?serv1 )
( web-server ?serv1 )
( web-version ?v1 )
( sql-server ?serv2 )
( access-db ?Access )

)
:effect
(and
( safe-server ?serv2 )
( main-server ?serv2 )
( sql-software ?s2 )
( access-granted-to-db ?serv2 ?Access )
( sql-version ?v2 )
( move-to-database ?serv2 )
(not ( web-version ?v1 ))
(not ( web-software ?s1 ))
)
)

(:action CVE-2015-1635-sends-malicious-request-to-config
:parameters (?serv1 - server ?f1 - file ?s1 - software ?config - config ?Attacker - adversary)
:precondition
(and
( main-server ?serv1 )
( configuration ?config )
( web-file ?f1 )
( safe-server ?serv1 )
( access-to-web-software ?s1 ?Attacker )

)
:effect
(and
( execute-file-in-config ?f1 ?config )

)
)

(:action attacker-connected-to-web-server
:parameters (?serv1 - server ?Attacker - adversary ?Internet - connection)
:precondition
(and
( attacker ?Attacker )
( remote-access ?Internet )
( connected-to-web ?serv1 )

)
:effect
(and
( safe-server ?serv1 )
( main-server ?serv1 )
( access-to-server ?serv1 ?Attacker ?Internet )

)
)

(:action CVE-2014-1466-SQL-Injection-to-Open-mysql
:parameters (?serv2 - server ?s2 - software ?f2 - file ?Attacker - adversary ?Internet - connection)
:precondition
(and
( sql-server ?serv2 )
( sql-file ?f2 )
( access-to-server ?serv2 ?Attacker ?Internet )
( access-to-sql-software ?s2 ?Attacker )

)
:effect
(and
( sql-injection ?f2 ?s2 )
( use-software ?s2 ?Attacker )

)
)

(:action CVE-2015-1635-remote-attack-intiation
:parameters (?serv1 - server ?s1 - software ?v1 - version  ?Attacker - adversary ?Internet - connection)
:precondition
(and
( safe-server ?serv1 )
( access-to-server ?serv1 ?Attacker ?Internet )
( web-version ?v1 )
( main-server ?serv1 )
( web-software ?s1 )

)
:effect
(and
( access-to-web-software ?s1 ?Attacker )

)
)

(:action Connected-to-Database-Server
:parameters (?serv2 - server)
:precondition
(and
( connected-to-db ?serv2 )

)
:effect
(and
( reach-to-db ?serv2 )

)
)

(:action CVE-2015-1635-privilige-to-execute-arbitrary-code-in-Web-Server
:parameters (?serv1 - server ?f1 - file ?c1 - code  ?config - config)
:precondition
(and
( web-code ?c1 )
( main-server ?serv1 )
( execute-file-in-config ?f1 ?config )
( safe-server ?serv1 )

)
:effect
(and
( execute-code ?serv1 ?c1 )
(not ( execute-file-in-config ?f1 ?config ))
(not ( web-file ?f1 ))
(not ( configuration ?config ))
)
)

(:action CVE-2014-1466-access-to-login-field
:parameters (?c2 - code)
:precondition
(and
( sql-code ?c2 )
( login-page )

)
:effect
(and
( login-field )

)
)

(:action CVE-2014-1466-execute-arbitrary-commands-via
:parameters (?c2 - code)
:precondition
(and
( login-field )
( sql-code ?c2 )

)
:effect
(and
( execute-code-in-login-feild ?c2 )

)
)

(:action CVE-2014-1466-access-to-login-page
:parameters ( ?s2 - software ?f2 - file ?Attacker - adversary)
:precondition
(and
( sql-injection ?f2 ?s2 )
( use-software ?s2 ?Attacker )

)
:effect
(and
( login-page )

)
)

(:action Access-to-Webserver
:parameters (?serv1 - server ?Access - accesstoken ?Internet - connection)
:precondition
(and
( web-server ?serv1 )
( access-web ?Access )
( remote-access ?Internet )

)
:effect
(and
( connected-to-web ?serv1 )

)
)

(:action Access-to-Database-Server
:parameters (?serv1 - server ?serv2 - server ?Access - accesstoken)
:precondition
(and
( sql-server ?serv2 )
( reach-to-web ?serv1 )
( access-db ?Access )

)
:effect
(and
( connected-to-db ?serv2 )

)
)


)
