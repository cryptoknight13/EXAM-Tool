( define  (domain network_final)
(:requirements :strips :typing)
(:types webserver sqlserver ftpserver adminserver dnsserver software version file code connection config adversary accesstoken request location functionality buffer response attack function path pathname loginpage admindata environment malserver daemon malsoftware object cstring)
(:predicates 
                                                              ;Common Predicates;

 (access-web ?Acc4 - accesstoken)
 (access-db ?Acc1 - accesstoken)
 (access-ftp ?Acc2 - accesstoken)
 (access-dns ?Acc5 - accesstoken)
 (access-admin ?Acc3 - accesstoken)
 (attacker ?Attacker - adversary)
 (remote-access ?Internet - connection)
 (compromised-web-server ?CompServ - webserver)
 (compromised-sql-server ?CompServ - sqlserver)
 (compromised-ftp-server ?CompServ - ftpserver)
 (compromised-admin-server ?CompServ - adminserver)
 (compromised-dns-server ?CompServ - dnsserver)
 (has-connected ?web - webserver ?sql - sqlserver ?amdin - adminserver ?ftp - ftpserver ?dns - dnsserver)
 
                                                      ;;;;;;;;;; Predicates for Web Server ;;;;;;;;;;;;

 (configuration ?config - config)
 (reach-to-web ?web - webserver)
 (connected-to-web ?web - webserver)
 (execute-file-in-config ?File - file ?config - config)
 (access-to-web-software ?software - software ?Attacker - adversary)
 (execute-code ?web - webserver ?Code - code)
 (web-file ?File - file)
 (web-server ?web - webserver)
 (web-code ?Code - code)
 (web-software ?Software - software)
 (web-version ?Version - version)
 (access-to-web-server ?web - webserver ?Attacker - adversary ?Internet - connection)
                                                      ;;;;;;;;;; Predicates for Database Server ;;;;;;;;;;;;;
 (sql-injection ?File - file ?Software - software)
 (login-page ?Page - loginpage)
 (login-field)
 (use-software ?Software - software ?Attacker - adversary)
 (execute-code-in-login-feild ?Code - code)
 (move-to-database ?sql - sqlserver)
 (access-granted-to-db ?sql - sqlserver ?Acc1 - accesstoken)
 (access-to-sql-software ?software - software ?Attacker - adversary)
 (reach-to-db ?sql - sqlserver)
 (connected-to-db ?sql - sqlserver)
 (sql-file ?File - file)
 (sql-server ?sql - sqlserver)
 (sql-code ?Code - code)
 (sql-software ?Software - software)
 (sql-version ?Version - version)
 (access-to-sql-server ?sql - sqlserver ?Attacker - adversary ?Internet - connection)
 (access-login-page-via-software ?Page - loginpage)
                                                ;; Modelling another vulnerability for database;;;;;

 (sql-env ?Env - environment)
 (access-to-sql-server-2 ?sql - sqlserver ?Attacker - adversary)
(sql-software-2 ?Software - software)
 (sql-version-2 ?Version - version)
 (access-to-sql-software-2 ?sql - sqlserver ?Software - software ?version - version ?Attacker - adversary)
 (sql-malicious-server ?malserv - malserver)
 (sql-daemon ?daemon - daemon)
 (replace-daemond ?daemon - daemon ?malserv - malserver ?sql - sqlserver ?Attacker - adversary)
 (sql-attack ?Attack - attack )
 (execute-unauthorized-requests ?Env - environment ?Attack - attack ?sql - sqlserver ?Attacker - adversary)

                                                    ;;Modelling CVE-2018-1058 : Attacker --> Database Direct
 (sql-software-3 ?s3 - software)
 (sql-version-3 ?v3 - version)
 (attacker-with-user-account ?Attacker - adversary)
 (sql-flaw ?Flaw - malsoftware)
 (sql-code-2 ?c3 - code)
 (attacker-exploits-vulnerable-software ?sql - sqlserver ?s3 - software ?v3 - version ?Access - accesstoken ?Internet - connection)
 (attacker-gains-elevated-permissions ?s3 - software ?v3 - version ?Attacker - adversary ?Flaw - malsoftware ?Internet - connection)
 (attacker-executes-malicious-SQL-code-in-postgresql ?Attacker - adversary ?c3 - code ?s3 - software ?v3 - version)
  								
                                ;;;Predicates for CVE-2021-20329 : Attacker --> DNS Server --> Database Server;;;;
 								
 (attacker-exploits-server ?serv2 - sqlserver ?s6 - software ?v6 - version)
 (access-to-sql-software-5 ?s6 - software ?v6 - version ?serv2 - sqlserver)
 (sql-software-5 ?s6 - software)
 (sql-version-5 ?v6 - version)
 (go-object ?obj - object)
 (specific-cstring ?string - cstring)
 (attacker-injects-additional-fields ?obj - object ?string - cstring ?s6 - software ?v6 - version ?serv2 - sqlserver)
 
                                                    ;;; Predicates for FTP Server
 (request-ftp ?Request - request)
 (exe-file ?File - file)
 (directory ?Directory - location)
 (has-upload-file ?File - file ?Attacker - adversary ?Functionality - functionality)
 (has-upload-exe-extension ?File - file ?Directory - location ?Attacker - adversary)
 (functionality-exploited ?File - file ?Functionality - Functionality)
 (access-to-avatar ?Software - software ?Version - version ?Attacker - adversary)
 (access-to-exe-file ?File - file ?Directory - location ?Request - request)
 (has-authentication ?server - ftpserver ?Attacker - adversary ?Internet - connection) 
 (move-to-FTP ?server - ftpserver)
 (access-granted-to-ftp ?server - ftpserver ?Acc2 - accesstoken)
 (execution-success ?server - ftpserver ?code - code ?Attacker - adversary)   
 (reach-to-ftp ?Server - ftpserver)
 (connected-to-ftp ?Server - ftpserver)
 (ftp-file ?File - file)
 (ftp-server ?Server - ftpserver)
 (ftp-code ?Code - code)
 (ftp-software ?Software - software)
 (ftp-functionality ?Functionality - functionality)
 (ftp-version ?Version - version)
                                                    ;Predicates for Admin Server;
 (buffer-overflow ?Buffer - buffer)
 (move-to-admin ?server - adminserver)
 (admin-function ?Function - function)
 (admin-path ?Path - path)
 (admin-file ?file - file)
 (admin-server ?server - adminserver)
 (admin-software ?software - software)
 (admin-version ?version - version)
 (longpath ?Pathname - pathname)
 (access-to-admin-software ?Sofware - software ?Attacker - adversary)
 (admin-attack ?Attack - attack)
 (connected-to-admin ?serv4 - adminserver)
 (dos-attack-execution ?Server - adminserver ?Attack - attack ?Attacker - adversary)
 (request-to-service ?File - file ?Path - path ?Function - function)
 (access-granted-to-admin ?server - adminserver ?Acc3 - accesstoken)
   ;;; Admin via DNS;;;;
(move-to-admin-via-dns ?admin - adminserver ?dns - dnsserver)
(admin-software-2 ?software - software)
(admin-version-2 ?version - version)
(access-to-admin-software-2 ?Sofware - software ?Version - version ?Attacker - adversary)
(information ?Data - admindata)
(download-data ?Data - admindata ?Attacker - adversary)


								    ;; Predicates for CVE-2019-0211 ;;;
(admin-software-4 ?s4 - software)
(admin-version-4 ?v4 - version)
(admin-code ?c4 - code)
(attacker-gains-elevated-privileges-in-admin-software ?s4 - software ?v4 - version ?Attacker - adversary ?serv4 - adminserver)
(attacker-executes-arbitrary-code ?c4 - code ?serv4 - adminserver ?Attacker - adversary)
								    ;;; Predicates for CVE-2020-0688 : Attcker --> Web Server --> FTP --> Admin;;;
 (admin-software-3 ?s5 - software)
 (admin-code-2 ?c5 - code)
 (access-to-admin-server-3 ?s5 - software ?Attacker - adversary ?serv4 - adminserver)
 (attacker-executes-arbitrary-code-in-HTTP ?c5 - code ?s5 - software ?serv4 - adminserver ?Attacker - adversary)
 
                                                                    ;;Predicates for DNS Server
 (access-to-dns-software ?software - software ?Attacker - adversary)
 (access-to-dns-server ?server - dnsserver ?Attacker - adversary ?Internet - connection)
 (exploited ?software - software ?Buffer - buffer)
 (response-dns ?Response - response)
 (dns-attack ?Attack - attack)
 (dos-attack-in-dns ?server - dnsserver ?Attack - attack)
 (connected-to-dns ?server - dnsserver)
 (execute-code-in-dns ?server - dnsserver ?Code - code)
 (dns-server ?server - dnsserver)
 (dns-software ?software - software)
 (dns-version ?version - version)
 (dns-code ?code - code)
)
                                                     ;Actions for Web Server;

(:action Access-to-Webserver
    :parameters (?serv1 - webserver ?serv2 - sqlserver ?serv3 - adminserver ?serv4 - ftpserver ?serv5 - dnsserver ?Access - accesstoken ?Internet - connection)
    :precondition(and
        (access-web ?Access)
        (web-server ?serv1)
        (dns-server ?serv5)
        (remote-access ?Internet)
        (has-connected ?serv1 ?serv2 ?serv3 ?serv4 ?serv5)
    )
    :effect(and
        (connected-to-web ?serv1)
    )
)
(:action attacker-connected-to-web-server-exploits-CVE-2015-1635
    :parameters (?serv1 - webserver ?Attacker - adversary ?Internet - connection)
    :precondition (and
        (connected-to-web ?serv1)
        (attacker ?Attacker)
        (remote-access ?Internet)
        (web-server ?serv1)
        
    )
    :effect (and
        (access-to-web-server ?serv1 ?Attacker ?Internet)
    )
)
(:action attacker-exploits-vulnerable-software-version
    :parameters (?serv1 - webserver ?s1 - software ?v1 - version  ?Attacker - adversary ?Internet - connection)
    :precondition (and 
        (access-to-web-server ?serv1 ?Attacker ?Internet)
        (web-software ?s1)
        (web-version ?v1)
        (web-server ?serv1)
    )
    :effect (and 
        (access-to-web-software ?s1 ?Attacker)
    )
)

(:action attacker-changes-server-configuration
    :parameters (?serv1 - webserver ?f1 - file ?s1 - software ?config - config ?Attacker - adversary)
    :precondition (and
        (web-file ?f1)
        (access-to-web-software ?s1 ?Attacker)
        (configuration ?config)
    )
    :effect (and
        (execute-file-in-config ?f1 ?config)
    )
)

(:action attacker-gains-privileges-by-executing-malicious-file
    :parameters (?serv1 - webserver ?f1 - file ?c1 - code  ?config - config)
    :precondition (and
        (execute-file-in-config ?f1 ?config)
        (web-code ?c1)
    )
    :effect (and
        (execute-code ?serv1 ?c1)
        (not (web-file ?f1))
        (not (execute-file-in-config ?f1 ?config))
        (not (configuration ?config))
    )
 )
 (:action attacker-execute-code-to-compromise-Web-Server
    :parameters (?c1 - code ?serv1 - webserver)
    :precondition (and
        (web-server ?serv1)
        (execute-code ?serv1 ?c1)
    )
    :effect (and
        (compromised-web-server ?serv1)
        )
  )
  (:action Connected-to-Web-Server
    :parameters (?serv1 - webserver)
    :precondition (and
        (connected-to-web ?serv1)
    )
    :effect(and
        (reach-to-web ?serv1)
    )
  )
 
                                   ;;;;;;;;;; Actions for Database Server through CVE-2014-1466 ;;;;;;;;;;;;;
                                   
(:action Access-to-Database-Server
    :parameters (?serv1 - webserver ?serv2 - sqlserver ?Access - accesstoken)
    :precondition(and
        (access-db ?Access)
        (reach-to-web ?serv1)
        (sql-server ?serv2)
    )
    :effect(and
        (connected-to-db ?serv2)
    )
)                            
(:action Attacker-moves-to-database-server-exploits-CVE-2014-1466
    :parameters (?serv1 - webserver ?serv2 - sqlserver ?s1 - software ?v1 - version ?Access - accesstoken)
    :precondition (and
        (access-db ?Access)
        (compromised-web-server ?serv1)
        (web-server ?serv1)
        (web-version ?v1)
        (sql-server ?serv2)
        (web-software ?s1)
        
    )
    :effect (and
        (move-to-database ?serv2)
        (not (web-software ?s1))
        (not (web-version ?v1))
        (access-granted-to-db ?serv2 ?Access)
    )
 
 )
 
 (:action attacker-connected-to-vulnerable-Software-Version
    :parameters (?serv2 - sqlserver ?s2 - software ?v2 - version ?f2 - file ?Attacker - adversary ?Internet - connection ?Access - accesstoken)
    :precondition (and
        (access-granted-to-db ?serv2 ?Access)
        (move-to-database ?serv2)
        (remote-access ?Internet)
        (attacker ?Attacker)
        (sql-software ?s2)
        (sql-file ?f2)
        (sql-version ?v2)
    )
    :effect (and
        (access-to-sql-software ?s2 ?Attacker)
        (access-to-sql-server ?serv2 ?Attacker ?Internet)
    )
 )
 (:action attacker-uploads-malicious-SQL-code-to-software   
    :parameters (?serv2 - sqlserver ?s2 - software ?f2 - file ?Attacker - adversary ?Internet - connection)
    :precondition (and
        (sql-file ?f2)
        (sql-server ?serv2)
        (access-to-sql-software ?s2 ?Attacker)
        (access-to-sql-server ?serv2 ?Attacker ?Internet)
    )
    :effect (and
        (use-software ?s2 ?Attacker)
        (sql-injection ?f2 ?s2)
    )
 )
 (:action attacker-opens-login-page-in-application-through-software
    :parameters ( ?s2 - software ?f2 - file ?Attacker - adversary ?page - loginpage)
    :precondition (and
        (sql-injection ?f2 ?s2)
        (use-software ?s2 ?Attacker)
        (login-page ?page)
    )
    :effect (and
        (access-login-page-via-software ?page)
    )
 )
 (:action attacker-gains-access-to-login-field
    :parameters (?c2 - code ?serv2 - sqlserver ?page - loginpage)
    :precondition (and (access-login-page-via-software ?page) (sql-code ?c2) (sql-server ?serv2))
    :effect (and
     (login-field)
 )
 )
 (:action attacker-executes-malicious-SQL-code-in-login-field
    :parameters (?c2 - code)
    :precondition (and
        (sql-code ?c2)
        (login-field)
    )
    :effect (and
        (execute-code-in-login-feild ?c2)
    )
 )
 (:action attacker-compromises-Database-Server
    :parameters (?serv2 - sqlserver ?c2 - code ?Attacker - adversary)
    :precondition (and
        (attacker ?Attacker)
        (sql-server ?serv2)
        (execute-code-in-login-feild ?c2)
    )
    :effect(and
        (compromised-sql-server ?serv2)
    )
 )
  (:action Connected-to-Database-Server
    :parameters (?serv2 - sqlserver)
    :precondition (and
        (connected-to-db ?serv2)
    )
    :effect(and
        (reach-to-db ?serv2)
    )
  )
                                        ;;;;;;;;;; Database Server Action for CVE-2020-13295 ;;;;;;;;;

(:action attacker-connected-to-database-server-to-exploits-CVE-2020-13295
    :parameters (?web - webserver ?sql - sqlserver ?Attacker - adversary ?env - environment)
    :precondition (and (compromised-web-server ?web) (sql-server ?sql) (attacker ?Attacker))
    :effect (and
        (access-to-sql-server-2 ?sql ?Attacker)
    )
)
 (:action attacker-exploits-vulnerable-software-version-in-database-server
    :parameters (?sql - sqlserver ?Attacker - adversary ?soft - software ?ver - version)
    :precondition (and (access-to-sql-server-2 ?sql ?Attacker) (sql-software-2 ?soft)(sql-version-2 ?ver))
    :effect (and
        (access-to-sql-software-2 ?sql ?soft ?ver ?Attacker)
    )
)
(:action attacker-replaces-daemond-with-malicious-server
    :parameters (?sql - sqlserver ?Attacker - adversary ?soft - software ?ver - version ?malserv - malserver ?daemon - daemon)
    :precondition (and (access-to-sql-software-2 ?sql ?soft ?ver ?Attacker)(sql-malicious-server ?malserv) (sql-daemon ?daemon))
    :effect (and
        (replace-daemond ?daemon ?malserv ?sql ?Attacker)
    )
)
(:action attacker-performs-unauthorized-request-via-environment-using-SSRF-Vulnerability
    :parameters (?sql - sqlserver ?Attacker - adversary ?malserv - malserver ?daemon - daemon ?env - environment ?Attack - attack)
    :precondition (and (sql-env ?env) (replace-daemond ?daemon ?malserv ?sql ?Attacker) (sql-attack ?Attack))
    :effect (and
        (execute-unauthorized-requests ?env ?Attack ?sql ?Attacker)
    )
)
 (:action attacker-compromises-Database-Server-using-SSRF
    :parameters (?sql - sqlserver ?Attacker - adversary ?env - environment ?Attack - attack)
    :precondition (and
        (execute-unauthorized-requests ?env ?Attack ?sql ?Attacker)
    )
    :effect(and
        (compromised-sql-server ?sql)
    )
 )
                                         ;;;;;;;;; Database Server Action for CVE-2018-1058: Attacker --> Database  ;;;;;;;;   

(:action Attacker-moves-to-database-server-exploits-CVE-2018-1058
    :parameters (?sql - sqlserver ?s3 - software ?v3 - version ?Access - accesstoken ?Internet - connection)
    :precondition (and (connected-to-db ?sql)(access-db ?Access)(sql-software-3 ?s3)(sql-version-3 ?v3)(remote-access ?Internet))
    :effect (and
        (attacker-exploits-vulnerable-software ?sql ?s3 ?v3 ?Access ?Internet)
    )
)
    (:action Attacker-gains-elevated-privileges
    :parameters (?sql - sqlserver ?s3 - software ?v3 - version ?Internet - connection ?Attacker - adversary ?Flaw - malsoftware ?Access - accesstoken)
    :precondition (and 
        (attacker-exploits-vulnerable-software ?sql ?s3 ?v3 ?Access ?Internet)
        (attacker-with-user-account ?Attacker)
        (sql-flaw ?Flaw)
    )
    :effect (and
        (attacker-gains-elevated-permissions ?s3 ?v3 ?Attacker ?Flaw ?Internet)
    )
)
    (:action attacker-executes-malicious-SQL-code
    :parameters (?sql - sqlserver ?s3 - software ?v3 - version ?Attacker - adversary ?Flaw - malsoftware ?c3 - code ?Internet - connection)
    :precondition (and
        (sql-server ?sql)
        (attacker-gains-elevated-permissions ?s3 ?v3 ?Attacker ?Flaw ?Internet)
        (sql-code-2 ?c3)
    )
    :effect (and
        (attacker-executes-malicious-SQL-code-in-postgresql ?Attacker ?c3 ?s3 ?v3) 
    )
)

    (:action attacker-compromises-Database-Server-using-malicious-sql
    :parameters (?sql - sqlserver ?c3 - code ?Attacker - adversary ?s3 - software ?v3 - version)
    :precondition (and
        (attacker ?Attacker)
        (sql-server ?sql)
        (attacker-executes-malicious-SQL-code-in-postgresql ?Attacker ?c3 ?s3 ?v3)
    )
    :effect(and
        (compromised-sql-server ?sql)
    )
 )
						        ;;;;;;;;; Compromised Database Server via DNS Server CVE-2021-20329: Attacker --> DNS --> Database;;;;;

(:action attacker-moves-to-sql-server-exploits-CVE-2021-20329
    :parameters (?serv5 - dnsserver ?serv2 - sqlserver ?Access - accesstoken ?s6 - software ?v6 - version)
    :precondition (and
        (access-db ?Access)
        (sql-server ?serv2)
        (compromised-dns-server ?serv5)
        (sql-software-5 ?s6)
        (sql-version-5 ?v6)
    )
    :effect (and
        (attacker-exploits-server ?serv2 ?s6 ?v6)
    )
)
    (:action attacker-exploits-vulnerable-software-version-in-db-server
    :parameters (?serv2 - sqlserver ?s6 - software ?v6 - version)
    :precondition (and
        (attacker-exploits-server ?serv2 ?s6 ?v6)
    )
    :effect (and
        (access-to-sql-software-5 ?s6 ?v6 ?serv2)
    )
)
    (:action attacker-uses-object-with-string-to-inject-additional-fields
    :parameters (?s6 - software ?v6 - version ?serv2 - sqlserver ?obj - object ?string - cstring)
    :precondition (and 
        (access-to-sql-software-5 ?s6 ?v6 ?serv2)
        (go-object ?obj)
        (specific-cstring ?string)
     )
    :effect (and
       (attacker-injects-additional-fields ?obj ?string ?s6 ?v6 ?serv2)
    )
)
    (:action attacker-compromised-database-Server-via-DNS
    :parameters (?s6 - software ?v6 - version ?Attacker - adversary ?serv2 - sqlserver ?obj - object ?string - cstring)
    :precondition (and
        (attacker-injects-additional-fields ?obj ?string ?s6 ?v6 ?serv2)
    )
    :effect (and 
        (compromised-sql-server ?serv2)
    )
)

                                                        ;;;;;; FTP Server Action ;;;;;;;
  (:action Access-to-FTP-Server
    :parameters (?serv1 - webserver ?serv3 - ftpserver ?Access - accesstoken)
    :precondition(and
        (access-ftp ?Access)
        (reach-to-web ?serv1)
        (ftp-server ?serv3)
    )
    :effect(and
        (connected-to-ftp ?serv3)
    )
) 
 (:action Attacker-moves-to-ftp-server-to-exploit-CVE-2013-4465
    :parameters (?serv1 - webserver ?serv3 - ftpserver ?s1 - software ?v1 - version  ?s3 - software ?v3 - version ?Access - accesstoken ?Internet - connection)
    :precondition (and
        (access-ftp ?Access)
        (compromised-web-server ?serv1)
        (web-version ?v1)
        (web-software ?s1)
        (remote-access ?Internet)
        (ftp-server ?serv3)
        (ftp-software ?s3)
        (ftp-version ?v3)
    )
    :effect (and
        (move-to-FTP ?serv3)
        (ftp-software ?s3)
        (not (web-software ?s1))
        (ftp-version ?v3)
        (not (web-version ?v1))
        (access-granted-to-ftp ?serv3 ?Access)
    )
)
  (:action Attacker-connected-to-software-to-access-avatar-functionality
    :parameters (?serv1 - webserver ?serv3 - ftpserver ?s3 - software ?v3 - version ?Attacker - adversary ?Access - accesstoken)
    :precondition (and
        (access-granted-to-ftp ?serv3 ?Access)
        (attacker ?Attacker)
        (ftp-server ?serv3)
        (move-to-FTP ?serv3)
        (ftp-software ?s3)
        (ftp-version ?v3)
    )
    :effect (and
        (access-to-avatar ?s3 ?v3 ?Attacker)
    )
 )
 
(:action attackers-uploads-malicious-file-in-avatar
    :parameters (?serv3 - ftpserver ?s3 - software ?v3 - version ?f3 - file ?Attacker - adversary ?Functionality - functionality ?Access - accesstoken)
    :precondition (and
        (access-granted-to-ftp ?serv3 ?Access)
        (access-to-avatar ?s3 ?v3 ?Attacker)
        (ftp-functionality ?Functionality)
        (ftp-file ?f3)
    )
    :effect (and
        (has-upload-file ?f3 ?Attacker ?Functionality)
        (functionality-exploited ?f3 ?Functionality)
    )
 )
 
  (:action attacker-has-authentication-access
    :parameters (?f3 - file ?serv3 - ftpserver ?Attacker - adversary ?Functionality - functionality ?Internet - connection)
    :precondition (and
        (has-upload-file ?f3 ?Attacker ?Functionality)
        (functionality-exploited ?f3 ?Functionality)
        (ftp-server ?serv3)
    )
    :effect (and
        (has-authentication ?serv3 ?Attacker ?Internet)
    )
)

(:action attacker-uploads-executable-extention-in-unspecified-directory
    :parameters (?f4 - file ?serv3 - ftpserver ?Attacker - adversary ?Directory - location ?Internet - connection)
    :precondition (and
        (exe-file ?f4)
        (directory ?Directory)
        (has-authentication ?serv3 ?Attacker ?Internet)
    )
    :effect (and
        (has-upload-exe-extension ?f4 ?Directory ?Attacker)
    )
)

(:action attacker-accessing-execuatble-extention-via-direct-request 
    :parameters (?f4 - file ?Directory - location ?Attacker - adversary ?Request - request)
    :precondition (and
        (exe-file ?f4)
        (directory ?Directory)
        (has-upload-exe-extension ?f4 ?Directory ?Attacker)
        (request-ftp ?Request)
    )
    :effect (and
        (access-to-exe-file ?f4 ?Directory ?Request)
    )
)

(:action attacker-gets-privilige-to-execute-arbitrary-code-in-FTP-server
    :parameters (?f4 - file ?c3 - code ?serv3 - ftpserver ?Directory - location ?Request - request ?Attacker - adversary)
    :precondition (and
        (ftp-code ?c3)
        (access-to-exe-file ?f4 ?Directory ?Request)
    )
    :effect (and
        (execution-success ?serv3 ?c3 ?Attacker)
    )
)
(:action attacker-compromised-FTP-Server
    :parameters(?serv3 - ftpserver ?c3 - code ?Attacker - adversary)
    :precondition (and
        (attacker ?Attacker)
        (ftp-server ?serv3)
        (execution-success ?serv3 ?c3 ?Attacker)
    )
    :effect (and
        (compromised-ftp-server ?serv3)
    )
 )
 (:action Connected-to-FTP-Server
    :parameters (?serv3 - ftpserver)
    :precondition (and
        (connected-to-ftp ?serv3)
    )
    :effect(and
        (reach-to-ftp ?serv3)
    )
  )
                            ;;;Actions for Admin Server via WebServer;;;;;;
        
    (:action Access-to-Admin-Server
    :parameters (?serv1 - webserver ?serv4 - adminserver ?Access - accesstoken)
    :precondition(and
        (access-admin ?Access)
        (reach-to-web ?serv1)
        (admin-server ?serv4)
    )
    :effect(and
        (connected-to-admin ?serv4)
    )
   )                           
    (:action Attacker-moves-to-admin-server-exploits-CVE-2009-0241
    :parameters (?serv1 - webserver ?serv4 - adminserver ?s1 - software ?v1 - version ?Access - accesstoken)
    :precondition (and
        (access-admin ?Access)
        (compromised-web-server ?serv1)
        (web-version ?v1)
        (web-software ?s1)
    )
    :effect (and
        (move-to-admin ?serv4)
        (access-granted-to-admin ?serv4 ?Access)
    )
)
(:action attacker-connected-to-admin-server-software
    :parameters (?serv4 - adminserver ?s4 - software ?v4 - version ?Internet - connection ?Attacker - adversary ?Access - accesstoken)
    :precondition (and
        (access-granted-to-admin ?serv4 ?Access)
        (move-to-admin ?serv4)
        (attacker ?Attacker)
        (remote-access ?Internet)
        (admin-software ?s4)
        (admin-version ?v4)
    )
    :effect (and
        (access-to-admin-software ?s4 ?Attacker)
        
    )
)
 
 (:action attacker-gains-access-to-file-in-software
    :parameters (?serv4 - adminserver ?s4 - software ?f5 - file ?Path - path ?Function - function ?Attacker - adversary ?Access - accesstoken)
    :precondition (and
        (access-to-admin-software ?s4 ?Attacker)
        (admin-file ?f5)
        (access-granted-to-admin ?serv4 ?Access)
        (admin-path ?Path)
        (admin-function ?Function)
    )
    :effect (and
        (request-to-service ?f5 ?Path ?Function)
    )
)
(:action attacker-sends-request-to-file-to-initiate-dos-attack
    :parameters (?serv4 - adminserver ?f5 - file ?Pathname - pathname ?Buffer - buffer ?Attack - attack ?Path - path ?Function - function ?Attacker - adversary)
    :precondition (and
        (longpath ?Pathname)
        (buffer-overflow ?Buffer)
        (request-to-service ?f5 ?Path ?Function)    
        (admin-attack ?Attack)
    )
    :effect (and
        (dos-attack-execution ?serv4 ?Attack ?Attacker)
    )
)

(:action attacker-compromised-Admin-Server-via-Web-Server
    :parameters (?serv4 - adminserver ?Attacker - adversary ?Attack - attack)
    :precondition (and
        (dos-attack-execution ?serv4 ?Attack ?Attacker)
    )
    :effect (and 
        (compromised-admin-server ?serv4)
    )
)


                                                  ;;;;;;;;; Compromised Admin Server via DNS Server;;;;;

    (:action attacker-moves-to-admin-server-exploits-CVE-2022-37835
    :parameters (?serv5 - dnsserver ?serv4 - adminserver ?Access - accesstoken)
    :precondition (and
        (access-admin ?Access)
        (compromised-dns-server ?serv5)
    )
    :effect (and
        (move-to-admin-via-dns ?serv4 ?serv5)
    )
)
(:action attacker-exploits-vulnerable-software-version-in-admin-server
    :parameters (?serv4 - adminserver ?serv5 - dnsserver ?s4 - software ?v4 - version ?Internet - connection ?Attacker - adversary)
    :precondition (and
        (move-to-admin-via-dns ?serv4 ?serv5)
        (admin-software-2 ?s4)
        (admin-version-2 ?v4)
    )
    :effect (and
        (access-to-admin-software-2 ?s4 ?v4 ?Attacker)
        
    )
)
(:action attacker-downloads-data-from-admin-server
    :parameters (?s4 - software ?v4 - version ?admin - adminserver ?Attacker - adversary ?data - admindata)
    :precondition (and 
        (access-to-admin-software-2 ?s4 ?v4 ?Attacker)
        (information ?data))
    :effect (and
       (download-data ?data ?Attacker)
    )
)
(:action attacker-compromised-Admin-Server-via-DNS-Server
    :parameters (?serv4 - adminserver ?serv5 - dnsserver ?Attacker - adversary ?data - admindata)
    :precondition (and
        (download-data ?data ?Attacker)
    )
    :effect (and 
        (compromised-admin-server ?serv4)
    )
)
 						 ;;;;;;;;; Admin Server CVE-2019-0211 : Attacker --> Admin ;;;;;;;;;;;;
    						
(:action attacker-exploits-vulnerable-software-version-in-admin-server-CVE-2019-0211
    :parameters (?serv4 - adminserver ?s4 - software ?v4 - version ?Internet - connection ?Attacker - adversary)
    :precondition (and
        (connected-to-admin ?serv4)
        (admin-software-4 ?s4)
        (admin-version-4 ?v4)
        (remote-access ?Internet)
        (attacker ?Attacker)
    )
    :effect (and
        (attacker-gains-elevated-privileges-in-admin-software ?s4 ?v4 ?Attacker ?serv4)
    )
)
(:action attacker-executes-arbitrary-code-in-admin-server
    :parameters (?serv4 - adminserver ?s4 - software ?v4 - version ?Internet - connection ?Attacker - adversary ?c4 - code)
    :precondition (and
     	(attacker-gains-elevated-privileges-in-admin-software ?s4 ?v4 ?Attacker ?serv4)
     	(remote-access ?Internet)
     	(admin-code ?c4)
    )
    :effect (and 
    	(attacker-executes-arbitrary-code ?c4 ?serv4 ?Attacker)
    )
)
  
(:action attacker-compromised-Admin-Server
    :parameters (?serv4 - adminserver ?c4 - code ?Attacker - adversary)
    :precondition (and
        (attacker-executes-arbitrary-code ?c4 ?serv4 ?Attacker)
    )
    :effect (and 
        (compromised-admin-server ?serv4)
    )
) 						    
                    ;;;;;;;;; Admin Server CVE-2020-0688: Attacker --> Web --> FTP --> Admin ;;;;;;;;;

(:action attacker-connects-to-software-CVE-2020-0688
    :parameters (?serv3 - ftpserver ?serv4 - adminserver ?s5 - software ?Internet - connection ?Attacker - adversary)
    :precondition (and
        ;(connected-to-admin ?serv4)
        (compromised-ftp-server ?serv3)
        (admin-software-3 ?s5)
        (remote-access ?Internet)
        (attacker ?Attacker)
    )
    :effect (and
        (access-to-admin-server-3 ?s5 ?Attacker ?serv4)
    )
)   
(:action attacker-executes-arbitrary-code-remotely
      	:parameters (?serv4 - adminserver ?s5 - software ?Attacker - adversary ?c5 - code)
      	:precondition (and
      	(access-to-admin-server-3 ?s5 ?Attacker ?serv4)
      	(admin-code-2 ?c5)
        )
      	:effect (and
      	  (attacker-executes-arbitrary-code-in-HTTP ?c5 ?s5 ?serv4 ?Attacker)
      	 )
)
      
(:action attacker-compromised-Admin-Server-via-FTP-Server
    :parameters (?serv4 - adminserver ?c5 - code ?s5 - software ?Attacker - adversary)
    :precondition (and
       (attacker-executes-arbitrary-code-in-HTTP ?c5 ?s5 ?serv4 ?Attacker)
    )
    :effect (and 
        (compromised-admin-server ?serv4)
    )
)

                                                              ;Actions for DNS Server;
(:action Access-to-DNS-Server
    :parameters (?serv1 - webserver ?serv5 - dnsserver ?Access - accesstoken)
    :precondition(and
        (access-dns ?Access)
        (reach-to-web ?serv1)
        (dns-server ?serv5)
    )
    :effect(and
        (connected-to-dns ?serv5)
    )
   )  

(:action attacker-connected-to-dns-server-to-exploit-CVE-2017-14491
    :parameters (?serv1 - webserver ?serv5 - dnsserver ?Attacker - adversary ?Internet - connection ?Access - accesstoken)
    :precondition (and
        (access-dns ?Access)
        (attacker ?Attacker)
        (remote-access ?Internet)
        (dns-server ?serv5)
    )
    :effect (and
        (access-to-dns-server ?serv5 ?Attacker ?Internet)
    )
)

(:action attacker-connected-to-vulnerable-software
    :parameters (?serv5 - dnsserver ?s5 - software ?v5 - version ?Attacker - adversary ?Internet - connection)
    :precondition (and
        (dns-software ?s5)
        (dns-version ?v5)
        (access-to-dns-server ?serv5 ?Attacker ?Internet)
    )
    :effect (and
        (access-to-dns-software ?s5 ?Attacker)
    )
)
(:action attacker-exploits-the-network-services
    :parameters (?s5 - software ?Attacker - adversary ?buffer - buffer)
    :precondition (and
        (access-to-dns-software ?s5 ?Attacker)
        (buffer-overflow ?buffer)
    )
    :effect (and
        (exploited ?s5 ?buffer)
    )
)
(:action attacker-initiates-dos-attack
    :parameters (?serv5 - dnsserver ?s5 - software ?buffer - buffer ?Attack - attack)
    :precondition (and
            (exploited ?s5 ?buffer)
            (dns-attack ?Attack)
            (dns-server ?serv5)
    )
    :effect (and
        (dos-attack-in-dns ?serv5 ?Attack)
    )
)
(:action attacker-executes-arbitrary-code-via-crafted-dns-response
    :parameters (?serv5 - dnsserver ?s5 - software ?c4 - code ?buffer - buffer ?Response - response ?Attack - attack)
    :precondition (and
            (dos-attack-in-dns ?serv5 ?Attack)
            (exploited ?s5 ?buffer)
            (dns-Code ?c4)
            (response-dns ?Response)
    )
    :effect (and
        (execute-code-in-dns ?serv5 ?c4)
    )
)
(:action attacker-compromised-dns-server
    :parameters (?serv5 - dnsserver ?c4 - code ?Attack - attack)
    :precondition (and
        (execute-code-in-dns ?serv5 ?c4)
    )
    :effect (and
        (compromised-dns-server ?serv5)
)
)
) 
