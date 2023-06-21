( define  (domain network_final)
(:requirements :strips :typing)
(:types webserver sqlserver ftpserver adminserver dnsserver software version file code connection config adversary accesstoken request location functionality buffer response attack function path pathname loginpage admindata environment malserver daemon)
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
 
                                                    ;;; Predicates for FTP Server
 (request ?Request - request)
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
 (function ?Function - function)
 (path ?Path - path)
 (admin-file ?file - file)
 (admin-server ?server - adminserver)
 (admin-software ?software - software)
 (admin-version ?version - version)
 (longpath ?Pathname - pathname)
 (access-to-admin-software ?Sofware - software ?Attacker - adversary)
 (attack ?Attack - attack)
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
 
                                                                    ;;Predicates for DNS Server
 (access-to-dns-software ?software - software ?Attacker - adversary)
 (access-to-dns-server ?server - dnsserver ?Attacker - adversary ?Internet - connection)
 (exploited ?software - software ?Buffer - buffer)
 (response ?Response - response)
 (dos-attack-in-dns ?server - dnsserver ?Attack - attack)
 (connected-to-dns ?server - dnsserver)
 (execute-code-in-dns ?server - dnsserver ?Code - code)
 (dns-server ?server - dnsserver)
 (dns-software ?software - software)
 (dns-version ?version - version)
 (dns-code ?code - code)
)

%OPERATORS%

)