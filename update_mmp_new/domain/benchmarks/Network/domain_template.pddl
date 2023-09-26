( define  (domain network_final)
(:requirements :strips :typing)
(:types default_object server software version file code)
(:predicates 
                                                              ;Common Predicates;
 ;;; Granting Access;
 (access-db ?Acc1)
 (access-ftp ?Acc2)
 (access-admin ?Acc3)
 (access-web ?Acc4)
 (access-dns ?Acc5)
 ;;; End Access ;;;;;
 
 (server ?server - server)
 (attacker ?Attacker)
 (at-software ?software - software)
 (file ?File - file)
 (version ?Version - version)
 (remote-access ?Internet)
 (main-server ?server - server)
 (safe-server ?server - server)
 (compromised-server ?CompServ - server)
 (access-to-server ?server - server ?Attacker ?Internet)
 (access-to-software ?software - software ?Attacker)
 (code ?Code - code)
 (execute-code ?server - server ?Code - code)
                                                    ;;Predicates for DNS Server
 (access-to-dns-software ?software - software ?Attacker)
 (access-to-dns-server ?server - server ?Attacker ?Internet)
 (exploited ?software - software ?Buffer)
 (response ?Response)
 (dos-attack-in-dns ?server - server ?Attack)
 (execute-code-in-dns ?server - server ?Code - code)
                                                      ;;;;;;;;;; Predicates for Web Server ;;;;;;;;;;;;

 (configuration ?config)
 (execute-file-in-config ?File - file ?config)

                                                     ;;;;;;;;;; Predicates for Database Server ;;;;;;;;
 
 (sql-injection ?File - file ?Software - software)
 (login-page)
 (login-field)
 (use-software ?Software - software ?Attacker)
 (execute-code-in-login-feild ?Code - code)
 (move-to-database ?server - server)
 (access-granted-to-db ?server - server ?Acc1)
 
                                                     ;;;;;;;;;; Predicates for FTP1 Server ;;;;;;;;;
 (request ?Request)
 (exe-file ?File - file)
 (directory ?Directory)
 (functionality ?Functionality)
 (has-upload-file ?File - file ?Attacker ?Functionality)
 (has-upload-exe-extension ?File - file ?Dirctory ?Attacker)
 (functionality-exploited ?File - file ?Functionality)
 (access-to-avatar ?Software - software ?Version - version ?Attacker)
 (access-to-exe-file ?File - file ?Directory ?Request)
 (has-authentication ?server - server ?Attacker ?Internet) 
 (move-to-FTP ?server - server)
 (execute-code-FTP ?server - server ?code - code)
 (access-granted-to-ftp ?server - server ?Acc2)
 (execution-success ?server - server ?code - code ?Attacker)
 
                                            ;;;;;;;;;;;;;;;;;; Admin Server Predicates ;;;;;;;;;;;;;;;;;;;;
 (buffer-overflow ?Buffer)
 (function ?Function)
 (path ?Path)
 (c-file ?file - file)
 (longpath ?Pathname)
 (access-to-admin-software ?Sofware - software ?Attacker)
 (attack ?Attack)
 (dos-attack-execution ?Server - server ?Attack ?Attacker)
 (request-to-service ?File - file ?Path ?Function)
 (access-granted-to-admin ?server - server ?Acc3)
 (move-to-admin ?server - server)
 )


%OPERATORS%

)
