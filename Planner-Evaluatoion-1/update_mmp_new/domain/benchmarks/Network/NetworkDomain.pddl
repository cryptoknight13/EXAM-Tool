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
 ;(execute-code-FTP ?server - server ?code - code)
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
          ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
          
          
          
                                                              ;Actions for Web Server;
(:action attacker-connected-to-web-server
    :parameters (?serv1 - server ?Attacker ?Internet ?Access)
    :precondition (and
        (main-server ?serv1)
        (attacker ?Attacker)
        (access-web ?Access)
        (remote-access ?Internet)
        (safe-server ?serv1)

    )
    :effect (and
        (access-to-server ?serv1 ?Attacker ?Internet)
        
        
    )
)
(:action remote-attack-intiation
    :parameters (?serv1 - server ?s1 - software ?v1 - version  ?Attacker ?Internet ?Access)
    :precondition (and 
        (access-web ?Access)
        (access-to-server ?serv1 ?Attacker ?Internet)
        (main-server ?serv1)
        (safe-server ?serv1)
        (at-software ?s1)
        (version ?v1)
    )
    :effect (and 
        (access-to-software ?s1 ?Attacker)
    )
)

(:action sends-malicious-request-to-config
    :parameters (?serv1 - server ?f1 - file ?s1 - software ?config ?Attacker)
    :precondition (and
        (file ?f1)
        (main-server ?serv1)
        (safe-server ?serv1)
        (access-to-software ?s1 ?Attacker)
        (configuration ?config)
    )
    :effect (and
        (execute-file-in-config ?f1 ?config)
    )
)

(:action privilige-to-execute-arbitrary-code-in-Web-Server
    :parameters (?serv1 - server ?f1 - file ?c1 - code  ?config)
    :precondition (and
        (execute-file-in-config ?f1 ?config)
        (code ?c1)
        (main-server ?serv1)
        (safe-server ?serv1)
    )
    :effect (and
        (execute-code ?serv1 ?c1)
        (not (file ?f1))
        (not (execute-file-in-config ?f1 ?config))
        (not (configuration ?config))
    )
 )
 (:action Web-Server-Compromised
    :parameters (?c1 - code ?serv1 - server)
    :precondition (and
        (main-server ?serv1)
        (safe-server ?serv1)
        (execute-code ?serv1 ?c1)
    )
    :effect (and
        (compromised-server ?serv1)
        (not (main-server ?serv1))
        (not (safe-server ?serv1))
        )
    )
 
                                            ;;;;;;;;;;;;;;;;      Actions for Database Server   ;;;;;;;;;;;;;;;
 (:action Attacker-moves-to-database-server
    :parameters (?serv1 - server ?serv2 - server ?s1 - software ?v1 - version ?s2 - software ?v2 - version ?Access)
    :precondition (and
        (access-db ?Access)
        (compromised-server ?serv1)
        (not (main-server ?serv1))
        (not (safe-server ?serv1))
        (version ?v1)
        (at-software ?s1)
        (not (compromised-server ?serv2))
        
    )
    :effect (and
        (move-to-database ?serv2)
        (main-server ?serv2)
        (safe-server ?serv2)
        (not (at-software ?s1))
        (not (version ?v1))
        (at-software ?s2)
        (version ?v2)
        (access-granted-to-db ?serv2 ?Access)
    )
 
 )
 
 (:action connected-to-Database-Server
    :parameters (?serv2 - server ?s2 - software ?v2 - version ?f2 - file ?Attacker ?Internet ?Access)
    :precondition (and
        (access-granted-to-db ?serv2 ?Access)
        (move-to-database ?serv2)
        (main-server ?serv2)
        (remote-access ?Internet)
        (attacker ?Attacker)
        (safe-server ?serv2)
        (at-software ?s2)
        (version ?v2)
    )
    :effect (and
        (file ?f2)
        (access-to-software ?s2 ?Attacker)
        (access-to-server ?serv2 ?Attacker ?Internet)
    )
 )
 (:action SQL-Injection-to-Open-mysql  
    :parameters (?serv2 - server  ?s2 - software  ?f2 - file ?Attacker ?Internet ?Access)
    :precondition (and 
        (access-granted-to-db ?serv2 ?Access)
        (file ?f2)
        (attacker ?Attacker)
        (remote-access ?Internet)
        (at-software ?s2)
        (access-to-software ?s2 ?Attacker)
        (access-to-server ?serv2 ?Attacker ?Internet)
    )
    :effect (and
        (use-software ?s2 ?Attacker)
        (sql-injection ?f2 ?s2)
    )
 )
 (:action access-to-login-page
    :parameters (?serv1 - server ?s2 - software ?f2 - file ?Attacker )
    :precondition (and
        (compromised-server ?serv1)
        (file ?f2)
        (at-software ?s2)
        (attacker ?Attacker)
        (sql-injection ?f2 ?s2)
        (use-software ?s2 ?Attacker)
    )
    :effect (and
        (login-page)
    )
 )
 (:action access-to-login-field
    :parameters (?c2 - code)
    :precondition (login-page)
    :effect (and
     (login-field)
     (code ?c2)
 )
 )
 (:action execute-arbitrary-commands-via
    :parameters (?s2 - software ?f2 - file ?c2 - code ?Attacker)
    :precondition (and
        (at-software ?s2)
        (attacker ?Attacker)
        (code ?c2)
        (login-field)
    )
    :effect (and
        (execute-code-in-login-feild ?c2)
    )
 )
 (:action Compromised-Database-Server
    :parameters (?serv2 - server ?c2 - code ?Attacker)
    :precondition (and
        (attacker ?Attacker)
        (code ?c2)
        (login-field)
        (login-page)
        (execute-code-in-login-feild ?c2)
    )
    :effect(and
        (compromised-server ?serv2)
        (not (safe-server ?serv2))
    )
 )

                                      ;;;;;;;;;;;;;;;;;;;    Actions for FTP Server1     ;;;;;;;;;;;;;;;;;;;;;;
 (:action Attacker-moves-to-ftp-server
    :parameters (?serv1 - server ?serv3 - server ?s1 - software ?v1 - version  ?s3 - software ?v3 - version ?Access)
    :precondition (and
        (access-ftp ?Access)
        (compromised-server ?serv1)
        (not (main-server ?serv1))
        (not (safe-server ?serv1))
        (version ?v1)
        (at-software ?s1)
    
    )
    :effect (and
        (move-to-FTP ?serv3)
        (safe-server ?serv3)
        (at-software ?s3)
        (not (at-software ?s1))
        (version ?v3)
        (not (version ?v1))
        (access-granted-to-ftp ?serv3 ?Access)
    )
)
  (:action connected-to-FTPServer
    :parameters (?serv1 - server ?serv3 - server ?s3 - software ?v3 - version ?f3 - file ?Internet ?Attacker ?Access )
    :precondition (and
        (access-granted-to-ftp ?serv3 ?Access)
        (attacker ?Attacker)
        (remote-access ?Internet)
        (compromised-server ?serv1)
        (at-software ?s3)
        (version ?v3)
        (move-to-FTP ?serv3)
    )
    :effect (and
        (access-to-avatar ?s3 ?v3 ?Attacker)
        (file ?f3)
    )
 )
 
(:action exploiting-vulnerability-in-avatar-upload-functionality
    :parameters (?serv3 - server ?s3 - software ?v3 - version ?f3 - file ?Attacker ?Functionality ?Access)
    :precondition (and
        (access-granted-to-ftp ?serv3 ?Access)
        (access-to-avatar ?s3 ?v3 ?Attacker)
        (functionality ?Functionality)
        (file ?f3)
    )
    :effect (and
        (has-upload-file ?f3 ?Attacker ?Functionality)
        (functionality-exploited ?f3 ?Functionality)
    )
 )
 
  (:action attacker-has-authentication
    :parameters (?f3 - file ?serv3 - server ?Attacker ?Functionality ?Internet)
    :precondition (and
        (attacker ?Attacker)
        (remote-access ?Internet)
        (has-upload-file ?f3 ?Attacker ?Functionality)
        (functionality-exploited ?f3 ?Functionality)
    )
    :effect (and
        (has-authentication ?serv3 ?Attacker ?Internet)
    )
)

(:action upload-executable-extention-in-unspecified-directory
    :parameters (?f4 - file ?serv3 - server ?Attacker ?Directory ?Internet)
    :precondition (and
        (exe-file ?f4)
        (attacker ?Attacker)
        (directory ?Directory)
        (has-authentication ?serv3 ?Attacker ?Internet)
    )
    :effect (and
        (has-upload-exe-extension ?f4 ?Directory ?Attacker)
    )
)

(:action accessing-exe-extention-via-direct-request 
    :parameters (?f4 - file ?c3 - code ?Directory ?Attacker ?Request)
    :precondition (and
        (attacker ?Attacker)
        (exe-file ?f4)
        (directory ?Directory)
        (has-upload-exe-extension ?f4 ?Directory ?Attacker)
        (request ?Request)
    )
    :effect (and
        (access-to-exe-file ?f4 ?Directory ?Request)
        (directory ?Directory)
        (code ?c3)
    )
)

(:action privilige-to-execute-arbitrary-code-in-FTP-server
    :parameters (?f4 - file ?c3 - code ?serv3 - server ?Directory ?Request ?Attacker)
    :precondition (and
        (attacker ?Attacker)
        (exe-file ?f4)
        (directory ?directory)
        (access-to-exe-file ?f4 ?Directory ?Request)
    )
    :effect (and
       ; (execute-code-FTP ?serv3 ?c3)
        (execution-success ?serv3 ?c3 ?Attacker)
    )
)
(:action compromised-FTP-Server
    :parameters(?serv3 - server ?c3 - code ?Attacker)
    :precondition (and

        (code ?c3)
        (attacker ?Attacker)
       ; (execute-code-FTP ?serv3 ?c3)
        (execution-success ?serv3 ?c3 ?Attacker)
    )
    :effect (and
        (compromised-server ?serv3)
        (not (safe-server ?serv3))
    )
 )
                                                             ;Actions for FTP Server2;

                                                              ;Actions for Admin Server;
 (:action Attacker-moves-to-admin-server
    :parameters (?serv1 - server ?serv4 - server ?s1 - software ?v1 - version  ?s4 - software ?v4 - version ?Access)
    :precondition (and
        (access-admin ?Access)
        (compromised-server ?serv1)
        (not (main-server ?serv1))
        (not (safe-server ?serv1))
        (version ?v1)
        (at-software ?s1)
    
    )
    :effect (and
        (move-to-admin ?serv4)
        (safe-server ?serv4)
        (at-software ?s4)
        (not (at-software ?s1))
        (version ?v4)
        (not (version ?v1))
        (access-granted-to-admin ?serv4 ?Access)
    )
)

(:action attacker-connected-to-admin-server
    :parameters (?serv4 - server ?s4 - software ?v4 - version ?Internet ?Attacker ?Access)
    :precondition (and
        (access-granted-to-admin ?serv4 ?Access)
        (move-to-admin ?serv4)
        (attacker ?Attacker)
        (remote-access ?Internet)
        (at-software ?s4)
        (version ?v4)
    )
    :effect (and
        (access-to-admin-software ?s4 ?Attacker)
        
    )
)
 
 (:action attacker-gains-access
    :parameters (?serv4 - server ?s4 - software ?f5 - file ?Path ?Function ?Attacker ?Access)
    :precondition (and
        (access-to-admin-software ?s4 ?Attacker)
        (c-file ?f5)
        (access-granted-to-admin ?serv4 ?Access)
        (path ?Path)
        (function ?Function)
    )
    :effect (and
        (request-to-service ?f5 ?Path ?Function)
    )
)
(:action attacker-sends-request
    :parameters (?serv4 - server ?f5 - file ?Pathname ?Buffer ?Attack ?Path ?Function ?Attacker)
    :precondition (and
        (longpath ?Pathname)
        (buffer-overflow ?Buffer)
        (request-to-service ?f5 ?Path ?Function)    
        (attack ?Attack)
    )
    :effect (and
        (dos-attack-execution ?serv4 ?Attack ?Attacker)
        
    )
)

(:action Admin-Server-Compromised
    :parameters (?serv4 - server ?Attacker ?Attack )
    :precondition (and
        (attack ?Attack)
        (attacker ?Attacker)
        (dos-attack-execution ?serv4 ?Attack ?Attacker)
    )
    :effect (and 
        (compromised-server ?serv4)
        (not (main-server ?serv4))
    )
)
                                                              ;Actions for DNS Server;
(:action attacker-connected-to-web-server
    :parameters (?serv5 - server ?s5 - software ?v5 - version ?Attacker ?Internet ?Access)
    :precondition (and
        (access-dns ?Access)
        (main-server ?serv5)
        (attacker ?Attacker)
        (remote-access ?Internet)
        (safe-server ?serv5)
        (not (compromised-server ?serv5))
    )
    :effect (and
        (access-to-dns-server ?serv5 ?Attacker ?Internet)
        (at-software ?s5)
        (version ?v5)
    )
)

(:action attacker-connected-to-dns-network-services
    :parameters (?serv5 - server ?s5 - software ?v5 - version ?Attacker ?Internet)
    :precondition (and
        (at-software ?s5)
        (version ?v5)
        (access-to-dns-server ?serv5 ?Attacker ?Internet)
    )
    :effect (and
        (access-to-dns-software ?s5 ?Attacker)
    )
)
(:action exploitation-of-network-services
    :parameters (?s5 - software ?Attacker ?buffer)
    :precondition (and
        (access-to-dns-software ?s5 ?Attacker)
        (buffer-overflow ?buffer)
    )
    :effect (and
        (exploited ?s5 ?buffer)
    )
)
(:action dos-attack
    :parameters (?serv5 - server ?s5 - software ?buffer ?Attack)
    :precondition (and
            (exploited ?s5 ?buffer)
            (attack ?Attack)
    )
    :effect (and
        (dos-attack-in-dns ?serv5 ?Attack)
    )
)
(:action execute-arbitrary-code-via-cRafted-dns-response
    :parameters (?serv5 - server ?s5 - software ?c4 - code ?buffer ?Response ?Attack)
    :precondition (and
            (dos-attack-in-dns ?serv5 ?Attack)
            (exploited ?s5 ?buffer)
            (Code ?c4)
            (response ?Response)
    )
    :effect (and
        (execute-code-in-dns ?serv5 ?c4)
    )
)
(:action attacker-compromised-dns-server
    :parameters (?serv5 - server ?c4 - code ?Attack)
    :precondition (and 
        (execute-code-in-dns ?serv5 ?c4)
    ))
    :effect
        (compromised-server ?serv5)
)
)