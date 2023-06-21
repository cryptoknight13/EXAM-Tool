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
 
 (server ?server - server)
 (attacker ?Attacker - adversary)
 (software ?software - software)
 (file ?File - file)
 
 (version ?Version - version)
 (remote-access ?Internet - connection)
 (main-server ?server - server)
 (safe-server ?server - server)
 (compromised-server ?CompServ - server)

 ;(access-to-software ?software - software ?Attacker - adversary)
 (code ?Code - code)
 
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
 
                                                        ;;;;;;;;;; Predicates for FTP Server ;;;;;;;;;;;;;;;
 (request ?Request - request)
 (exe-file ?File - file)
 (directory ?Directory - location)
 (ftp-functionality ?Functionality - functionality)
 (has-upload-file ?File - file ?Attacker - adversary ?Functionality - functionality)
 (has-upload-exe-extension ?File - file ?Dirctory - location ?Attacker - adversary)
 (functionality-exploited ?File - file ?Functionality - functionality)
 (access-to-avatar ?Software - software ?Version - version ?Attacker - adversary)
 (access-to-exe-file ?File - file ?Directory - location ?Request - request)
 (has-authentication ?server - server ?Attacker - adversary ?Internet - connection) 
 (move-to-FTP ?server - server)
 (execute-code-FTP ?server - server ?code - code)
 (access-granted-to-ftp ?server - server ?Acc2 - accesstoken)
 (execution-success ?server - server ?code - code ?Attacker - adversary)
 (reach-to-ftp ?Server - server)
 (connected-to-ftp ?Server - server)
 (ftp-file ?File - file)
 (ftp-server ?Server - server)
 (ftp-code ?Code - code)
 (ftp-software ?Software - software)
 (ftp-version ?Version - version)
                                                     ;;Predicates for DNS Server
 (access-to-dns-software ?software - software ?Attacker - adversary)
 (attack ?Attack - attack)
 (access-to-dns-server ?server - server ?Attacker - adversary ?Internet - connection)
 (buffer-overflow ?buffer - buffer)
 (exploited ?software - software ?Buffer - buffer) 
 (response ?Response - response)
 (dos-attack-in-dns ?server - server ?Attack - attack)
 (execute-code-in-dns ?server - server ?Code - code)
 (dns-server ?Server - server)
 (dns-code ?Code - code)
 (dns-software ?Software - software)
 (dns-version ?Version - version)
 (connected-to-dns ?Server - server)
 (reach-to-dns ?Server - server)
                                             ;;;;;;;;;;;;;;;;;; Admin Server Predicates ;;;;;;;;;;;;;;;;;;;;
 (function ?Function - function)
 (path ?Path - path)
 (longpath ?Pathname - pathname)
 (access-to-admin-software ?Sofware - software ?Attacker - adversary)
 (dos-attack-execution ?Server - server ?Attack - attack ?Attacker - adversary)
 (request-to-service ?File - file ?Path - path ?Function - function)
 (access-granted-to-admin ?server - server ?Acc3 - accesstoken)
 (move-to-admin ?server - server)
 (reach-to-admin ?Server - server)
 (connected-to-admin ?Server - server)
 (admin-file ?File - file)
 (admin-server ?Server - server)
 (admin-software ?Software - software)
 (admin-version ?Version - version)
 (buffer-overflow-admin ?buffer - buffer)
 )
          ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
          
          
          
                                                              ;Actions for Web Server;
(:action Access-to-Webserver
    :parameters (?serv1 - server ?Access - accesstoken ?Internet - connection)
    :precondition(and
        (access-web ?Access)
        (web-server ?serv1)
        (remote-access ?Internet)
    )
    :effect(and
        (connected-to-web ?serv1)
        ;(main-server ?serv1)
    )
)
(:action attacker-connected-to-web-server
    :parameters (?serv1 - server ?Attacker - adversary ?Internet - connection)
    :precondition (and
        (connected-to-web ?serv1)
        (attacker ?Attacker)
        ;(access-web ?Access)
        (remote-access ?Internet)
        
    )
    :effect (and
        (access-to-server ?serv1 ?Attacker ?Internet)
        (main-server ?serv1)
        (safe-server ?serv1)
        
        
    )
)
(:action CVE-2015-1635-remote-attack-intiation
    :parameters (?serv1 - server ?s1 - software ?v1 - version  ?Attacker - adversary ?Internet - connection)
    :precondition (and 
        ;(access-web ?Access)
        (access-to-server ?serv1 ?Attacker ?Internet)
        (main-server ?serv1)
        (safe-server ?serv1)
        (web-software ?s1)
        (web-version ?v1)
    )
    :effect (and 
        (access-to-web-software ?s1 ?Attacker)
    )
)

(:action CVE-2015-1635-sends-malicious-request-to-config
    :parameters (?serv1 - server ?f1 - file ?s1 - software ?config - config ?Attacker - adversary)
    :precondition (and
        (web-file ?f1)
        (main-server ?serv1)
        (safe-server ?serv1)
        (access-to-web-software ?s1 ?Attacker)
        (configuration ?config)
    )
    :effect (and
        (execute-file-in-config ?f1 ?config)
    )
)

(:action CVE-2015-1635-privilige-to-execute-arbitrary-code-in-Web-Server
    :parameters (?serv1 - server ?f1 - file ?c1 - code  ?config - config)
    :precondition (and
        (execute-file-in-config ?f1 ?config)
        (web-code ?c1)
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
        )
  )
  (:action Connected-to-Web-Server
    :parameters (?serv1 - server)
    :precondition (and
        (connected-to-web ?serv1)
    )
    :effect(and
        (reach-to-web ?serv1)
    )
  )
  
                                   ;;;;;;;;;; Actions for Database Server ;;;;;;;;;;;;;
                                   
(:action Access-to-Database-Server
    :parameters (?serv1 - server ?serv2 - server ?Access - accesstoken)
    :precondition(and
        (access-db ?Access)
        (reach-to-web ?serv1)
        (sql-server ?serv2)
    )
    :effect(and
        (connected-to-db ?serv2)
    )
)                            
(:action CVE-2014-1466-Attacker-moves-to-database-server
    :parameters (?serv1 - server ?serv2 - server ?s1 - software ?v1 - version ?s2 - software ?v2 - version ?Access - accesstoken)
    :precondition (and
        (access-db ?Access)
        ;(connected-to-db ?serv2)
        (compromised-server ?serv1)
        (web-server ?serv1)
        (web-version ?v1)
        (sql-server ?serv2)
        (web-software ?s1)
        
    )
    :effect (and
        (move-to-database ?serv2)
        (main-server ?serv2)
        (safe-server ?serv2)
        (not (web-software ?s1))
        (not (web-version ?v1))
        (sql-software ?s2)
        (sql-version ?v2)
        (access-granted-to-db ?serv2 ?Access)
    )
 
 )
 
 (:action CVE-2014-1466-connected-to-Database-Software
    :parameters (?serv2 - server ?s2 - software ?v2 - version ?f2 - file ?Attacker - adversary ?Internet - connection ?Access - accesstoken)
    :precondition (and
        (access-granted-to-db ?serv2 ?Access)
        (move-to-database ?serv2)
        (main-server ?serv2)
        (remote-access ?Internet)
        (attacker ?Attacker)
        (safe-server ?serv2)
        (sql-software ?s2)
        (sql-file ?f2)
        (sql-version ?v2)
    )
    :effect (and
        (access-to-sql-software ?s2 ?Attacker)
        (access-to-server ?serv2 ?Attacker ?Internet)
    )
 )
 (:action CVE-2014-1466-SQL-Injection-to-Open-mysql  
    :parameters (?serv2 - server ?s2 - software ?f2 - file ?Attacker - adversary ?Internet - connection)
    :precondition (and 
        ;(access-granted-to-db ?serv2 ?Access)
        (sql-file ?f2)
        (sql-server ?serv2)
        (access-to-sql-software ?s2 ?Attacker)
        (access-to-server ?serv2 ?Attacker ?Internet)
    )
    :effect (and
        (use-software ?s2 ?Attacker)
        (sql-injection ?f2 ?s2)
    )
 )
 (:action CVE-2014-1466-access-to-login-page
    :parameters ( ?s2 - software ?f2 - file ?Attacker - adversary)
    :precondition (and
        ;(compromised-server ?serv1)
        ;(file ?f2)
        ;(software ?s2)
        ;(attacker ?Attacker)
        (sql-injection ?f2 ?s2)
        (use-software ?s2 ?Attacker)
    )
    :effect (and
        (login-page)
    )
 )
 (:action CVE-2014-1466-access-to-login-field
    :parameters (?c2 - code)
    :precondition (and (login-page) (sql-code ?c2))
    :effect (and
     (login-field)
 )
 )
 (:action CVE-2014-1466-execute-arbitrary-commands-via
    :parameters (?c2 - code)
    :precondition (and
        ;(software ?s2)
        ;(attacker ?Attacker)
        (sql-code ?c2)
        (login-field)
    )
    :effect (and
        (execute-code-in-login-feild ?c2)
    )
 )
 (:action Compromised-Database-Server
    :parameters (?serv2 - server ?c2 - code ?Attacker - adversary)
    :precondition (and
        (attacker ?Attacker)
        ;(code ?c2)
        (login-field)
        (login-page)
        (sql-server ?serv2)
        (execute-code-in-login-feild ?c2)
    )
    :effect(and
        (compromised-server ?serv2)
    )
 )
  (:action Connected-to-Database-Server
    :parameters (?serv2 - server)
    :precondition (and
        (connected-to-db ?serv2)
    )
    :effect(and
        (reach-to-db ?serv2)
    )
  )
 
                                          ;;;;;;;;;;;;;;;;;;;    Actions for FTP Server1     ;;;;;;;;;;;;;;;;;;;;;;

 (:action Access-to-FTP-Server
    :parameters (?serv1 - server ?serv3 - server ?Access - accesstoken)
    :precondition(and
        (access-ftp ?Access)
        (reach-to-web ?serv1)
        (ftp-server ?serv3)
    )
    :effect(and
        (connected-to-ftp ?serv3)
    )
) 
 (:action CVE-2013-4465-Attacker-moves-to-ftp-server
    :parameters (?serv1 - server ?serv3 - server ?s1 - software ?v1 - version  ?s3 - software ?v3 - version ?Access - accesstoken ?Internet - connection)
    :precondition (and
        (access-ftp ?Access)
        (compromised-server ?serv1)
        (web-version ?v1)
        (web-software ?s1)
        (remote-access ?Internet)
        (ftp-server ?serv3)
        (ftp-software ?s3)
        (ftp-version ?v3)
    
    )
    :effect (and
        (move-to-FTP ?serv3)
        (safe-server ?serv3)
        (ftp-software ?s3)
        (not (web-software ?s1))
        (ftp-version ?v3)
        (not (web-version ?v1))
        (access-granted-to-ftp ?serv3 ?Access)
    )
)
  (:action CVE-2013-4465-Attacker-connected-to-FTP-Server
    :parameters (?serv1 - server ?serv3 - server ?s3 - software ?v3 - version ?f3 - file  ?Attacker - adversary ?Access - accesstoken)
    :precondition (and
        (access-granted-to-ftp ?serv3 ?Access)
        (attacker ?Attacker)
        (ftp-server ?serv3)
        ;(remote-access ?Internet)
        ;(compromised-server ?serv1)
        (ftp-software ?s3)
        (ftp-version ?v3)
        (move-to-FTP ?serv3)
        (ftp-file ?f3)
    )
    :effect (and
        (access-to-avatar ?s3 ?v3 ?Attacker)
    )
 )
 
(:action CVE-2013-4465-exploiting-vulnerability-in-avatar-upload-functionality
    :parameters (?serv3 - server ?s3 - software ?v3 - version ?f3 - file ?Attacker - adversary ?Functionality - functionality ?Access - accesstoken)
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
 
  (:action CVE-2013-4465-attacker-has-authentication
    :parameters (?f3 - file ?serv3 - server ?Attacker - adversary ?Functionality - functionality ?Internet - connection)
    :precondition (and
        (attacker ?Attacker)
        (remote-access ?Internet)
        (ftp-server ?serv3)
        (has-upload-file ?f3 ?Attacker ?Functionality)
        (functionality-exploited ?f3 ?Functionality)
    )
    :effect (and
        (has-authentication ?serv3 ?Attacker ?Internet)
    )
)

(:action CVE-2013-4465-upload-executable-extention-in-unspecified-directory
    :parameters (?f4 - file ?serv3 - server ?Attacker - adversary ?Directory - location ?Internet - connection)
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

(:action CVE-2013-4465-accessing-exe-extention-via-direct-request 
    :parameters (?f4 - file ?c3 - code ?Directory - location ?Attacker - adversary ?Request - request)
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
        (ftp-code ?c3)
    )
)

(:action CVE-2013-4465-privilige-to-execute-arbitrary-code-in-FTP-server
    :parameters (?f4 - file ?c3 - code ?serv3 - server ?Directory - location ?Request - request ?Attacker - adversary)
    :precondition (and
        (attacker ?Attacker)
        ;(exe-file ?f4)
        (ftp-code ?c3)
        (directory ?directory)
        (access-to-exe-file ?f4 ?Directory ?Request)
    )
    :effect (and
       ; (execute-code-FTP ?serv3 ?c3)
        (execution-success ?serv3 ?c3 ?Attacker)
    )
)
(:action compromised-FTP-Server
    :parameters(?serv3 - server ?c3 - code ?Attacker - adversary)
    :precondition (and
        ;(code ?c3)
        (attacker ?Attacker)
        (ftp-server ?serv3)
       ; (execute-code-FTP ?serv3 ?c3)
        (execution-success ?serv3 ?c3 ?Attacker)
    )
    :effect (and
        (compromised-server ?serv3)
    )
 )
 (:action Connected-to-FTP-Server
    :parameters (?serv3 - server)
    :precondition (and
        (connected-to-ftp ?serv3)
    )
    :effect(and
        (reach-to-ftp ?serv3)
    )
  )
  
  
                                                          ;;;;;;;;;;;;;;;;;   ;Actions for Admin Server; ;;;;;;;;;;;;;;;;;
 (:action Access-to-Admin-Server
    :parameters (?serv1 - server ?serv4 - server ?Access - accesstoken ?Internet - connection)
    :precondition(and
        (access-admin ?Access)
        (admin-server ?serv4)
        (reach-to-web ?serv1)
        (remote-access ?Internet)
    )
    :effect(and
        (connected-to-admin ?serv4)
    )
) 
 (:action CVE-2009-0241-Attacker-moves-to-admin-server
    :parameters (?serv1 - server ?serv4 - server ?s1 - software ?v1 - version  ?s4 - software ?v4 - version ?Access - accesstoken)
    :precondition (and
        (access-admin ?Access)
        (compromised-server ?serv1)
        (web-version ?v1)
        (web-software ?s1)
        (admin-server ?serv4)
        (admin-software ?s4)
        (admin-version ?v4)
    
    )
    :effect (and
        (move-to-admin ?serv4)
        (safe-server ?serv4)
        (admin-software ?s4)
        (admin-version ?v4)
        (access-granted-to-admin ?serv4 ?Access)
    )
)

(:action CVE-2009-0241-attacker-connected-to-admin-server
    :parameters (?serv4 - server ?s4 - software ?v4 - version ?Internet - connection ?Attacker - adversary ?Access - accesstoken)
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
 
 (:action CVE-2009-0241-attacker-gains-access
    :parameters (?serv4 - server ?s4 - software ?f5 - file ?Path - path ?Function - function ?Attacker - adversary ?Access - accesstoken)
    :precondition (and
        (access-to-admin-software ?s4 ?Attacker)
        (admin-file ?f5)
        (access-granted-to-admin ?serv4 ?Access)
        (path ?Path)
        (function ?Function)
    )
    :effect (and
        (request-to-service ?f5 ?Path ?Function)
    )
)
(:action CVE-2009-0241-attacker-sends-request
    :parameters (?serv4 - server ?f5 - file ?Pathname - pathname ?Buffer - buffer ?Attack - attack ?Path - path ?Function - function ?Attacker - adversary)
    :precondition (and
        (longpath ?Pathname)
        (buffer-overflow-admin ?Buffer)
        (request-to-service ?f5 ?Path ?Function)    
        (attack ?Attack)
    )
    :effect (and
        
        
    )
)

(:action Admin-Server-Compromised
    :parameters (?serv4 - server ?Attacker - adversary ?Attack - attack)
    :precondition (and
        (attack ?Attack)
        (attacker ?Attacker)
        (dos-attack-execution ?serv4 ?Attack ?Attacker)
        (admin-server ?serv4)
    )
    :effect (and 
        (compromised-server ?serv4)
    )
)
 (:action Connected-to-Admin-Server
    :parameters (?serv4 - server)
    :precondition (and
        (connected-to-admin ?serv4)
    )
    :effect(and
        (reach-to-admin ?serv4)
    )
  )
  
  
                                                               ;Actions for DNS Server;

(:action Access-to-DNS-Server
    :parameters (?serv5 - server ?Access - accesstoken ?Internet - connection)
    :precondition(and
        (access-dns ?Access)
        (dns-server ?serv5)
        (remote-access ?Internet)
    )
    :effect(and
        (connected-to-dns ?serv5)
        ;(main-server ?serv1)
    )
)
(:action CVE-2017-14491-attacker-connected-to-dns-server
    :parameters (?serv5 - server ?Attacker - adversary ?Internet - connection ?Access - accesstoken)
    :precondition (and
        (access-dns ?Access)
        (dns-server ?serv5)
        (attacker ?Attacker)
        (remote-access ?Internet)
        
    )
    :effect (and
        (access-to-dns-server ?serv5 ?Attacker ?Internet)
        ;(dns-software ?s5)
        ;(dns-version ?v5)
        (main-server ?serv5)
        (safe-server ?serv5)
    )
)

(:action CVE-2017-14491-attacker-connected-to-dns-network-services
    :parameters (?serv5 - server ?s5 - software ?v5 - version ?Attacker - adversary ?Internet - connection)
    :precondition (and
        (dns-software ?s5)
        (dns-version ?v5)
        (main-server ?serv5)
        (safe-server ?serv5)
        (access-to-dns-server ?serv5 ?Attacker ?Internet)
    )
    :effect (and
        (access-to-dns-software ?s5 ?Attacker)
    )
)
(:action CVE-2017-14491-exploitation-of-network-services
    :parameters (?s5 - software ?Attacker - adversary ?buffer - buffer)
    :precondition (and
        (access-to-dns-software ?s5 ?Attacker)
        (buffer-overflow ?buffer)
    )
    :effect (and
        (exploited ?s5 ?buffer)
    )
)
(:action CVE-2017-14491-dos-attack
    :parameters (?serv5 - server ?s5 - software ?buffer - buffer ?Attack - attack)
    :precondition (and
            (exploited ?s5 ?buffer)
            (attack ?Attack)
    )
    :effect (and
        (dos-attack-in-dns ?serv5 ?Attack)
    )
)
(:action execute-arbitrary-code-via-cRafted-dns-response
    :parameters (?serv5 - server ?s5 - software ?c4 - code ?buffer - buffer ?Response - response ?Attack - attack)
    :precondition (and
            (dos-attack-in-dns ?serv5 ?Attack)
            (exploited ?s5 ?buffer)
            (dns-code ?c4)
            (response ?Response)
    )
    :effect (and
        (execute-code-in-dns ?serv5 ?c4)
    )
)
(:action Attacker-compromised-dns-server
    :parameters (?serv5 - server ?c4 - code ?Attack - attack)
    :precondition (and
        (execute-code-in-dns ?serv5 ?c4)
        (dns-server ?serv5)
    )
    :effect
        (compromised-server ?serv5)
)
  (:action Connected-to-DNS-Server
    :parameters (?serv5 - server)
    :precondition (and
        (connected-to-dns ?serv5)
    )
    :effect(and
        (reach-to-dns ?serv5)
    )
  )
)
