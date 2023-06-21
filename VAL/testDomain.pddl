( define  (domain network_final)
(:requirements :strips :typing)
(:types webserver cvevul sqlserver adversary accesspoint connection software version file config code loginpage link attack location)
(:predicates

    (access-point-web ?Acc1 - accesspoint)
    (access-point-sql ?Acc2 - accesspoint)
    (access-point-admin ?Acc3 - accesspoint)
    (access-point-dns ?Acc5 - accesspoint)
    (access-point-ftp ?Acc4 - accesspoint)
    (remote-access ?Internet - connection)
    (attacker ?Attacker - adversary)
    
    (has-connection-web-to-sql ?web - webserver ?sql - sqlserver)
    (has-connection-sql-to-web ?sql - sqlserver ?web - webserver)
                                                          ;;;;;;;;;; Predicates for Web Server ;;;;;;;;;;;;

    ;(reach-to-web ?web - webserver)
    ;(connected-to-web ?web - webserver)
    (web-server ?web - webserver)
    (connected-to ?web - webserver)
    (has-connected-to-web ?web - webserver ?Attacker - adversary)
    (access-to-web-software ?software - software ?web - webserver ?Attacker - adversary)
    (web-software ?Software - software)
    (web-version ?Version - version)
    (configuration ?config - config)
    (execute-file-in-config ?File - file ?config - config ?web - webserver)
    (execute-code ?web - webserver ?Code - code ?Attacker - adversary)
    (web-file ?File - file)
    (web-code ?Code - code)
    (compromised-web-server ?compweb - webserver)
                                                          ;;;;;;;;;; Predicates for Database Server ;;;;;;;;;;;;;
    
    (sql-server ?sql - sqlserver)
    (has-connected-to-sql ?sql - sqlserver ?Attacker - adversary)
    (sql-software ?Software - software)
    (sql-version ?Version - version)
    (access-to-sql-software ?software - software ?sql - sqlserver ?Attacker - adversary)
    (access-to-sql-server ?sql - sqlserver ?Attacker - adversary ?Internet - connection)
    (sql-file ?File - file)
    (use-software ?Software - software ?sql - sqlserver ?Attacker - adversary)
    (sql-injection ?File - file ?Software - software ?sql - sqlserver ?Attacker - adversary)
    (login-page ?Page - loginpage)
    (access-login-page-via-software ?Page - loginpage ?Software - software ?sql - sqlserver)
    (access-login-field ?Page - loginpage ?sql - sqlserver ?Attacker - adversary)
    (sql-code ?Code - code)
    (execute-code-in-login-feild ?Code - code ?Page - loginpage ?sql - sqlserver)
    (compromised-sql-server ?compsql - sqlserver)
    ;(move-to-database ?sql - sqlserver)
    ;(access-granted-to-db ?sql - sqlserver ?Acc1 - accesstoken)
    ;(reach-to-db ?sql - sqlserver)
    ;(connected-to-db ?sql - sqlserver)
    
                                                                ;;;;;;;;;; Predicates for APACHE Web Server ;;;;;;;;;;;;
    ;(apache-server ?apache - webserver)
    (apache-software ?Software - software)
    (apache-version ?Version - version)
    (access-to-apache-software ?Software - software ?Version - version ?apache - webserver ?Attacker - adversary)
    (apache-path ?Url - link)
    (apache-attack ?Attack - attack)
    (apache-file ?File - file)
    (map-url-to-files ?Attack - attack ?Url - link ?File - file ?apache - webserver ?Attacker - adversary)
    (apache-location ?Directory - location)
    (access-to-directories ?Directory - location ?apache - webserver ?Attacker - adversary) 
    (apache-code ?Code - code)
    (execute-code-in-file ?Code - code ?File - file ?apache - webserver)
)
    
                                         ;;;;;   Attacker Exploiting CVE-2015-1635 to Comromise Webserver ;;;;;

(:action attacker-connected-to-web-server-to-exploit-CVE-2015-1635
    :parameters (?web - webserver ?Attacker - adversary ?Internet - connection ?access - accesspoint)
    :precondition (and (web-server ?web) (attacker ?Attacker) (remote-access ?Internet) (access-point-web ?access))
    :effect (and
        (has-connected-to-web ?web ?Attacker)
    )
)

(:action attacker-expoits-the-vulnerable-software-version
    :parameters (?web - webserver ?Attacker - adversary ?s1 - software ?v1 - version ?Internet - connection)
    :precondition (and 
        (has-connected-to-web ?web ?Attacker)
        (web-software ?s1)
        (web-version ?v1)
        )
    :effect (and
        (access-to-web-software ?s1 ?web ?Attacker)
    )
)
(:action attacker-changes-server-configuration
    :parameters (?web - webserver ?f1 - file ?s1 - software ?config - config ?Attacker - adversary)
    :precondition (and
        (web-file ?f1)
        (access-to-web-software ?s1 ?web ?Attacker)
        (configuration ?config)
    )
    :effect (and
        (execute-file-in-config ?f1 ?config ?web)
    )
)
(:action attacker-gains-privileges-by-executing-malicious-code
    :parameters (?web - webserver ?f1 - file ?c1 - code  ?config - config ?Attacker - adversary)
    :precondition (and
        (execute-file-in-config ?f1 ?config ?web)
        (web-code ?c1)
    )
    :effect (and
        (execute-code ?web ?c1 ?Attacker)
    )
 )
(:action attacker-execute-code-to-compromise-Web-Server
    :parameters (?c1 - code ?web - webserver ?Attacker - adversary)
    :precondition (and (execute-code ?web ?c1 ?Attacker))
    :effect (and
        (compromised-web-server ?web)
    )
)
                                   ;;;;;;;;;; Attacker Exploiting CVE--2014-1466 to compromise Database Server ;;;;;;;;;;;;;
                                   
(:action Attacker-connects-to-database-server-via-web-server-to-exploit-CVE-2014-1466
    :parameters (?web - webserver ?sql - sqlserver ?Attacker - adversary ?Internet - connection ?access - accesspoint)
    :precondition (and (compromised-web-server ?web) (has-connection-web-to-sql ?web ?sql) (sql-server ?sql) ( attacker ?Attacker) (remote-access ?Internet) (access-point-sql ?access))
    :effect (and
        (has-connected-to-sql ?sql ?Attacker)
    )
)
 (:action attacker-connected-to-vulnerable-Software-Version
    :parameters (?sql - sqlserver ?s2 - software ?v2 - version ?Attacker - adversary ?Internet - connection ?access - accesspoint)
    :precondition (and
        (has-connected-to-sql ?sql ?Attacker)
        (sql-software ?s2)
        (sql-version ?v2)
    )
    :effect (and
        (access-to-sql-software ?s2 ?sql ?Attacker)
        (access-to-sql-server ?sql ?Attacker ?Internet)
    )
 )
 (:action attacker-uploads-malicious-SQL-file-to-software   
    :parameters (?sql - sqlserver ?s2 - software ?f2 - file ?Attacker - adversary ?Internet - connection)
    :precondition (and
        (sql-file ?f2)
        (access-to-sql-software ?s2 ?sql ?Attacker)
        (access-to-sql-server ?sql ?Attacker ?Internet)
    )
    :effect (and
        (use-software ?s2 ?sql ?Attacker)
        (sql-injection ?f2 ?s2 ?sql ?Attacker)
    )
 )
 (:action attacker-opens-login-page-in-application-through-software
    :parameters (?sql - sqlserver ?s2 - software ?f2 - file ?Attacker - adversary ?page - loginpage)
    :precondition (and
        (use-software ?s2 ?sql ?Attacker)
        (sql-injection ?f2 ?s2 ?sql ?Attacker)
        (login-page ?page)
    )
    :effect (and
        (access-login-page-via-software ?page ?s2 ?sql)
    )
 )
 (:action attacker-gains-access-to-login-field
    :parameters ( ?s2 - software ?sql - sqlserver ?page - loginpage ?Attacker - adversary)
    :precondition (and (access-login-page-via-software ?page ?s2 ?sql) (sql-server ?sql))
    :effect (and
     (access-login-field ?page ?sql ?Attacker)
 )
 )
 (:action attacker-executes-malicious-SQL-code-in-login-field
    :parameters (?c2 - code ?sql - sqlserver ?page - loginpage ?Attacker - adversary)
    :precondition (and
        (sql-code ?c2)
        (access-login-field ?page ?sql ?Attacker)
    )
    :effect (and
        (execute-code-in-login-feild ?c2 ?page ?sql)
    )
 )
(:action attacker-compromised-databse-server
    :parameters (?c2 - code ?sql - sqlserver ?page - loginpage)
    :precondition (and (execute-code-in-login-feild ?c2 ?page ?sql) )
    :effect (and
        (compromised-sql-server ?sql)
    )
)
                                                    ;;;;;   Attacker Exploiting CVE-2015-1635 to Comromise Apache Webserver ;;;;;
                                                    
(:action attacker-exploits-vulnearble-apache-web-server-software-using-CVE-2021-41773
    :parameters (?apache - webserver ?sql - sqlserver ?Attacker - adversary ?Internet - connection ?soft1 - software ?ver1 - version)
    :precondition (and
        (compromised-sql-server ?sql)
        (has-connection-sql-to-web ?sql ?apache)
        (apache-software ?soft1)
        (apache-version ?ver1)
        ;(apache-server ?serv1)
        (attacker ?Attacker)
        (remote-access ?Internet)
        
    )
    :effect (and
        (access-to-apache-software ?soft1 ?ver1 ?apache ?Attacker)
    )
)

(:action attacker-initiates-modifications-in-path-normalization
    :parameters (?apache - webserver ?soft1 - software ?ver1 - version  ?Url - link ?File - file ?Attacker - adversary ?Internet - connection ?Attack - attack)
    :precondition (and 
        (access-to-apache-software ?soft1 ?ver1 ?apache ?Attacker)
        (apache-path ?Url)
        (apache-attack ?Attack)
        (apache-file ?File)
      )
    :effect (and 
       (map-url-to-files ?Attack ?Url ?File ?apache ?Attacker) 
    )
)
(:action attacker-gets-access-to-outside-directories
    :parameters (?Url - link ?File - file ?Directory - location ?Attacker - adversary ?apache - webserver ?Attack - attack)
    :precondition (and
        (map-url-to-files ?Attack ?Url ?File ?apache ?Attacker) 
        (apache-location ?Directory)
    )
    :effect (and
       (access-to-directories ?Directory ?apache ?Attacker) 
    )
)
(:action attacker-initiates-remote-code-execution-on-web-server
    :parameters (?Directory - location ?Attacker - adversary ?Code - code ?File - file ?apache - webserver)
    :precondition (and
        (access-to-directories ?Directory ?apache ?Attacker) 
        (apache-file ?File)
        (apache-code ?Code)
    )
    :effect (and
        (execute-code-in-file ?Code ?File ?apache)
    )
 )
(:action attacker-compromised-web-server-via-database-server
    :parameters (?Code - code ?File - file ?apache - webserver)
    :precondition (and (execute-code-in-file ?Code ?File ?apache))
    :effect (and
            (compromised-web-server ?apache)
    )
)
)
    
    