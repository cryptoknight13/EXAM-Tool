( define  (domain network_final)
(:requirements :strips :typing)
(:types server software version file code connection config adversary accesstoken)
(:predicates 
                                                              ;Common Predicates;

 (access-web ?Acc4 - accesstoken)
 
 (server ?server - server)
 (attacker ?Attacker - adversary)
 (software ?software - software)
 (file ?File - file)
 (version ?Version - version)
 (remote-access ?Internet - connection)
 (main-server ?server - server)
 (safe-server ?server - server)
 (compromised-server ?CompServ - server)
 (access-to-server ?server - server ?Attacker - adversary ?Internet - connection)
 (access-to-software ?software - software ?Attacker - adversary)
 (code ?Code - code)
 (execute-code ?server - server ?Code - code)
                                                      ;;;;;;;;;; Predicates for Web Server ;;;;;;;;;;;;

 (configuration ?config - config)
 (execute-file-in-config ?File - file ?config - config)
 )
          ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
          
          
          
                                                              ;Actions for Web Server;
(:action attacker-connected-to-web-server
    :parameters (?serv1 - server ?Attacker - adversary ?Internet - connection ?Access - accesstoken)
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
(:action CVE-2015-1635-remote-attack-intiation
    :parameters (?serv1 - server ?s1 - software ?v1 - version  ?Attacker - adversary ?Internet - connection ?Access - accesstoken)
    :precondition (and 
        (access-web ?Access)
        (access-to-server ?serv1 ?Attacker ?Internet)
        (main-server ?serv1)
        (safe-server ?serv1)
        (software ?s1)
        (version ?v1)
    )
    :effect (and 
        (access-to-software ?s1 ?Attacker)
    )
)

(:action CVE-2015-1635-sends-malicious-request-to-config
    :parameters (?serv1 - server ?f1 - file ?s1 - software ?config - config ?Attacker - adversary)
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

(:action CVE-2015-1635-privilige-to-execute-arbitrary-code-in-Web-Server
    :parameters (?serv1 - server ?f1 - file ?c1 - code  ?config - config)
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
        )
    )

)