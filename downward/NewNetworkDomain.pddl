( define  (domain network_example)
(:requirements :strips :typing)
(:types server software version file code connection location adversary accesstoken attack link)
(:predicates 
                                                              ;Common Predicates;

 (access-web ?Acc1 - accesstoken)
 (attacker ?Attacker - adversary)
 (remote-access ?Internet - connection)
 (main-server ?server - server)
 (safe-server ?server - server)
 (compromised-server ?CompServ - server)

 
                                                      ;;;;;;;;;; Predicates for Web Server ;;;;;;;;;;;;
 (reach-to-web ?Server - server)
 (connected-to-web ?Server - server)
 (web-file ?File - file) ;outside_file
 (web-location ?Directory - location) ; /outside_directory
 (web-server ?Server - server)
 (web-code ?Code - code) ;CGI Scripts
 (web-software ?Software - software)
 (web-version ?Version - version)
 (web-attack ?Attack - attack) ; path travse attack
 (web-path ?Url - link)
 (map-url-to-files ?Url - link ?File - file)
 (execute-code-in-file ?Code - code ?File - file)
 (access-to-directories ?Directory - location ?Attacker - adversary)
 (access-to-server ?server - server ?Attacker - adversary ?Internet - connection)
 (access-to-web-software ?Software - software ?Attacker - adversary)
)
          
                                                              ;Actions for Web Server;
;Accces to web-server
;attacker-connected-to-web-server
;change-made-in-path-normalization-in software
;Access-to-outside-directries-and files
;rmote-code-execution
(:action Access-to-Webserver
    :parameters (?serv1 - server ?Access - accesstoken ?Internet - connection)
    :precondition(and
        (access-web ?Access)
        (web-server ?serv1)
        (remote-access ?Internet)
    )
    :effect(and
        (connected-to-web ?serv1)
    )
)
(:action CVE-2021-41773-attacker-connected-to-web-server
    :parameters (?serv1 - server ?Attacker - adversary ?Internet - connection ?soft1 - software ?ver1 - version)
    :precondition (and
        (connected-to-web ?serv1)
        (web-software ?soft1)
        (web-version ?ver1)
        (attacker ?Attacker)
        (remote-access ?Internet)
        
    )
    :effect (and
        (access-to-server ?serv1 ?Attacker ?Internet)
        (main-server ?serv1)
        (safe-server ?serv1)
        (access-to-web-software ?soft1 ?Attacker)
 
    )
)
(:action CVE-2021-41773-change-in-path-normalization
    :parameters (?serv1 - server ?soft1 - software ?ver1 - version  ?Url - link ?File - file ?Attacker - adversary ?Internet - connection ?Attack - attack)
    :precondition (and 
        (access-to-web-software ?soft1 ?Attacker)
        (main-server ?serv1)
        (safe-server ?serv1)
        (access-to-server ?serv1 ?Attacker ?Internet)
        (web-path ?Url)
        (web-attack ?Attack)
        (web-file ?File)
      )
    :effect (and 
       (map-url-to-files ?Url ?File) 
    )
)

(:action CVE-2021-41773-access-to-outside-directories
    :parameters (?Url - link ?File - file ?Directory - location ?Attacker - adversary)
    :precondition (and
        (map-url-to-files ?Url ?File) 
        (web-location ?Directory)
        (attacker ?Attacker)
    )
    :effect (and
       (access-to-directories ?Directory ?Attacker) 
    )
)

(:action CVE-2021-41773-remote-code-execution
    :parameters (?Directory - location ?Attacker - adversary ?Code - code ?File - file)
    :precondition (and
        (access-to-directories ?Directory ?Attacker)
        (web-code ?Code)
    )
    :effect (and
        (execute-code-in-file ?Code ?File)
    )
 )
 (:action Web-Server-Compromised
    :parameters (?serv1 - server ?Code - code ?File - file)
    :precondition (and
        (execute-code-in-file ?Code ?File)
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
)