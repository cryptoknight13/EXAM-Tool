(define (problem network-problem)
 (:domain network_example)
 (:objects  
   Apache-web-server - server
   outside_file - file
   CGI_Scripts - code
   Apache_HTTP_Server - software
   v2-4-49 - version
   internet - connection
   attacker1 - adversary
   outside_directory - location
   access_web_server - accesstoken
   Path_Traverse_Attack - attack
   URLs_to_Files - link
 )
 (:init 
    (attacker attacker1)
    (web-attack Path_Traverse_Attack)
    (access-web access_web_server)
    (remote-access internet)
    (web-file outside_file)
    (web-server Apache-web-server)
    (web-code CGI_Scripts)
    (web-software Apache_HTTP_Server)
    (web-location outside_directory)
    (web-version v2-4-49)
    (web-path URLs_to_Files)
)
 (:goal (and
       (compromised-server Apache-web-server)
    )
  )
 )
