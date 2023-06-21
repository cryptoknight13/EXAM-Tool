(define (problem network-prob)
(:domain network_final)
(:objects 
    v1 v2 v3 - cvevul
    attacker1 - adversary
)

(:init
    (has-web-vulnerability v1)
    (has-sql-vulnerability v2)
    (has-sql-to-web-vulnerability v3)
    (attacker attacker1)
    (web-server Web-Server-1)

)
(:goal (and
    (compromised-sql-server Databse-Server-8)
))

)