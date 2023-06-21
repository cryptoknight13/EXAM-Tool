(define (problem network-prob)
(:domain network_final)
(:objects 
v3 v2 v1 - cvevul
attacker1 - adversary
Web-Server-1 - webserver
Database-Server-1 - sqlserver
)
(:init
( web-vulnerability-has-v1)
(attacker attacker1)
(web-server Web-Server-1)
( sql-vulnerability-has-v2)
( sql-to-web-vulnerability-has-v3)
(sql-server Database-Server-1)
(has-connection-web-to-sql Web-Server-1 Database-Server-1)
(has-connection-sql-to-web Database-Server-1 Web-Server-2)
)
(:goal (compromised-sql-server Databse-Server-8)))
