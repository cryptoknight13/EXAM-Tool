(define (problem network-prob)
(:domain network_final)
(:objects 
v2 v1 v3 - cvevul
attacker1 - adversary
Web-Server-1 Web-Server-2 - webserver
Database-Server-1 Database-Server-2 - sqlserver
)
(:init
(attacker attacker1)
( sql-to-web-vulnerability-has-v3)
( sql-vulnerability-has-v2)
(web-server Web-Server-1)
( web-vulnerability-has-v1)
(sql-server Database-Server-1)
(sql-server Database-Server-2)
(has-connection-web-to-sql Web-Server-1 Database-Server-1)
(has-connection-sql-to-web Database-Server-1 Web-Server-2)
(has-connection-web-to-sql Web-Server-2 Database-Server-2)
(has-connection-sql-to-web Database-Server-2 Web-Server-3)
)
(:goal (compromised-sql-server Databse-Server-8)))
