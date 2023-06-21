(define (problem network-prob)
(:domain network_final)
(:objects 
    web_port sql_port access_web_server access_admin_server access_DNS_Server - accesspoint
    server_dot_c unrestricted_file_upload crafted-http-request executable_extension SQLInjection outside_file - file
    cpsmysqlusermanager dnsmasq Ganglia microsoft-windows-8 simple-machines-forum Apache_HTTP_Server_software - software
    v2-3 before-2-0-6 windows-server-2012-gold v3-1-1 v2-7-8 v2-4-49 - version
    attacker1 - adversary
    internet - connection
    outside_directory - location
    Path_Traverse_Attack - attack
    URLs_to_Files - link
    arbitrary_sql_commands arbitrary_dns_code arbitrary_code_ftp Arbitrary_code_web CGI_Scripts - code
    login_page - loginpage
    HTTP_sys - config
Web-Server-1 Web-Server-2 Web-Server-3 Web-Server-4 Web-Server-5 Web-Server-6 Web-Server-7 Web-Server-8 Web-Server-9 Web-Server-10 Web-Server-11 Web-Server-12 Web-Server-13 Web-Server-14 Web-Server-15 Web-Server-16 Web-Server-17 Web-Server-18 Web-Server-19 Web-Server-20 - webserver
Database-Server-1 Database-Server-2 Database-Server-3 Database-Server-4 Database-Server-5 Database-Server-6 Database-Server-7 Database-Server-8 Database-Server-9 Database-Server-10 Database-Server-11 Database-Server-12 Database-Server-13 Database-Server-14 Database-Server-15 Database-Server-16 Database-Server-17 Database-Server-18 Database-Server-19 Database-Server-20 - sqlserver
)

(:init
    
    
    (access-point-web web_port)
    (remote-access internet)
    (attacker attacker1)
    (web-code Arbitrary_code_web)
    (web-file crafted-http-request)
    
    (attacker attacker1)
    (sql-code arbitrary_sql_commands)
    ;(sql-software cpsmysqlusermanager)
    ;(sql-version v2-3)
    ;(login-page login_page)
    (access-point-sql sql_port)
    (sql-file SQLInjection)
    (apache-file outside_file)
    (apache-code CGI_Scripts)
    (apache-software Apache_HTTP_Server_software)
    (apache-location outside_directory)
    (apache-attack Path_Traverse_Attack)
    (apache-version v2-4-49)
    (apache-path URLs_to_Files)
    (web-server Web-Server-1)
(sql-server Database-Server-1)
(sql-server Database-Server-2)
(sql-server Database-Server-3)
(sql-server Database-Server-4)
(sql-server Database-Server-5)
(sql-server Database-Server-6)
(sql-server Database-Server-7)
(sql-server Database-Server-8)
(sql-server Database-Server-9)
(sql-server Database-Server-10)
(sql-server Database-Server-11)
(sql-server Database-Server-12)
(sql-server Database-Server-13)
(sql-server Database-Server-14)
(sql-server Database-Server-15)
(sql-server Database-Server-16)
(sql-server Database-Server-17)
(sql-server Database-Server-18)
(sql-server Database-Server-19)
(sql-server Database-Server-20)
(has-connection-web-to-sql Web-Server-1 Database-Server-1)
(has-connection-sql-to-web Database-Server-1 Web-Server-2)
(has-connection-web-to-sql Web-Server-2 Database-Server-2)
(has-connection-sql-to-web Database-Server-2 Web-Server-3)
(has-connection-web-to-sql Web-Server-3 Database-Server-3)
(has-connection-sql-to-web Database-Server-3 Web-Server-4)
(has-connection-web-to-sql Web-Server-4 Database-Server-4)
(has-connection-sql-to-web Database-Server-4 Web-Server-5)
(has-connection-web-to-sql Web-Server-5 Database-Server-5)
(has-connection-sql-to-web Database-Server-5 Web-Server-6)
(has-connection-web-to-sql Web-Server-6 Database-Server-6)
(has-connection-sql-to-web Database-Server-6 Web-Server-7)
(has-connection-web-to-sql Web-Server-7 Database-Server-7)
(has-connection-sql-to-web Database-Server-7 Web-Server-8)
(has-connection-web-to-sql Web-Server-8 Database-Server-8)
(has-connection-sql-to-web Database-Server-8 Web-Server-9)
(has-connection-web-to-sql Web-Server-9 Database-Server-9)
(has-connection-sql-to-web Database-Server-9 Web-Server-10)
(has-connection-web-to-sql Web-Server-10 Database-Server-10)
(has-connection-sql-to-web Database-Server-10 Web-Server-11)
(has-connection-web-to-sql Web-Server-11 Database-Server-11)
(has-connection-sql-to-web Database-Server-11 Web-Server-12)
(has-connection-web-to-sql Web-Server-12 Database-Server-12)
(has-connection-sql-to-web Database-Server-12 Web-Server-13)
(has-connection-web-to-sql Web-Server-13 Database-Server-13)
(has-connection-sql-to-web Database-Server-13 Web-Server-14)
(has-connection-web-to-sql Web-Server-14 Database-Server-14)
(has-connection-sql-to-web Database-Server-14 Web-Server-15)
(has-connection-web-to-sql Web-Server-15 Database-Server-15)
(has-connection-sql-to-web Database-Server-15 Web-Server-16)
(has-connection-web-to-sql Web-Server-16 Database-Server-16)
(has-connection-sql-to-web Database-Server-16 Web-Server-17)
(has-connection-web-to-sql Web-Server-17 Database-Server-17)
(has-connection-sql-to-web Database-Server-17 Web-Server-18)
(has-connection-web-to-sql Web-Server-18 Database-Server-18)
(has-connection-sql-to-web Database-Server-18 Web-Server-19)
(has-connection-web-to-sql Web-Server-19 Database-Server-19)
(has-connection-sql-to-web Database-Server-19 Web-Server-20)
(has-connection-web-to-sql Web-Server-20 Database-Server-20)


)
(:goal (and
    ;(compromised-web-server Web-Server-1)
    (compromised-sql-server Database-Server-1)
))

)