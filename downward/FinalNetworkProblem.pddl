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
Web-Server-1 - webserver
Database-Server-1 - sqlserver
)

(:init
    (web-version windows-server-2012-gold)
    (web-software microsoft-windows-8)
    (access-point-web web_port)
    (remote-access internet)
    (attacker attacker1)
    (web-code Arbitrary_code_web)
    (web-file crafted-http-request)
    (configuration HTTP_sys)
    (attacker attacker1)
    (sql-code arbitrary_sql_commands)
    (sql-software cpsmysqlusermanager)
    (sql-version v2-3)
    (login-page login_page)
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
(sql-server Database-Server-1)
(has-connection-web-to-sql Web-Server-1 Database-Server-1)

)
(:goal (and
    ;(compromised-web-server Web-Server-100)
    (compromised-sql-server Database-Server-1)
))

)