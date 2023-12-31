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
(:INIT 
(sql-server database-server-2)
(sql-server database-server-1)
(sql-server database-server-20)
(has-connection-web-to-sql web-server-16 database-server-16)
(has-connection-web-to-sql web-server-12 database-server-12)
(sql-server database-server-19)
(web-file crafted-http-request)
(apache-file outside_file)
(access-point-web web_port)
(has-connection-web-to-sql web-server-2 database-server-2)
(sql-server database-server-7)
(has-connection-sql-to-web database-server-8 web-server-9)
(sql-server database-server-5)
(attacker attacker1)
(remote-access internet)
(sql-server database-server-13)
(web-server web-server-1)
(has-connection-sql-to-web database-server-2 web-server-3)
(apache-version v2-4-49)
(has-connection-web-to-sql web-server-6 database-server-6)
(has-connection-web-to-sql web-server-3 database-server-3)
(has-connection-web-to-sql web-server-20 database-server-20)
(has-connection-sql-to-web database-server-10 web-server-11)
(has-connection-sql-to-web database-server-18 web-server-19)
(access-point-sql sql_port)
(has-connection-web-to-sql web-server-5 database-server-5)
(has-connection-sql-to-web database-server-5 web-server-6)
(has-connection-sql-to-web database-server-15 web-server-16)
(has-connection-web-to-sql web-server-10 database-server-10)
(has-connection-sql-to-web database-server-9 web-server-10)
(apache-attack path_traverse_attack)
(sql-server database-server-16)
(has-connection-web-to-sql web-server-7 database-server-7)
(has-connection-sql-to-web database-server-7 web-server-8)
(sql-server database-server-11)
(has-connection-web-to-sql web-server-13 database-server-13)
(has-connection-sql-to-web database-server-13 web-server-14)
(sql-server database-server-3)
(has-connection-sql-to-web database-server-17 web-server-18)
(sql-code arbitrary_sql_commands)
(has-connection-sql-to-web database-server-19 web-server-20)
(has-connection-web-to-sql web-server-17 database-server-17)
(has-connection-web-to-sql web-server-8 database-server-8)
(has-connection-sql-to-web database-server-1 web-server-2)
(has-connection-web-to-sql web-server-1 database-server-1)
(apache-code cgi_scripts)
(sql-server database-server-10)
(apache-path urls_to_files)
(has-connection-web-to-sql web-server-14 database-server-14)
(apache-software apache_http_server_software)
(has-connection-sql-to-web database-server-12 web-server-13)
(sql-server database-server-9)
(has-connection-sql-to-web database-server-3 web-server-4)
(sql-server database-server-12)
(has-connection-web-to-sql web-server-11 database-server-11)
(sql-server database-server-8)
(sql-server database-server-15)
(apache-location outside_directory)
(has-connection-web-to-sql web-server-4 database-server-4)
(has-connection-sql-to-web database-server-11 web-server-12)
(sql-file sqlinjection)
(has-connection-web-to-sql web-server-19 database-server-19)
(has-connection-sql-to-web database-server-16 web-server-17)
(has-connection-web-to-sql web-server-9 database-server-9)
(sql-server database-server-17)
(has-connection-sql-to-web database-server-14 web-server-15)
(sql-server database-server-4)
(has-connection-sql-to-web database-server-6 web-server-7)
(sql-server database-server-6)
(has-connection-web-to-sql web-server-15 database-server-15)
(sql-server database-server-14)
(has-connection-sql-to-web database-server-4 web-server-5)
(sql-server database-server-18)
(web-code arbitrary_code_web)
(has-connection-web-to-sql web-server-18 database-server-18)
)
(:goal 
(and
(compromised-sql-server database-server-1)
)
)
)
