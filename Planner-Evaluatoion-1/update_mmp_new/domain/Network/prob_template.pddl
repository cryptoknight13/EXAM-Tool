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
%INIT%
)
(:goal 
(and
%GOAL%
)
)
)
