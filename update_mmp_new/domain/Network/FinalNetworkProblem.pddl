(define (problem network-prob)
(:domain network_final)
(:objects 
unrestricted_file_upload executable_extension server_dot_c SQLInjection crafted-http-request - file
Arbitrary_code_web arbitrary_dns_code arbitrary_sql_commands arbitrary_code_ftp - code
access_web_server access_admin_server access_FTP_Server access_Database access_DNS_Server - accesstoken
longpath - pathname
stack-based heap-based-buffer-overflow - buffer
v2-7-8 windows-server-2012-gold v2-3 before-2-0-6 v3-1-1 - version
crafted-dns-response - response
cpsmysqlusermanager dnsmasq Ganglia microsoft-windows-8 simple-machines-forum - software
login_page - loginpage
HTTP_sys - config
avatar_upload_functionality - functionality
gmetad - path
process-path - function
attacker1 - adversary
unspecified_directory - location
direct-request - request
DOS_Attack - attack
internet - connection
Web-Server-1 - webserver
Database-Server-1 - sqlserver
FTP-Server-1 - ftpserver
Admin-Server-1 - adminserver
DNS-Server-1 - dnsserver
)
(:init
(sql-code arbitrary_sql_commands)
(admin-version v3-1-1)
(ftp-file unrestricted_file_upload)
(web-version windows-server-2012-gold)
(access-admin access_admin_server)
(function process-path)
(attacker attacker1)
(dns-software dnsmasq)
(longpath longpath)
(sql-file SQLInjection)
(directory unspecified_directory)
(access-dns access_DNS_Server)
(web-code Arbitrary_code_web)
(dns-code arbitrary_dns_code)
(admin-file server_dot_c)
(ftp-version before-2-0-6)
(exe-file executable_extension)
(buffer-overflow heap-based-buffer-overflow)
(ftp-software simple-machines-forum)
(access-db access_Database)
(login-page login_page)
(path gmetad)
(remote-access internet)
(access-web access_web_server)
(admin-software Ganglia)
(ftp-code arbitrary_code_ftp)
(configuration HTTP_sys)
(dns-version v2-7-8)
(buffer-overflow stack-based)
(access-ftp access_FTP_Server)
(ftp-functionality avatar_upload_functionality)
(web-file crafted-http-request)
(sql-software cpsmysqlusermanager)
(web-software microsoft-windows-8)
(sql-version v2-3)
(request direct-request)
(response crafted-dns-response)
(attack DOS_Attack)
(web-server Web-Server-1)
(sql-server Database-Server-1)
(ftp-server FTP-Server-1)
(admin-server Admin-Server-1)
(dns-server DNS-Server-1)
(has-connected Web-Server-1 Database-Server-1 Admin-Server-1 FTP-Server-1 DNS-Server-1)
)
(:goal (compromised-admin-server Admin-Server-1)))
