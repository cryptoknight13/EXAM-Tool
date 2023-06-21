(define (problem network-prob)
(:domain network_final)
(:objects 
unrestricted_file_upload executable_extension server_dot_c SQLInjection crafted-http-request - file
Arbitrary_code_web arbitrary_dns_code arbitrary_sql_commands arbitrary_code_ftp - code
access_web_server access_admin_server access_FTP_Server access_Database access_DNS_Server - accesstoken
longpath - pathname
stack-based heap-based-buffer-overflow - buffer
v2-7-8 windows-server-2012-gold v2-3 before-2-0-6 v3-1-1 v4-8 - version
crafted-dns-response - response
cpsmysqlusermanager dnsmasq Ganglia microsoft-windows-8 simple-machines-forum Torguard-VPN - software
login_page - loginpage
Sensitive_Credentials - admindata
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
(:INIT 
(ftp-file unrestricted_file_upload)
(web-code arbitrary_code_web)
(remote-access internet)
(ftp-code arbitrary_code_ftp)
(ftp-software simple-machines-forum)
(response crafted-dns-response)
(access-dns access_dns_server)
(longpath longpath)
(sql-file sqlinjection)
(access-web access_web_server)
(ftp-version before-2-0-6)
(configuration http_sys)
(web-server web-server-1)
(admin-server admin-server-1)
(has-connected web-server-1 database-server-1 admin-server-1 ftp-server-1 dns-server-1)
(attacker attacker1)
(ftp-server ftp-server-1)
(access-ftp access_ftp_server)
(information sensitive_credentials)
(web-software microsoft-windows-8)
(access-admin access_admin_server)
(exe-file executable_extension)
(request direct-request)
(buffer-overflow stack-based)
(ftp-functionality avatar_upload_functionality)
(sql-software cpsmysqlusermanager)
(sql-server database-server-1)
(dns-code arbitrary_dns_code)
(web-file crafted-http-request)
(dns-server dns-server-1)
(login-page login_page)
(function process-path)
(sql-version v2-3)
(admin-version v3-1-1)
(attack dos_attack)
(sql-code arbitrary_sql_commands)
(buffer-overflow heap-based-buffer-overflow)
(directory unspecified_directory)
(access-db access_database)
(dns-version v2-7-8)
)
(:goal 
(and
(compromised-admin-server admin-server-1)
)
)
)
