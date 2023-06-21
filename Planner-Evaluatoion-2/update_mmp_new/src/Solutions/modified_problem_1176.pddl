(define (problem network-prob)
(:domain network_final)
(:objects 
unrestricted_file_upload executable_extension server_dot_c SQLInjection crafted-http-request - file
Arbitrary_code_web arbitrary_dns_code arbitrary_sql_commands arbitrary_code_ftp - code
access_web_server access_admin_server access_FTP_Server access_Database access_DNS_Server - accesstoken
longpath - pathname
stack-based heap-based-buffer-overflow - buffer
v2-7-8 windows-server-2012-gold v2-3 before-2-0-6 v3-1-1 v4-8 before-v13-0-12 - version
crafted-dns-response - response
cpsmysqlusermanager dnsmasq Ganglia microsoft-windows-8 simple-machines-forum Torguard-VPN GitLab-Runner - software
login_page - loginpage
Shared-Runner - environment
Malicious-Server - malserver
dockerd - daemon
Sensitive_Credentials - admindata
HTTP_sys - config
avatar_upload_functionality - functionality
gmetad - path
process-path - function
attacker1 - adversary
unspecified_directory - location
direct-request - request
DOS_Attack Server-Side-Request-Forgery - attack
internet - connection
Web-Server-1 - webserver
Database-Server-1 - sqlserver
FTP-Server-1 - ftpserver
Admin-Server-1 - adminserver
DNS-Server-1 - dnsserver
)
(:INIT 
(response crafted-dns-response)
(dns-version v2-7-8)
(web-server web-server-1)
(admin-version v3-1-1)
(web-software microsoft-windows-8)
(sql-malicious-server malicious-server)
(admin-version-2 v4-8)
(admin-file server_dot_c)
(access-dns access_dns_server)
(access-db access_database)
(function process-path)
(web-file crafted-http-request)
(buffer-overflow heap-based-buffer-overflow)
(attacker attacker1)
(ftp-server ftp-server-1)
(directory unspecified_directory)
(dns-software dnsmasq)
(admin-software ganglia)
(longpath longpath)
(ftp-file unrestricted_file_upload)
(dns-server dns-server-1)
(remote-access internet)
(sql-env shared-runner)
(information sensitive_credentials)
(ftp-functionality avatar_upload_functionality)
(sql-version v2-3)
(sql-server database-server-1)
(path gmetad)
(sql-software-2 gitlab-runner)
(request direct-request)
(access-web access_web_server)
(ftp-code arbitrary_code_ftp)
(sql-code arbitrary_sql_commands)
(exe-file executable_extension)
(web-code arbitrary_code_web)
(sql-file sqlinjection)
(access-ftp access_ftp_server)
(ftp-software simple-machines-forum)
(sql-attack server-side-request-forgery)
(buffer-overflow stack-based)
(admin-software-2 torguard-vpn)
(access-admin access_admin_server)
(admin-server admin-server-1)
(attack dos_attack)
(has-connected web-server-1 database-server-1 admin-server-1 ftp-server-1 dns-server-1)
(ftp-version before-2-0-6)
(dns-code arbitrary_dns_code)
(configuration http_sys)
)
(:goal 
(and
(compromised-sql-server database-server-1)
)
)
)
