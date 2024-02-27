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
(:init
(web-version windows-server-2012-gold)
(web-software microsoft-windows-8)
(configuration HTTP_sys)
(web-code Arbitrary_code_web)
(access-web access_web_server)
(web-file crafted-http-request)

(sql-code arbitrary_sql_commands)
(sql-file SQLInjection)
(sql-software cpsmysqlusermanager)
(sql-version v2-3)
(login-page login_page)

(sql-env Shared-Runner)
(sql-software-2 GitLab-Runner)
(sql-version-2 before-v13-0-12)
(sql-daemon dockerd)
(sql-malicious-server Malicious-Server)
(sql-attack Server-Side-Request-Forgery)

(access-admin access_admin_server)
(buffer-overflow heap-based-buffer-overflow)
(access-db access_Database)



(information Sensitive_Credentials)

(ftp-file unrestricted_file_upload)
(request direct-request)
(exe-file executable_extension)
(function process-path)
(access-ftp access_FTP_Server)
(ftp-code arbitrary_code_ftp)
(ftp-version before-2-0-6)
(ftp-software simple-machines-forum)
(directory unspecified_directory)
(ftp-functionality avatar_upload_functionality)
(function process-path)

(dns-code arbitrary_dns_code)
(access-dns access_DNS_Server)
(response crafted-dns-response)
(dns-software dnsmasq)
(dns-version v2-7-8)
(attack DOS_Attack)

(remote-access internet)
(attacker attacker1)
(buffer-overflow stack-based)

(web-server Web-Server-1)
(sql-server Database-Server-1)
(ftp-server FTP-Server-1)
(admin-server Admin-Server-1)
(dns-server DNS-Server-1)
(has-connected Web-Server-1 Database-Server-1 Admin-Server-1 FTP-Server-1 DNS-Server-1)
)
(:goal  ;(compromised-dns-server DNS-Server-1)
        ;(compromised-admin-server Admin-Server-1)
        (compromised-sql-server Database-Server-1)
        ;(compromised-web-server Web-Server-1)
        ;(compromised-ftp-server FTP-Server-1)
))
