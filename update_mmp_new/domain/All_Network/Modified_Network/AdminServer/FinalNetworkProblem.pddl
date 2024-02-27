(define (problem network-prob)
(:domain network_final)
(:objects 
unrestricted_file_upload executable_extension server_dot_c SQLInjection crafted-http-request - file
Arbitrary_code_web arbitrary_dns_code arbitrary_sql_commands arbitrary_code_ftp malicious_sql_code arbitrary_apache_code arbitrary_microsoft_code - code
access_web_server access_admin_server access_FTP_Server access_Database access_DNS_Server - accesstoken
longpath - pathname
stack-based heap-based-buffer-overflow - buffer
v2-7-8 windows-server-2012-gold v2-3 before-2-0-6 v3-1-1 v4-8 before-v13-0-12 v9-3-to-10 before-and-v1-5-0 v2-4-17-to-2-4-38 - version
crafted-dns-response - response
cpsmysqlusermanager dnsmasq Ganglia microsoft-windows-8 simple-machines-forum Torguard-VPN GitLab-Runner postgresql MongoDB-Go-Driver Apache-HTTP-2-4 Microsoft-Exchange - software
login_page - loginpage
Shared-Runner - environment
Malicious-Server - malserver
flaw1 - malsoftware
dockerd - daemon
Sensitive_Credentials - admindata
HTTP_sys - config
avatar_upload_functionality - functionality
gmetad - path
process-path - function
object1 - object
string1 - cstring
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

(sql-software-3 postgresql)
(sql-version-3 v9-3-to-10)
(sql-code-2 malicious_sql_code)
(sql-flaw flaw1)
(attacker-with-user-account attacker1)

(sql-software-5 MongoDB-Go-Driver)
(sql-version-5 before-and-v1-5-0)
(go-object object1)
(specific-cstring string1)

(access-admin access_admin_server)
(buffer-overflow heap-based-buffer-overflow)
(access-db access_Database)
(longpath longpath)
(admin-version v3-1-1)
(admin-file server_dot_c)
(admin-software Ganglia)
(admin-path gmetad)

(admin-software-2 Torguard-VPN)
(admin-version-2 v4-8)
(information Sensitive_Credentials)

(admin-software-4 Apache-HTTP-2-4)
(admin-version-4 v2-4-17-to-2-4-38)
(admin-code arbitrary_apache_code)

(admin-software-3 Microsoft-Exchange)
(admin-code-2 arbitrary_microsoft_code)

(ftp-file unrestricted_file_upload)
(request-ftp direct-request)
(exe-file executable_extension)
(admin-function process-path)
(access-ftp access_FTP_Server)
(ftp-code arbitrary_code_ftp)
(ftp-version before-2-0-6)
(ftp-software simple-machines-forum)
(directory unspecified_directory)
(ftp-functionality avatar_upload_functionality)

(dns-code arbitrary_dns_code)
(access-dns access_DNS_Server)
(response-dns crafted-dns-response)
(dns-software dnsmasq)
(dns-attack DOS_Attack)
(dns-version v2-7-8)
(admin-attack DOS_Attack)

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
        (compromised-admin-server Admin-Server-1)
        ;(compromised-sql-server Database-Server-1)
        ;(compromised-web-server Web-Server-1)
        ;(compromised-ftp-server FTP-Server-1)
))
