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
(:INIT 
(access-admin access_admin_server)
(dns-attack dos_attack)
(exe-file executable_extension)
(response-dns crafted-dns-response)
(configuration http_sys)
(admin-software-4 apache-http-2-4)
(web-file crafted-http-request)
(sql-version v2-3)
(buffer-overflow heap-based-buffer-overflow)
(sql-software-5 mongodb-go-driver)
(ftp-server ftp-server-1)
(sql-software cpsmysqlusermanager)
(admin-attack dos_attack)
(go-object object1)
(sql-software-3 postgresql)
(sql-server database-server-1)
(remote-access internet)
(access-db access_database)
(has-connected web-server-1 database-server-1 admin-server-1 ftp-server-1 dns-server-1)
(admin-code arbitrary_apache_code)
(ftp-file unrestricted_file_upload)
(information sensitive_credentials)
(sql-file sqlinjection)
(sql-code arbitrary_sql_commands)
(ftp-software simple-machines-forum)
(admin-server admin-server-1)
(admin-code-2 arbitrary_microsoft_code)
(specific-cstring string1)
(sql-daemon dockerd)
(access-web access_web_server)
(admin-version-2 v4-8)
(admin-version v3-1-1)
(admin-software-2 torguard-vpn)
(directory unspecified_directory)
(attacker attacker1)
(longpath longpath)
(sql-version-5 before-and-v1-5-0)
(admin-software ganglia)
(dns-server dns-server-1)
(sql-env shared-runner)
(admin-path gmetad)
(access-dns access_dns_server)
(sql-version-3 v9-3-to-10)
(admin-function process-path)
(sql-code-2 malicious_sql_code)
(dns-software dnsmasq)
(login-page login_page)
(admin-file server_dot_c)
(web-software microsoft-windows-8)
(access-ftp access_ftp_server)
(web-server web-server-1)
(sql-malicious-server malicious-server)
(admin-software-3 microsoft-exchange)
(ftp-version before-2-0-6)
(dns-code arbitrary_dns_code)
(web-version windows-server-2012-gold)
(buffer-overflow stack-based)
(admin-version-4 v2-4-17-to-2-4-38)
(ftp-functionality avatar_upload_functionality)
(sql-version-2 before-v13-0-12)
(web-code arbitrary_code_web)
(sql-software-2 gitlab-runner)
(request-ftp direct-request)
(ftp-code arbitrary_code_ftp)
(sql-attack server-side-request-forgery)
(attacker-with-user-account attacker1)
(sql-flaw flaw1)
)
(:goal 
(and
(compromised-dns-server dns-server-1)
)
)
)
