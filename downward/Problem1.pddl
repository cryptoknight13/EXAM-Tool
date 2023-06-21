(define (problem network-problem)
 (:domain network_final)
 (:objects  
   ms-web-server Database-Server FTP-server Admin-Server DNS-Server - server
   crafted-http-request SQLInjection unrestricted-file-upload executable-extension server_dot_c - file
   Arbitrary_code_web arbitrary_sql_commands arbitrary_code_ftp arbitrary_dns_code - code
   microsoft-windows-8 cpsmysqlusermanager simple-machines-forum Ganglia dnsmasq - software
   windows-server-2012-gold v2-3 version-before-2-0-6 v3-1-1 v2-7-8 - version
   internet - connection
   HTTP_sys - config
   attacker1 - adversary
   avatar-upload-functionality - functionality
   direct-request - request
   unspecified-directory - location
   access_FTP_Server access_DNS_Server access_Database access_admin_server access_web_server - accesstoken
   stack-based heap-based-buffer-overflow - buffer
   process-path - function
   gmetad - path
   longpath - pathname
   DOS_Attack - attack
   crafted-dns-response - response
 )
 (:init 
    (attacker attacker1)
    (access-web access_web_server)
    (remote-access internet)
    (web-file crafted-http-request)
    (web-server ms-web-server)
    (web-code Arbitrary_code_web)
    (web-software microsoft-windows-8)
    (web-version windows-server-2012-gold)
    (configuration HTTP_sys)
    (access-db access_Database)
    (sql-file SQLInjection)
    (sql-server Database-Server)
    (sql-code arbitrary_sql_commands)
    (sql-software cpsmysqlusermanager)
    (sql-version v2-3)
)
 (:goal (and
        (reach-to-db Database-Server)
    )
  )
 )
