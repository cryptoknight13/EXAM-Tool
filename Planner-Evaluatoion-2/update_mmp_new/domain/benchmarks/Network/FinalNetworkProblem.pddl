(define (problem network-problem)
 (:domain network_final)
 (:objects
              ;;;;;  Web server - Compromised ;;;;;
   ms-web-server - server
              ;;;;;  Data base server - Compromised ;;;;;
   ;ms-web-server Database-Server - server 
              ;;;;;  FTP server - Compromised ;;;;;
   ;ms-web-server Database-Server FTP-server - server
              ;;;;;  Admin server - Compromised ;;;;;
   ;ms-web-server Database-Server FTP-server Admin-Server - server
              ;;;;;  DNS server - Compromised ;;;;;   
   ;ms-web-server Database-Server FTP-server Admin-Server DNS-Server - server
   
               ;;;;;  Web file  ;;;;;
   crafted-http-request - file
               ;;;;;  Database file  ;;;;;
   ;crafted-http-request SQLInjection - file
               ;;;;;  FTP file  ;;;;;
   ;crafted-http-request SQLInjection unrestricted-file-upload executable-extension - file
               ;;;;;  Admin file  ;;;;;
   ;crafted-http-request SQLInjection unrestricted-file-upload executable-extension server_dot_c - file
   
               ;;;;;  Web Code  ;;;;;
   Arbitrary_code_web - code
               ;;;;;  Database Code  ;;;;;
   ;Arbitrary_code_web arbitrary_sql_commands - code
               ;;;;;  FTP Code  ;;;;;
   ;Arbitrary_code_web arbitrary_sql_commands arbitrary_code_ftp - code
               ;;;;;  Admin Code  ;;;;;
   ;Arbitrary_code_web arbitrary_sql_commands arbitrary_code_ftp - code
               ;;;;;  DNS Code  ;;;;;
   ;Arbitrary_code_web arbitrary_sql_commands arbitrary_code_ftp arbitrary_dns_code - code
    
               ;;;;;  Web Software  ;;;;;
   microsoft-windows-8 - software
               ;;;;;  Database Software  ;;;;;
   ;microsoft-windows-8 cpsmysqlusermanager - software
               ;;;;;  FTP Software  ;;;;;
   ;microsoft-windows-8 cpsmysqlusermanager simple-machines-forum - software
               ;;;;;  Admin Software  ;;;;;
   ;microsoft-windows-8 cpsmysqlusermanager simple-machines-forum Ganglia - software
               ;;;;;  DNS Software  ;;;;;
   ;microsoft-windows-8 cpsmysqlusermanager simple-machines-forum Ganglia dnsmasq - software
   
               ;;;;;  Web version  ;;;;;
   windows-server-2012-gold - version
               ;;;;;  Database version  ;;;;;
   ;windows-server-2012-gold v2-3 - version
               ;;;;;  FTP version  ;;;;;
   ;windows-server-2012-gold v2-3 version-before-2-0-6 - version
               ;;;;;  Admin version  ;;;;;
   ;windows-server-2012-gold v2-3 version-before-2-0-6 v3-1-1 - version
               ;;;;;  DNS version  ;;;;;
   ;windows-server-2012-gold v2-3 version-before-2-0-6 v3-1-1 v2-7-8 - version
   
   internet - connection
   HTTP_sys - config
   attacker1 - adversary
              ;;;;;;;;;;;;;;; FTP Server ;;;;;;;;;;;;;;;
   avatar-upload-functionality - functionality
   direct-request - request
   unspecified-directory - location
              ;;;;;;;;;;;;;; FTP Server 2 ;;;;;;;;;;;;;;
   ;Remote-Desktop-Protocol
   ;deleted-object
   ;unprocessed-packets-in-memory
   access_FTP_Server - accesstoken
   access_DNS_Server - accesstoken
   access_Database - accesstoken
   access_admin_server - accesstoken
   access_web_server - accesstoken
              ;;;;;;;;;;;;;; Admin Server ;;;;;;;;;;;;
    stack-based - buffer
    process-path - function
    gmetad - path
    longpath - pathname
    DOS_Attack - attack
             ;;;;;;;;;;;;;;; DNS Server ;;;;;;;;;;;;;;;
    crafted-dns-response - response
    heap-based-buffer-overflow - buffer
 )
 (:init
                            ;;;;;;;;;;   Web Server   ;;;;;;;;;;;;    
    (attacker attacker1)
    (access-web access_web_server)
    (software microsoft-windows-8)
    (version windows-server-2012-gold)
    (remote-access internet)
    (main-server ms-web-server)
    (safe-server ms-web-server)
    (file crafted-http-request)
    (configuration HTTP_sys)
    (code Arbitrary_code_web)
    
      
                            ;;;;;;;;;;   DNS Server   ;;;;;;;;;;;;
    ;(attacker attacker1)
    ;(buffer-overflow heap-based-buffer-overflow)
    ;(response crafted-dns-response)
    ;(code arbitrary_dns_code)
    ;(remote-access internet)
    ;(main-server DNS-Server)
    ;(safe-server DNS-Server)
    ;(access-dns access_DNS_Server)
    ;(attack DOS_Attack)
    
                                ;;;;;   Database Server   ;;;;;;
    
    ;(access-db access_Database)
    
                                ;;;;;   FTP Server  ;;;;;;;;;
    ;(functionality avatar-upload-functionality)
    ;(exe-file executable-extension)
    ;(request direct-request)
    ;(directory unspecified-directory)
    ;(access-ftp access_FTP_Server)
    
                                ;;;;;   Admin Server Server   ;;;;;;
    ;(access-admin access_admin_server)
    ;(buffer-overflow stack-based)
    ;(function process-path)
    ;(c-file server_dot_c)
    ;(path gmetad)
    ;(longpath longpath)
    ;(attack DOS_Attack)
)
 (:goal (and
                            ;;;;;;;;;;   Web Server   ;;;;;;;;;;;;
        (compromised-server ms-web-server)
                            ;;;;;;;;;;   Database Server   ;;;;;;;;;;;;
        ;(compromised-server Database-Server)
                            ;;;;;;;;;;   FTP Server   ;;;;;;;;;;;;
        ;(compromised-server FTP-server)
                            ;;;;;;;;;;   Admin Server   ;;;;;;;;;;;;
       ;(compromised-server Admin-Server)
                            ;;;;;;;;;;   DNS Server   ;;;;;;;;;;;
                            ;;;;;;;;;;   DNS Server   ;;;;;;;;;;;;        
        ;(compromised-server DNS-Server)
    )
  )
 )
