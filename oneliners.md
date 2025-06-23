🔐 Security, Detection & Response
📌 Monitor and block brute-force IPs from /var/log/auth.log

grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1 > 5 {print $2}' | xargs -I{} iptables -A INPUT -s {} -j DROP

🔐 Integrate fail2ban with custom regex for obscure services

echo -e "[Definition]\nfailregex = .*MyCustomApp.*unauthorized.*\nignoreregex =" > /etc/fail2ban/filter.d/myapp.conf && systemctl restart fail2ban

🕵️ Tail nginx or apache logs for SQLi attempts and ban IPs

tail -F /var/log/nginx/access.log | grep --line-buffered -Ei 'union.*select|select.*from' | awk '{print $1}' | xargs -I{} iptables -A INPUT -s {} -j DROP

⚠️ Configure Suricata or Snort IDS with custom threat signatures

echo 'alert http any any -> any any (msg:"SQLi Attempt"; content:"union select"; nocase; sid:100001; rev:1;)' >> /etc/suricata/rules/local.rules && suricatasc -c reload-rules

🌐 Automate firewall updates using abuse IP databases

curl https://feodotracker.abuse.ch/downloads/ipblocklist.txt | grep -v '^#' | xargs -I{} ipset add blacklist {}

🧑‍💻 Set up auditd to trace privilege escalations or unusual syscalls

auditctl -a always,exit -F arch=b64 -S execve -F uid=0 -k root-activity

🚫 Parse logs with awk/sed to dynamically ban misbehaving users

awk '/Failed password/ {print $(NF-3)}' /var/log/auth.log | sort | uniq -c | awk '$1 > 10 {print $2}' | xargs -I{} iptables -A INPUT -s {} -j DROP

📡 Capture packets with tcpdump, inspect for lateral movement attempts

tcpdump -i eth0 port not 22 and not port 80 -nn -c 1000 -w /tmp/suspicious.pcap

🛡️ Schedule rootkit scans with chkrootkit, rkhunter, or ClamAV

(crontab -l 2>/dev/null; echo "0 3 * * * chkrootkit && rkhunter --check && clamscan -r /") | crontab -

🎣 Build a honeypot service to trap and log attacker behavior

nc -lvp 2222 > /var/log/honeypot.log &

🧠 Threat Intelligence & Automation
🔍 Parse and correlate logs across syslog, auth.log, and ufw.log

grep -i 'error\|fail' /var/log/syslog /var/log/auth.log /var/log/ufw.log | sort | uniq

🧪 Use Zeek to detect DNS tunneling and data exfiltration

zeek -r capture.pcap local && cat dns.log | grep 'type A' | awk '{print $12}' | sort | uniq -c | sort -nr

🧷 Configure ELK/Graylog to tag & alert on common CVE patterns

echo 'CVE-2024-XYZ' >> /etc/logstash/patterns.d/cve && systemctl restart logstash

🌐 Enrich malicious IPs with WHOIS lookups before blocking

for ip in $(awk '{print $(NF-3)}' /var/log/auth.log | sort | uniq); do whois $ip | grep -iE 'OrgName|Country'; done

🐶 Use watchdog to restart key services on signs of compromise

echo -e "watchdog-device = /dev/watchdog\nwatchdog-timeout = 15" >> /etc/watchdog.conf && systemctl enable --now watchdog

📡 Forward logs to a SIEM and configure correlation rules

logger -p auth.info "Forward to SIEM: $(tail -n 1 /var/log/auth.log)"

🧭 Automate netstat/ss anomaly checks for suspicious listeners

ss -tunlp | grep -vE '22|80|443' | grep LISTEN

🕰️ Lock users after unusual login hours via script

[ $(date +%H) -gt 22 ] && who | awk '{print $1}' | xargs -I{} usermod -L {}

🧪 Mirror traffic to sandbox VM for real-time malware inspection

iptables -t mangle -A PREROUTING -p tcp -j TEE --gateway 10.0.0.99

🌍 Monitor for SSH logins from non-whitelisted ASNs or geolocations

grep 'Accepted' /var/log/auth.log | awk '{print $(NF-3)}' | while read ip; do geoiplookup $ip | grep -qE 'RU|CN' && echo $ip >> /var/log/ssh_geo_alerts.log; done

🔥 Advanced Firewall & Networking
🧠 Dynamically manage iptables rules with Python

python3 -c "import iptc; rule = iptc.Rule(); rule.src='1.2.3.4'; rule.target = iptc.Target(rule, 'DROP'); iptc.Chain(iptc.Table(iptc.Table.FILTER), 'INPUT').insert_rule(rule)"

🛑 Enable rate-limiting in nftables for sensitive ports

nft add rule inet filter input tcp dport 22 limit rate 10/minute accept
nft add rule inet filter input tcp dport 22 drop

🗝️ Configure port knocking for hidden service access

knockd -d -c /etc/knockd.conf
echo '[openSSH]\nsequence = 1111,2222,3333\ncommand = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT' > /etc/knockd.conf

📛 Use ipset to manage large blocklists efficiently

ipset create blacklist hash:ip
for ip in $(cat blocklist.txt); do ipset add blacklist $ip; done
iptables -I INPUT -m set --match-set blacklist src -j DROP

🚷 Redirect suspicious traffic to a quarantine VLAN

iptables -t mangle -A PREROUTING -s 192.168.1.100 -j MARK --set-mark 99
ip rule add fwmark 99 table 100
ip route add default dev vlan999 table 100

🛡️ Implement DNS filtering using dnsmasq or Unbound

echo "address=/badsite.com/0.0.0.0" >> /etc/dnsmasq.d/blacklist.conf
systemctl restart dnsmasq

⚠️ Script dynamic rules for detecting SYN flood patterns

netstat -ntu | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | awk '$1 > 100 {print $2}' | xargs -I{} iptables -A INPUT -s {} -j DROP

❌ Harden IPv6 configurations and disable unnecessary protocols

sysctl -w net.ipv6.conf.all.disable_ipv6=1

🔄 Segment traffic using VLANs for risk isolation

ip link add link eth0 name eth0.100 type vlan id 100
ip addr add 192.168.100.1/24 dev eth0.100
ip link set up eth0.100

🔍 Configure firewalld rich rules for interface-aware filtering

firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" interface name="eth1" service name="ssh" accept'
firewall-cmd --reload

🧾 Log Analysis & Incident Forensics
Flag anomalies with logwatch or logcheck

logwatch --detail High --range today --service all --format text

Extract failed login geo-IP distribution

grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq | xargs geoiplookup | sort | uniq -c | sort -nr

Visualize auth logs with Gnuplot

awk '/Failed/ {print $1, $2, $3}' /var/log/auth.log | uniq -c > auth_fail.dat && gnuplot -e "set xdata time; set timefmt '%b %d %H:%M:%S'; plot 'auth_fail.dat' using 2:1 with lines"

Investigate audit logs after panics or faults

ausearch -m SEGV,ANOM_ABEND,USER_SEGV -ts recent | aureport -x

Parse journal logs by boots

journalctl -b -1 | grep -i 'fail\|panic\|error' | less

Detect log tampering or truncation

for f in /var/log/*.log; do tail -c 4k $f | strings | grep -i 'last line'; done

Trace cron job abuse

find /etc/cron* -type f | xargs grep -i 'wget\|curl\|nc\|python'

Detect changes to sensitive files

auditctl -w /etc/passwd -p wa -k passwd-mod
auditctl -w /etc/sudoers -p wa -k sudoers-mod

Scan for unauthorized binaries

find /tmp /dev/shm -type f -executable ! -user root -exec ls -lah {} +

Verify script hashes

sha256sum -c /opt/scripts/checksums.txt

⚙️ Performance, Tuning, and Hardening
Apply seccomp profile to exposed service

seccomp-tools dump ./myservice > myservice.seccomp.json

Isolate user processes with cgroups

cgcreate -g cpu,memory:/limited
cgset -r memory.limit_in_bytes=500M limited
cgexec -g cpu,memory:limited some_heavy_script.sh

Auto-reboot after OOM killer triggers

echo 1 > /proc/sys/vm/panic_on_oom && echo 10 > /proc/sys/kernel/panic

Reduce syscall attack surface with AppArmor

aa-genprof /usr/sbin/nginx

Detect unwanted kernel modules

lsmod | grep -vE 'ext4|xfs|nf_conntrack' > suspicious_modules.txt

Enable strict spoofing protection

sysctl -w net.ipv4.conf.all.rp_filter=1 && sysctl -p

Harden mount points

mount -o remount,nodev,nosuid,noexec /tmp

Lock sensitive files with chattr

chattr +i /etc/passwd /etc/shadow /etc/hosts

Monitor new kernel module insertions

tail -F /var/log/kern.log | grep -i 'module loaded'

Disable USB peripherals

echo 'install usb-storage /bin/true' > /etc/modprobe.d/usbblock.conf && update-initramfs -u

📡 Advanced Auditing & Logging Pipelines
Forward logs over TLS to remote aggregator

*.* @@(TLS)logstash.company.net:6514

Score threats from logs

awk '/Failed|Ban/ {score+=5} /segfault/ {score+=10} END {print "Threat Score:", score}' /var/log/syslog

Stream logs to Kafka with rsyslog

echo '*.* action(type="omkafka" topic="syslog" broker="localhost:9092")' >> /etc/rsyslog.conf && systemctl restart rsyslog

Rotate and encrypt logs with GPG

logrotate -f /etc/logrotate.conf
find /var/log -type f -name "*.1" -exec gpg --encrypt -r security@example.com {} \;

Watch for new or renamed services

systemctl list-unit-files | grep -i added | tee /var/log/service_watch.log

Alert if log integrity check fails

sha256sum -c /opt/logsums && echo "Alert: Tamper detected!" | mail -s "Log Integrity Alert" you@example.com

Correlate crashes across dmesg, audit, and journal

dmesg | grep -i 'panic\|segfault'
ausearch -m USER_SEGV
journalctl -xe

Create dashboards of top attack vectors

awk '{print $NF}' /var/log/fail2ban.log | sort | uniq -c | sort -nr | head -10 > top_bans.txt

Detect debug or verbose modes in production

grep -ri 'debug' /etc/* | grep -v '#|//' | grep -iE 'true|1'

Alert on high /var/log usage

du -sh /var/log | awk '$1+0 > 500 {print "Alert: /var/log usage high!"}'

🛠️ Scripting, Automation & Custom Tooling
Build a log correlation tool in Python

python3 -c "import pandas as pd; df = pd.read_csv('combined.log'); print(df.groupby('IP').size())"

Script a binary diff check

cmp /usr/bin/suspicious /usr/bin/suspicious.bak || echo 'Binary changed!'

Detect crypto miners by CPU/network use

top -b -n1 | grep -E '100.0%|99.9%' && ss -tunap | grep :3333

Detect newly added users

diff <(grep -vE '^#' /etc/passwd.old) <(grep -vE '^#' /etc/passwd) | grep '>' | mail -s "New Users Detected" sec@example.com

Create an audit wrapper around who/last/w

(who; last -n 5; w) | tee /var/log/user_audit_$(date +%F).log

Restrict SSH per-user IPs with shell wrapper

echo 'from="192.168.1.0/24" ssh-rsa AAA...' >> ~/.ssh/authorized_keys

Monitor Docker containers for privileged mode

docker ps --format '{{.ID}}' | xargs -I{} docker inspect {} | grep '"Privileged": true'

Lock expired/orphaned user accounts

awk -F: '$7 != "/usr/sbin/nologin" {print $1}' /etc/passwd | xargs -I{} passwd -l {}

Cron-based health check with Slack alert

*/5 * * * * curl -fs http://localhost:8080 || curl -X POST -d 'webhook_body' https://hooks.slack.com/services/...

Detect stealth I/O with iotop or atop

iotop -b -n 3 | grep -vE 'root|sshd' | sort -k10 -nr | head

🌐 Network Mapping & Vulnerability Identification
🔍 Scheduled internal port scans

nmap -sT -p- -oA /tmp/internal_scan 192.168.0.0/24

🕵️ Find rogue DHCP servers

dhcpdump -i eth0 | grep -i 'server identifier'

📡 Auto-report unauthenticated services via OpenVAS

omp -u admin -w 'pass' -T 'unauthenticated' -F xml -o scan.xml && curl -F 'file=@scan.xml' https://reporting.example.com/

🧭 Map lateral paths using ARP and MAC tables

arp -a && ip link show && brctl showmacs br0

🚨 Detect new MACs on trusted interfaces

ip neigh | grep REACHABLE | cut -d' ' -f1 | uniq -c | sort -nr

🕳️ Detect DNS leaks and proxy bypasses

curl ifconfig.me && dig TXT o-o.myaddr.l.google.com @ns1.google.com +short

🚫 Isolate hosts hitting known malicious IPs

grep -E '198\.51\.100\.' /var/log/syslog | awk '{print $5}' | uniq | xargs -I{} iptables -I FORWARD -s {} -j DROP

🧬 Detect outbound HTTP shells

tcpdump -i eth0 -A | grep -Ei 'cmd=|bash|curl'

🔐 Re-check TLS configurations

ssllabs-scan --quiet www.example.com | grep -i 'grade'

🕶️ Log login attempts from TOR exit nodes

grep 'Accepted' /var/log/auth.log | awk '{print $(NF-3)}' | xargs -I{} curl https://check.torproject.org/exit-addresses | grep {}

📊 Visualization, Reporting & Behavior Tracking
🔥 Create login source heatmap

awk '{print $1}' /var/log/auth.log | sort | uniq -c > /tmp/logins.txt && python heatmap.py /tmp/logins.txt

📋 Weekly threat summary by category

grep 'Ban\|Fail\|Blocked' /var/log/* | awk '{print $NF}' | sort | uniq -c | sort -nr > /tmp/weekly_threats.txt

🧮 Correlate bandwidth spikes with auth logs

iftop -nP -t -s 60 | tee /tmp/net_top.txt && grep 'Failed' /var/log/auth.log | tail -n 50

📈 Visualize CPU usage vs users

ps -eo user,%cpu --sort=-%cpu | head | gnuplot -p -e "plot '/dev/stdin' using 2:xtic(1) with boxes"

🦠 Map attacker behavior in kill-chain format

grep -Ei 'scan|connect|auth|exploit' /var/log/auth.log /var/log/apache2/access.log | sort

⚠️ Detect behavior drift of trusted users

awk '{print $1}' /var/log/auth.log | sort | uniq -c | awk '$1 > 20 {print "User with behavior spike:", $2}'

🚨 Trigger alert on unusual su use

grep 'session opened for user' /var/log/auth.log | grep -vE 'root|admin' | mail -s "SU Anomaly" you@example.com

🔑 Track sudo failure trends

grep 'sudo' /var/log/auth.log | grep -i 'incorrect' | awk '{print $1}' | sort | uniq -c

🕵️ Monitor for new binaries in /usr/local/bin

find /usr/local/bin -type f -exec stat -c '%n %y' {} + | sort -k2 | tail

📉 Visual trust vs alert dashboard

awk '{print $NF}' /var/log/fail2ban.log | sort | uniq -c > /tmp/trust_vs_alerts.txt && gnuplot trust_vs_alerts.txt

🧯 Containment, Quarantine & Response
🚨 Kill container if egress spikes

docker stats --no-stream | awk '$6+0 > 1000 {print $1}' | xargs -r docker kill

🧼 Quarantine suspected VM with vSwitch tag

virsh attach-interface guest suspicious-vm --type network --source quarantine --model virtio --config

🗑️ Auto-delete malicious temp files

find /tmp /dev/shm -type f -exec sha256sum {} + | grep -Ff known_malware_hashes.txt | awk '{print $2}' | xargs -I{} rm -f {}

📤 Transfer suspect logs to sandbox

scp /var/log/suspicious.log analyst@10.0.0.99:/mnt/sandbox/logs/

📬 Push IDS alerts into incident queue

grep 'ALERT' /var/log/suricata/fast.log | tail -n 10 | curl -X POST -d @- http://incident.queue.local/api/new

🔒 Kill processes binding to unassigned ports

ss -tulnp | awk '$5 !~ /22|80|443/ {print $7}' | cut -d, -f2 | xargs -r kill -9

✉️ Lock outbound mail if spam detected

grep -i 'spam' /var/log/mail.log | awk '{print $6}' | sort | uniq -c | awk '$1 > 100 {print $2}' | xargs -I{} postconf -e "inet_interfaces = loopback-only"

🛑 Monitor /etc/hosts for tampering

auditctl -w /etc/hosts -p wa -k hosts-watch

📸 Snapshot containers daily

docker ps -q | xargs -I{} docker commit {} snapshot_{} && docker save snapshot_{} > /backups/$(date +%F)-{}.tar

🧲 Block beaconing to C2 IPs dynamically

grep 'C2 connection' /var/log/suricata/fast.log | awk '{print $9}' | xargs -I{} iptables -A OUTPUT -d {} -j REJECT

