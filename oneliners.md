

## 🗺️ Network Mapping & Vulnerability Identification

### **Scheduled Internal Port Scans**
```bash
# Comprehensive internal network scan
nmap -sT -p- -oA /tmp/internal_scan 192.168.0.0/24

# Quick service discovery scan
nmap -sS -O -sV --top-ports 1000 -oA /tmp/service_scan 10.0.0.0/8

# Vulnerability scan with scripts
nmap --script vuln -oA /tmp/vuln_scan 192.168.1.0/24
```

### **Rogue Service Detection**
```bash
# Find rogue DHCP servers using dhcpdump
dhcpdump -i eth0 | grep -i 'server identifier'

# Detect unauthorized DNS servers
dig @192.168.1.1 . NS | grep -v "expected-dns-server"

# Find rogue access points
iwlist scan | grep -E 'ESSID|Address' | grep -v "authorized-ssid"
```

### **Automated Vulnerability Reporting**
```bash
# Auto-report unauthenticated services via OpenVAS
omp -u admin -w 'pass' -T 'unauthenticated' -F xml -o scan.xml && \
curl -F 'file=@scan.xml' https://reporting.example.com/

# Automated Nessus scan trigger
curl -X POST -H "X-ApiKeys: accessKey=abc; secretKey=xyz" \
  https://nessus.local:8834/scans/123/launch

# Generate vulnerability summary report
openvas-cli -u admin -w admin --get-report abc-123 --format=pdf > vuln_report.pdf
```

### **Network Topology Discovery**
```bash
# Map lateral paths with ARP and MAC tables
arp -a && ip link show && brctl showmacs br0

# Discover network topology via traceroute
for ip in 192.168.1.{1..254}; do traceroute -m 5 $ip 2>/dev/null; done

# Map VLAN configurations
vconfig | grep -v "VLAN Dev name"
```

### **Network Anomaly Detection**
```bash
# Detect new MACs on trusted interfaces
ip neigh | grep REACHABLE | cut -d' ' -f1 | uniq -c | sort -nr

# Monitor for MAC address changes
arp-scan -l | diff /tmp/baseline_macs.txt -

# Detect ARP spoofing attempts
tcpdump -i eth0 arp | awk '{print $12, $14}' | sort | uniq -c | sort -nr
```

### **DNS Security Monitoring**
```bash
# Detect DNS leaks and proxy bypasses
curl ifconfig.me && dig TXT o-o.myaddr.l.google.com @ns1.google.com +short

# Monitor DNS tunneling attempts
tcpdump -i eth0 -s 0 -A port 53 | grep -E '[a-zA-Z0-9]{50,}'

# Check for DNS cache poisoning
dig @8.8.8.8 google.com | grep -A1 "ANSWER SECTION"
```

### **Threat Response & Isolation**
```bash
# Isolate hosts hitting malicious IPs
grep -E '198\.51\.100\.' /var/log/syslog | awk '{print $5}' | uniq | \
xargs -I{} iptables -I FORWARD -s {} -j DROP

# Block suspicious domains
echo "malicious.domain.com" >> /etc/hosts && systemctl reload-or-restart dnsmasq

# Quarantine infected hosts via VLAN
vconfig add eth0 666 && ip link set eth0.666 up
```

### **Web Shell & Backdoor Detection**
```bash
# Detect outbound HTTP shells
tcpdump -i eth0 -A | grep -Ei 'cmd=|bash|curl'

# Find web shells in web directories
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|exec" {} \;

# Monitor for reverse shell connections
netstat -antp | grep -E ':4444|:1337|:31337'
```

### **SSL/TLS Security Assessment**
```bash
# Re-check TLS configs using ssllabs-scan
ssllabs-scan --quiet www.example.com | grep -i 'grade'

# Test SSL configuration locally
testssl.sh --parallel --fast https://example.com

# Check certificate transparency logs
curl -s "https://crt.sh/?q=example.com&output=json" | jq '.[] | .name_value'
```

### **Advanced Threat Detection**
```bash
# Log login attempts from TOR exit nodes
grep 'Accepted' /var/log/auth.log | awk '{print $(NF-3)}' | \
xargs -I{} curl https://check.torproject.org/exit-addresses | grep {}

# Detect cryptocurrency mining activity
ps aux | grep -E 'xmrig|cpuminer|ccminer' && \
netstat -anp | grep -E ':4444|:3333|:8080' | grep ESTABLISHED

# Monitor for privilege escalation attempts
ausearch -k privilege_escalation -ts recent | grep -E 'sudo|su|pkexec'
```

---

## 📊 Visualization, Reporting & Behavior Tracking

### **Geographic Attack Analysis**
```bash
# Create login source heatmap
awk '{print $1}' /var/log/auth.log | sort | uniq -c > /tmp/logins.txt && \
python heatmap.py /tmp/logins.txt

# Generate GeoIP attack map
grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | \
xargs -I{} geoiplookup {} | awk -F: '{print $2}' | sort | uniq -c
```

### **Threat Intelligence Reporting**
```bash
# Weekly threat summary by category
grep 'Ban\|Fail\|Blocked' /var/log/* | awk '{print $NF}' | sort | uniq -c | sort -nr > /tmp/weekly_threats.txt

# Generate IOC summary report
grep -E 'malware|trojan|backdoor' /var/log/security.log | \
awk '{print $4, $5}' | sort | uniq -c > /tmp/ioc_summary.txt

# Create attack timeline visualization
grep 'attack' /var/log/security.log | awk '{print $1, $2, $3}' | \
gnuplot -e "set xdata time; set timefmt '%b %d %H:%M:%S'; plot '/dev/stdin' using 1:4"
```

### **Network Performance Correlation**
```bash
# Correlate bandwidth spikes with auth logs
iftop -nP -t -s 60 | tee /tmp/net_top.txt && \
grep 'Failed' /var/log/auth.log | tail -n 50

# Monitor network latency during attacks
ping -c 100 8.8.8.8 | tail -1 | awk -F/ '{print $5}' && \
grep 'attack' /var/log/security.log | wc -l

# Track connection patterns
ss -tuln | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr
```

### **System Resource Analysis**
```bash
# Visualize CPU usage vs users
ps -eo user,%cpu --sort=-%cpu | head | \
gnuplot -p -e "plot '/dev/stdin' using 2:xtic(1) with boxes"

# Memory usage correlation with security events
free -m | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }' && \
grep 'security' /var/log/syslog | tail -5

# Disk I/O monitoring during incidents
iostat -x 1 5 | grep -E 'Device|sda' && \
grep 'incident' /var/log/security.log | tail -3
```

### **Attack Pattern Analysis**
```bash
# Map attacker behavior in kill-chain format
grep -Ei 'scan|connect|auth|exploit' /var/log/auth.log /var/log/apache2/access.log | sort

# Create attack sequence timeline
awk '{print $1, $2, $3, $NF}' /var/log/auth.log | grep 'Failed' | \
sort -k1,3 | uniq | head -20

# Analyze attack progression patterns
grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | \
sort | uniq -c | awk '$1 > 10 {print "Persistent attacker:", $2, "attempts:", $1}'
```

### **User Behavior Analytics**
```bash
# Detect behavior drift of trusted users
awk '{print $1}' /var/log/auth.log | sort | uniq -c | \
awk '$1 > 20 {print "User with behavior spike:", $2}'

# Monitor unusual login times
awk '{print $3, $9}' /var/log/auth.log | grep 'Accepted' | \
awk '{hour=substr($1,1,2); if(hour<6 || hour>22) print "Off-hours login:", $2}'

# Track command execution patterns
grep 'COMMAND' /var/log/auth.log | awk '{print $6, $NF}' | sort | uniq -c | sort -nr
```

### **Automated Alerting**
```bash
# Trigger alert on unusual su use
grep 'session opened for user' /var/log/auth.log | grep -vE 'root|admin' | \
mail -s "SU Anomaly" you@example.com

# Alert on multiple failed sudo attempts
grep 'sudo' /var/log/auth.log | grep -i 'incorrect' | awk '{print $1}' | sort | uniq -c | \
awk '$1 > 5 {print "Multiple sudo failures detected for:", $2}' | \
mail -s "Sudo Brute Force Alert" security@example.com

# Monitor for privilege escalation
ausearch -k privilege_escalation -ts today | grep -c 'type=EXECVE' | \
awk '$1 > 10 {print "High privilege escalation activity detected"}' | \
wall
```

### **File System Monitoring**
```bash
# Monitor for new binaries run in /usr/local/bin
find /usr/local/bin -type f -exec stat -c '%n %y' {} + | sort -k2 | tail

# Track SUID/SGID changes
find / -perm /6000 -type f 2>/dev/null | diff /tmp/baseline_suid.txt -

# Monitor critical file modifications
auditctl -w /etc/passwd -p wa -k passwd_changes && \
auditctl -w /etc/shadow -p wa -k shadow_changes
```

### **Dashboard Creation**
```bash
# Maintain visual dashboard of trust vs alerts
awk '{print $NF}' /var/log/fail2ban.log | sort | uniq -c > /tmp/trust_vs_alerts.txt && \
gnuplot trust_vs_alerts.txt

# Generate security metrics dashboard
echo "Security Metrics for $(date)" > /tmp/security_dashboard.txt
echo "Failed logins: $(grep 'Failed password' /var/log/auth.log | wc -l)" >> /tmp/security_dashboard.txt
echo "Blocked IPs: $(fail2ban-client status sshd | grep 'Banned IP list' | wc -w)" >> /tmp/security_dashboard.txt
echo "Active connections: $(ss -t | grep ESTAB | wc -l)" >> /tmp/security_dashboard.txt
```

---

## 🚨 Containment, Quarantine & Response

### **Container Security Response**
```bash
# Kill container if network egress spikes
docker stats --no-stream | awk '$6+0 > 1000 {print $1}' | xargs -r docker kill

# Quarantine suspicious containers
docker network create quarantine && \
docker network disconnect bridge suspicious_container && \
docker network connect quarantine suspicious_container

# Container forensics snapshot
docker commit suspicious_container forensic_snapshot_$(date +%s) && \
docker save forensic_snapshot_$(date +%s) > /forensics/container_$(date +%F).tar
```

### **Virtual Machine Quarantine**
```bash
# Quarantine suspected VM using vSwitch tag
virsh attach-interface guest suspicious-vm --type network --source quarantine --model virtio --config

# Isolate VM network access
virsh domif-setlink suspicious-vm vnet0 down

# Create VM snapshot for analysis
virsh snapshot-create-as suspicious-vm forensic_snapshot_$(date +%s) \
  "Snapshot before quarantine" --disk-only
```

### **Malware Response**
```bash
# Auto-delete malicious temp files
find /tmp /dev/shm -type f -exec sha256sum {} + | \
grep -Ff known_malware_hashes.txt | awk '{print $2}' | xargs -I{} rm -f {}

# Quarantine suspicious files
mkdir -p /quarantine/$(date +%F) && \
find /home -name "*.exe" -o -name "*.scr" -exec mv {} /quarantine/$(date +%F)/ \;

# Kill malicious processes
ps aux | grep -E 'malware|trojan|backdoor' | awk '{print $2}' | xargs -r kill -9
```

### **Incident Response Coordination**
```bash
# Transfer suspect logs to sandbox
scp /var/log/suspicious.log analyst@10.0.0.99:/mnt/sandbox/logs/

# Archive incident artifacts
tar -czf incident_$(date +%s).tar.gz /var/log/auth.log /var/log/apache2/access.log /tmp/artifacts/

# Push IDS alerts into incident queue
grep 'ALERT' /var/log/suricata/fast.log | tail -n 10 | \
curl -X POST -d @- http://incident.queue.local/api/new
```

### **Network Isolation & Blocking**
```bash
# Kill processes binding to unassigned ports
ss -tulnp | awk '$5 !~ /22|80|443/ {print $7}' | cut -d, -f2 | xargs -r kill -9

# Block suspicious network ranges
iptables -A INPUT -s 198.51.100.0/24 -j DROP && \
iptables -A OUTPUT -d 198.51.100.0/24 -j DROP

# Implement emergency network lockdown
iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -P OUTPUT DROP && \
iptables -A INPUT -i lo -j ACCEPT && iptables -A OUTPUT -o lo -j ACCEPT
```

### **Email Security Response**
```bash
# Lock outbound mail if spam detected
grep -i 'spam' /var/log/mail.log | awk '{print $6}' | sort | uniq -c | \
awk '$1 > 100 {print $2}' | xargs -I{} postconf -e "inet_interfaces = loopback-only"

# Block compromised email accounts
grep 'authentication failed' /var/log/mail.log | awk '{print $8}' | \
sort | uniq -c | awk '$1 > 50 {print $2}' | \
xargs -I{} postconf -e "smtpd_sender_restrictions = check_sender_access hash:/etc/postfix/blocked_senders"

# Quarantine suspicious emails
find /var/mail -name "*" -exec grep -l "suspicious_pattern" {} \; | \
xargs -I{} mv {} /var/quarantine/
```

### **File System Protection**
```bash
# Monitor /etc/hosts tampering
auditctl -w /etc/hosts -p wa -k hosts-watch

# Protect critical system files
chattr +i /etc/passwd /etc/shadow /etc/group && \
auditctl -w /etc/passwd -p wa -k critical_files

# Emergency file system protection
mount -o remount,ro /boot && mount -o remount,ro /usr
```

### **Backup & Recovery**
```bash
# Snapshot containers daily
docker ps -q | xargs -I{} docker commit {} snapshot_{}_$(date +%F) && \
docker save snapshot_{}_$(date +%F) > /backups/$(date +%F)-{}.tar

# Create system state backup
tar -czf system_backup_$(date +%s).tar.gz /etc /var/log /home && \
rsync -av system_backup_$(date +%s).tar.gz backup@remote.server:/backups/

# Database emergency backup
mysqldump --all-databases --single-transaction > emergency_db_backup_$(date +%F).sql
```

### **Dynamic Threat Response**
```bash
# Block beaconing to C2 IPs dynamically
grep 'C2 connection' /var/log/suricata/fast.log | awk '{print $9}' | \
xargs -I{} iptables -A OUTPUT -d {} -j REJECT

# Auto-update threat intelligence feeds
curl -s https://threat-intel.example.com/ips.txt | \
while read ip; do iptables -A INPUT -s $ip -j DROP; done

# Implement rate limiting for suspicious IPs
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name ssh_attack && \
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 \
  --hitcount 4 --name ssh_attack -j DROP
```

---

## 🎯 **Integration with NoSleep-Ops Lab**

### **Lab-Specific Commands**
```bash
# Run advanced monitoring in NoSleep-Ops
docker exec ubuntu-host /opt/lab-scripts/alerting-system.sh start

# Generate test scenarios for playbook validation
docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh all-advanced

# Monitor lab environment
docker exec ubuntu-host tail -f /var/log/security-alerts.log
```

### **Training Scenarios**
```bash
# Simulate incident response scenario
docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh apt-campaign && \
sleep 30 && \
docker exec ubuntu-host /opt/lab-scripts/alerting-system.sh stats

# Practice containment procedures
docker exec ubuntu-host iptables -A INPUT -s 192.0.2.0/24 -j DROP && \
docker exec ubuntu-host /opt/lab-scripts/network-traffic-generator.sh continuous
```

---

## ⚠️ **Important Security Notes**

- **Test all commands in a lab environment first**
- **Ensure proper backups before implementing blocking rules**
- **Document all incident response actions**
- **Coordinate with team members before network changes**
- **Maintain chain of custody for forensic evidence**

---

---

**🔒 This playbook is designed for authorized security professionals and should only be used in controlled environments or during actual security incidents.** 
