## System Administrator (20 Commands)

### Log Analysis & Security
```bash
# 1. Find failed SSH login attempts in the last hour
grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d %H')" | awk '{print $11}' | sort | uniq -c | sort -nr

# 2. Block IP with most failed login attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head -1 | awk '{print $2}' | xargs -I {} iptables -A INPUT -s {} -j DROP

# 3. Monitor real-time failed login attempts
tail -f /var/log/auth.log | grep --line-buffered "Failed password" | awk '{print strftime("%Y-%m-%d %H:%M:%S"), $0}'

# 4. Find large files consuming disk space (top 10)
find / -type f -size +100M 2>/dev/null | xargs ls -lh | sort -k5 -hr | head -10

# 5. Check for zombie processes and kill parent
ps aux | awk '$8 ~ /^Z/ { print $2 }' | xargs -r kill -9
```

### System Monitoring
```bash
# 6. Monitor memory usage by process (top 10)
ps aux --sort=-%mem | head -11 | awk 'NR>1 {printf "%-10s %-8s %-8s %s\n", $1, $4"%", $6/1024"MB", $11}'

# 7. Check disk usage and alert if >80%
df -h | awk 'NR>1 && $5+0 > 80 {print "WARNING: " $6 " is " $5 " full"}' | mail -s "Disk Space Alert" admin@company.com

# 8. Find files modified in last 24 hours
find /var/log -type f -mtime -1 -exec ls -lh {} \; | sort -k6,7

# 9. Monitor CPU usage per core
grep 'cpu[0-9]' /proc/stat | awk '{usage=($2+$4)*100/($2+$3+$4+$5)} END {print "CPU Usage: " usage "%"}'

# 10. Check system load and running processes
uptime | awk '{print "Load Average: " $(NF-2) " " $(NF-1) " " $NF}' && ps aux | wc -l | awk '{print "Running Processes: " $1}'
```

### Service Management
```bash
# 11. Restart failed systemd services
systemctl list-units --failed --no-legend | awk '{print $1}' | xargs -r systemctl restart

# 12. Check service status and restart if down
systemctl is-active nginx >/dev/null || (systemctl restart nginx && echo "nginx restarted at $(date)")

# 13. Find services consuming most memory
systemctl status --no-pager -l | grep -A2 "Memory:" | awk '/Memory:/ {print prev_line ": " $2} {prev_line=$0}'

# 14. Monitor service restart frequency
journalctl -u nginx --since "24 hours ago" | grep -c "Started\|Stopped" | awk '{print "nginx restarts in 24h: " $1}'

# 15. Check all listening ports and services
netstat -tulpn | awk 'NR>2 && $6=="LISTEN" {print $1 " " $4 " " $7}' | sort
```

### File System Operations
```bash
# 16. Find and remove old log files (>30 days)
find /var/log -name "*.log" -type f -mtime +30 -exec rm -f {} \; -print

# 17. Calculate directory sizes and sort
du -sh /var/* 2>/dev/null | sort -hr | head -10

# 18. Find duplicate files by size and checksum
find /home -type f -size +10M -exec md5sum {} \; | sort | uniq -d -w32

# 19. Monitor file changes in real-time
inotifywait -m -r -e modify,create,delete /etc --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S'

# 20. Backup configuration files with timestamp
tar -czf /backup/config-$(date +%Y%m%d-%H%M%S).tar.gz /etc/{nginx,apache2,mysql,ssh}/ 2>/dev/null
```

## DevOps Engineer (20 Commands)

### Docker Operations
```bash
# 21. Clean up unused Docker resources
docker system prune -af --volumes && docker image prune -af

# 22. Monitor Docker container resource usage
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# 23. Find containers with high memory usage
docker stats --no-stream | awk 'NR>1 {gsub(/[a-zA-Z%]/, "", $4); if($4+0 > 80) print $1 " using " $4 "% memory"}'

# 24. Restart unhealthy containers
docker ps --filter health=unhealthy --format "{{.Names}}" | xargs -r docker restart

# 25. Export container logs to file
docker ps --format "{{.Names}}" | xargs -I {} sh -c 'docker logs {} > /tmp/{}.log 2>&1'
```

### CI/CD & Automation
```bash
# 26. Check Git repositories for uncommitted changes
find /opt/projects -name ".git" -type d | while read repo; do cd "$(dirname "$repo")"; [[ -n $(git status --porcelain) ]] && echo "Uncommitted changes in: $(pwd)"; done

# 27. Deploy application with health check
kubectl set image deployment/app container=image:latest && kubectl rollout status deployment/app --timeout=300s

# 28. Backup database before deployment
mysqldump -u root -p$DB_PASS --single-transaction --all-databases | gzip > /backup/pre-deploy-$(date +%Y%m%d-%H%M%S).sql.gz

# 29. Monitor deployment success rate
kubectl get pods -l app=myapp -o jsonpath='{.items[*].status.containerStatuses[*].ready}' | tr ' ' '\n' | awk '{total++; if($1=="true") success++} END {print "Success Rate: " (success/total)*100 "%"}'

# 30. Rollback on failed health checks
curl -f http://localhost:8080/health || (kubectl rollout undo deployment/app && echo "Rollback completed")
```

### Infrastructure as Code
```bash
# 31. Validate Terraform syntax across modules
find . -name "*.tf" -exec dirname {} \; | sort -u | xargs -I {} terraform validate {}

# 32. Check Ansible playbook syntax
find /ansible -name "*.yml" -o -name "*.yaml" | xargs ansible-playbook --syntax-check

# 33. Generate infrastructure documentation
terraform show -json | jq -r '.values.root_module.resources[] | "\(.type).\(.name): \(.values.tags.Name // "unnamed")"'

# 34. Monitor infrastructure drift
terraform plan -detailed-exitcode > /dev/null; echo "Exit code: $? (0=no changes, 1=error, 2=changes detected)"

# 35. Extract secrets from configuration files
grep -r "password\|secret\|key" --include="*.yml" --include="*.yaml" /ansible | grep -v "vault"
```

### Monitoring & Alerting
```bash
# 36. Check SSL certificate expiry
echo | openssl s_client -servername $HOSTNAME -connect $HOSTNAME:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter

# 37. Monitor API endpoint response times
curl -w "%{time_total}s %{http_code}\n" -o /dev/null -s https://api.example.com/health

# 38. Check service dependencies
lsof -i :80 -i :443 -i :3306 | awk 'NR>1 {print $1 " is using port " $9}' | sort -u

# 39. Generate system health report
echo "=== System Health Report $(date) ===" && free -h && echo && df -h && echo && uptime

# 40. Alert on high error rates in logs
tail -n 1000 /var/log/app.log | grep -c "ERROR" | awk '{if($1 > 10) print "High error rate detected: " $1 " errors in last 1000 lines"}'
```

## Site Reliability Engineer (20 Commands)

### Performance Monitoring
```bash
# 41. Calculate 95th percentile response time from logs
awk '{print $10}' /var/log/nginx/access.log | sort -n | awk '{arr[NR]=$1} END {print "95th percentile: " arr[int(NR*0.95)]}'

# 42. Monitor database connection pool
mysqladmin -u root -p$DB_PASS processlist | awk 'NR>3 {state[$6]++} END {for(s in state) print s ": " state[s]}'

# 43. Track memory leak detection
ps -p $(pgrep myapp) -o pid,vsz,rss,comm --no-headers | awk '{if($2 > 1000000) print "Memory leak detected: " $4 " using " $2/1024 "MB"}'

# 44. Monitor queue depth
rabbitmqctl list_queues name messages | awk '$2 > 1000 {print "Queue " $1 " has " $2 " messages"}'

# 45. Calculate cache hit ratio
redis-cli info stats | awk -F: '/keyspace_hits/{hits=$2} /keyspace_misses/{misses=$2} END {print "Cache hit ratio: " (hits/(hits+misses))*100 "%"}'
```

### Incident Response
```bash
# 46. Capture network traffic during incident
tcpdump -i any -w /tmp/incident-$(date +%Y%m%d-%H%M%S).pcap -c 1000 host problematic-server.com

# 47. Generate thread dump for Java applications
jstack $(pgrep -f java) > /tmp/threaddump-$(date +%Y%m%d-%H%M%S).txt

# 48. Collect system state during outage
(ps aux; free -m; df -h; netstat -tulpn; dmesg | tail -50) > /tmp/system-state-$(date +%Y%m%d-%H%M%S).txt

# 49. Find root cause in logs with context
grep -B5 -A5 "OutOfMemoryError" /var/log/app/*.log | tail -20

# 50. Emergency service restart with notification
systemctl restart critical-service && echo "Critical service restarted at $(date)" | mail -s "Emergency Restart" oncall@company.com
```

### Capacity Planning
```bash
# 51. Predict disk space usage
df / | awk 'NR==2 {used=$3; avail=$4; total=used+avail; daily_growth=used*0.01; days_left=avail/daily_growth; print "Disk will be full in approximately " int(days_left) " days"}'

# 52. Monitor connection limits
ss -s | awk '/TCP/ {print "TCP connections: " $2}' && cat /proc/sys/net/core/somaxconn

# 53. Check file descriptor usage
lsof | wc -l | awk '{print "Open file descriptors: " $1}' && cat /proc/sys/fs/file-max

# 54. Monitor network bandwidth usage
cat /proc/net/dev | awk 'NR>2 {rx+=$2; tx+=$10} END {print "RX: " rx/1024/1024 "MB, TX: " tx/1024/1024 "MB"}'

# 55. Calculate resource utilization trends
sar -u 1 60 | awk 'NR>3 && /^[0-9]/ {cpu+=$3} END {print "Average CPU usage: " cpu/(NR-3) "%"}'
```

### Reliability Engineering
```bash
# 56. Test circuit breaker functionality
for i in {1..10}; do curl -f http://api.example.com/test || echo "Request $i failed"; sleep 1; done

# 57. Validate backup integrity
mysqldump -u root -p$DB_PASS --single-transaction testdb | mysql -u root -p$DB_PASS testdb_restore && echo "Backup validated"

# 58. Check service mesh health
kubectl get pods -l app=istio-proxy -o jsonpath='{.items[*].status.phase}' | tr ' ' '\n' | sort | uniq -c

# 59. Monitor SLA compliance
curl -s http://metrics.example.com/uptime | jq '.uptime_percentage' | awk '{if($1 < 99.9) print "SLA breach: " $1 "% uptime"}'

# 60. Chaos testing network partition
iptables -A INPUT -s $TARGET_IP -j DROP && sleep 30 && iptables -D INPUT -s $TARGET_IP -j DROP
```

## Network Engineer (15 Commands)

### Network Monitoring
```bash
# 61. Monitor network interface statistics
cat /proc/net/dev | awk 'NR>2 {printf "%-10s RX: %10.2f MB TX: %10.2f MB\n", $1, $2/1024/1024, $10/1024/1024}'

# 62. Check for network connectivity issues
ping -c 4 8.8.8.8 | tail -1 | awk -F'/' '{print "Avg latency: " $5 "ms"}'

# 63. Monitor DNS resolution times
dig @8.8.8.8 google.com | awk '/Query time/ {print "DNS resolution: " $4 " " $5}'

# 64. Check routing table changes
ip route show | md5sum > /tmp/route.new && diff /tmp/route.old /tmp/route.new >/dev/null || echo "Routing table changed"

# 65. Monitor bandwidth usage by interface
iftop -t -s 10 -i eth0 2>/dev/null | tail -1 | awk '{print "Bandwidth: " $2}'
```

### Security & Firewall
```bash
# 66. Block suspicious IP ranges
wget -qO- https://www.spamhaus.org/drop/drop.txt | grep -E '^[0-9]' | awk '{print "iptables -A INPUT -s " $1 " -j DROP"}' | bash

# 67. Monitor failed connection attempts
netstat -an | grep :80 | awk '$6 == "SYN_RECV" {count++} END {print "Half-open connections: " count+0}'

# 68. Check for port scans
journalctl -u sshd --since "1 hour ago" | awk '/Invalid user/ {ip=$8; count[ip]++} END {for(i in count) if(count[i] > 5) print "Port scan from: " i}'

# 69. Monitor firewall rule hits
iptables -L -v -n | awk '/^[0-9]/ && $1 > 1000 {print "High traffic rule: " $0}'

# 70. Check SSL/TLS configuration
nmap --script ssl-enum-ciphers -p 443 $TARGET_HOST | grep -E "(TLS|SSL)" | sort -u
```

### Network Troubleshooting
```bash
# 71. Trace network path and latency
traceroute -I $TARGET_HOST 2>/dev/null | awk '{print NR ": " $2 " (" $3 ") " $4}'

# 72. Check for duplicate IP addresses
nmap -sn 192.168.1.0/24 | awk '/Nmap scan report/ {print $5}' | sort | uniq -d

# 73. Monitor TCP connection states
ss -tan state established | wc -l | awk '{print "Established connections: " $1}'

# 74. Check network interface errors
cat /proc/net/dev | awk 'NR>2 && ($3+$11 > 0) {print $1 " has " ($3+$11) " errors"}'

# 75. Monitor packet loss
ping -c 100 $TARGET_HOST | tail -2 | head -1 | awk '{print "Packet loss: " $6}'
```

## Database Administrator (15 Commands)

### MySQL/MariaDB Operations
```bash
# 76. Find slow queries in MySQL
mysqldumpslow -s t -t 10 /var/log/mysql/slow.log | head -20

# 77. Check MySQL replication lag
mysql -e "SHOW SLAVE STATUS\G" | awk '/Seconds_Behind_Master/ {print "Replication lag: " $2 " seconds"}'

# 78. Monitor database connections
mysql -e "SHOW PROCESSLIST" | awk 'NR>1 {state[$6]++} END {for(s in state) print s ": " state[s]}'

# 79. Check table sizes and optimization needs
mysql -e "SELECT table_name, ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)' FROM information_schema.TABLES WHERE table_schema = 'mydb' ORDER BY (data_length + index_length) DESC LIMIT 10;"

# 80. Backup database with compression
mysqldump -u root -p$DB_PASS --single-transaction --routines --triggers mydb | gzip > /backup/mydb-$(date +%Y%m%d).sql.gz
```

### PostgreSQL Operations
```bash
# 81. Check PostgreSQL connection limits
psql -c "SELECT count(*) as active_connections, setting as max_connections FROM pg_stat_activity, pg_settings WHERE name='max_connections';"

# 82. Find long-running queries
psql -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query FROM pg_stat_activity WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';"

# 83. Monitor table bloat
psql -c "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size FROM pg_tables ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 10;"

# 84. Check index usage
psql -c "SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch FROM pg_stat_user_indexes WHERE idx_tup_read = 0;"

# 85. Vacuum analyze all tables
psql -c "SELECT 'VACUUM ANALYZE ' || schemaname || '.' || tablename || ';' FROM pg_tables WHERE schemaname = 'public';" | psql
```

### Database Performance
```bash
# 86. Monitor Redis memory usage
redis-cli info memory | awk -F: '/used_memory_human/ {print "Redis memory usage: " $2}'

# 87. Check MongoDB replica set status
mongo --eval "rs.status()" | grep -E "(name|stateStr|health)"

# 88. Find blocking queries in PostgreSQL
psql -c "SELECT blocked_locks.pid AS blocked_pid, blocked_activity.usename AS blocked_user, blocking_locks.pid AS blocking_pid, blocking_activity.usename AS blocking_user FROM pg_catalog.pg_locks blocked_locks JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype AND blocking_locks.pid != blocked_locks.pid JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid WHERE NOT blocked_locks.granted;"

# 89. Check disk space used by databases
du -sh /var/lib/mysql/* | sort -hr | head -10

# 90. Monitor database query cache hit ratio
mysql -e "SHOW STATUS LIKE 'Qcache%'" | awk '/Qcache_hits/ {hits=$2} /Qcache_inserts/ {inserts=$2} END {print "Query cache hit ratio: " (hits/(hits+inserts))*100 "%"}'
```

## Systems Engineer (10 Commands)

### System Integration
```bash
# 91. Check service dependencies and start order
systemctl list-dependencies --reverse nginx | grep -v "●" | awk '{print $2}'

# 92. Monitor inter-service communication
lsof -i TCP:3306 | awk 'NR>1 {print $1 " -> " $2 " (" $8 ")"}'

# 93. Check system call frequency for process
strace -c -p $(pgrep nginx) 2>&1 | tail -10

# 94. Monitor shared library dependencies
ldd /usr/bin/nginx | awk '{print $1 " -> " $3}' | grep -v "=>"

# 95. Check kernel module usage
lsmod | awk 'NR>1 && $3 > 0 {print $1 " used by " $3 " processes"}'
```

### Advanced System Operations
```bash
# 96. Generate system configuration backup
(crontab -l; systemctl list-enabled; iptables-save; cat /etc/fstab) > /backup/system-config-$(date +%Y%m%d).txt

# 97. Monitor system entropy for cryptographic operations
cat /proc/sys/kernel/random/entropy_avail | awk '{if($1 < 1000) print "Low entropy warning: " $1 " bits available"}'

# 98. Check for memory leaks in kernel modules
grep -E "(slab|kmalloc)" /proc/slabinfo | awk '$3 != $4 {print $1 ": " $3-$4 " objects leaked"}'

# 99. Monitor hardware temperature sensors
sensors 2>/dev/null | awk '/°C/ {gsub(/[+°C]/, "", $2); if($2 > 70) print "High temperature: " $1 " " $2 "°C"}'

# 100. Comprehensive system health check
echo "=== SYSTEM HEALTH CHECK $(date) ===" && (uptime; free -h; df -h; systemctl --failed; dmesg | tail -5) 2>/dev/null
```

---

## Usage Notes

**Safety Reminders:**
- Always test commands in development environments first
- Use appropriate permissions and sudo when necessary
- Replace placeholder values (passwords, hostnames, etc.) with actual values
- Some commands require additional packages (e.g., `jq`, `iftop`, `sensors`)
- Monitor resource usage when running intensive commands in production

**Customization:**
- Adjust thresholds (CPU %, memory limits, etc.) based on your environment
- Modify file paths to match your system configuration
- Update service names and ports to match your infrastructure
- Configure email addresses for alerting commands

**Dependencies:**
Common tools that may need installation:
- `jq` - JSON processor
- `iftop` - Bandwidth monitor
- `iotop` - I/O monitor
- `htop` - Process viewer
- `tcpdump` - Network analyzer
- `nmap` - Network scanner
- `redis-cli` - Redis client
- `kubectl` - Kubernetes client
