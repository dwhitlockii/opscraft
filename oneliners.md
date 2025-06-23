# One-Liners for DevOps & SysAdmin

## 🐧 Linux/Bash One-Liners

### System Administrator

#### **System Monitoring & Health**
```bash
# Real-time system resource monitoring with alerts
top -b -n1 | awk '/^%Cpu/ {print "CPU: " $2} /^KiB Mem/ {print "Memory: " $3 "/" $2}' && df -h | awk '$5+0 > 80 {print "WARNING: " $1 " is " $5 " full"}'

# Find processes consuming most memory with PID for quick kill
ps aux --sort=-%mem | head -10 | awk '{printf "%-8s %-8s %-8s %s\n", $2, $3, $4, $11}'

# Monitor failed SSH attempts in real-time
tail -f /var/log/auth.log | grep --line-buffered "Failed password" | awk '{print strftime("%Y-%m-%d %H:%M:%S"), "Failed login attempt from", $11, "for user", $9}'

# Check system uptime, load average, and logged users in one line
uptime && who | wc -l | xargs echo "Active users:" && last -n 5 | head -5

# Find large files consuming disk space (over 100MB)
find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null | awk '{print $5 "\t" $9}' | sort -hr | head -20
```

#### **Log Analysis & Troubleshooting**
```bash
# Parse Apache access logs for top IPs and status codes
cat /var/log/apache2/access.log | awk '{print $1, $9}' | sort | uniq -c | sort -rn | head -20

# Find errors in system logs from last 24 hours with context
journalctl --since "24 hours ago" --priority=err --no-pager | grep -A 2 -B 2 "error\|failed\|critical"

# Monitor log file growth rate in MB per hour
ls -la /var/log/*.log | awk '{size+=$5} END {print "Current size:", size/1024/1024 "MB"}' && sleep 3600 && ls -la /var/log/*.log | awk '{size+=$5} END {print "New size:", size/1024/1024 "MB"}'

# Extract unique error patterns from application logs
grep -i "error\|exception\|fail" /var/log/application.log | sed 's/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}.*\]//' | sort | uniq -c | sort -rn

# Real-time monitoring of multiple log files with timestamps
multitail -i /var/log/syslog -i /var/log/auth.log -i /var/log/apache2/error.log --label 1 --label 2 --label 3
```

#### **User & Permission Management**
```bash
# Audit user accounts with last login and password expiry
awk -F: '$3>=1000 {print $1}' /etc/passwd | while read user; do echo -n "$user: "; last -1 $user | head -1 | awk '{print $4,$5,$6,$7}'; chage -l $user | grep "Password expires"; done

# Find SUID/SGID files for security audit
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null | awk '{print $1, $3, $4, $9}'

# Check for users with empty passwords (security risk)
awk -F: '($2 == "" || $2 == "*" || $2 == "!") {print "User " $1 " has no password set"}' /etc/shadow

# Find files owned by deleted users (orphaned files)
find / -nouser -exec ls -la {} \; 2>/dev/null | head -20

# Generate user activity report with command history
for user in $(awk -F: '$3>=1000 {print $1}' /etc/passwd); do echo "=== $user ==="; tail -5 /home/$user/.bash_history 2>/dev/null || echo "No history available"; done
```

### DevOps Engineer

#### **Docker & Containerization**
```bash
# Clean up unused Docker resources and show space reclaimed
docker system df && docker system prune -af --volumes && echo "=== After cleanup ===" && docker system df

# Monitor container resource usage in real-time
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Find and stop containers using most resources
docker stats --no-stream --format '{{.Container}} {{.CPUPerc}}' | sort -k2 -nr | head -5 | awk '{print $1}' | xargs -I {} docker stop {}

# Build and tag Docker image with git commit hash
docker build -t myapp:$(git rev-parse --short HEAD) . && docker tag myapp:$(git rev-parse --short HEAD) myapp:latest

# Export Docker container with timestamp for backup
docker export $(docker ps -q --filter "name=myapp") | gzip > myapp-backup-$(date +%Y%m%d-%H%M%S).tar.gz

# Batch update all running containers to latest images
docker ps --format '{{.Image}}' | sort -u | xargs -I {} sh -c 'docker pull {} && docker ps --format "{{.Names}}" --filter "ancestor={}" | xargs -I [] docker restart []'
```

#### **Kubernetes Operations**
```bash
# Get pods consuming most CPU/Memory across all namespaces
kubectl top pods --all-namespaces --sort-by=cpu | head -10 && echo "=== MEMORY ===" && kubectl top pods --all-namespaces --sort-by=memory | head -10

# Check cluster health with node status and resource usage
kubectl get nodes -o wide && kubectl top nodes && kubectl get pods --all-namespaces | grep -v Running | head -10

# Find failed pods and their logs in one command
kubectl get pods --all-namespaces --field-selector=status.phase=Failed -o name | xargs -I {} kubectl logs {} --tail=50

# Scale deployments based on current resource usage
kubectl top pods -l app=myapp --no-headers | awk '$3+0 > 80 {print $1}' | wc -l | xargs -I {} kubectl scale deployment myapp --replicas={}

# Backup all configmaps and secrets to files
kubectl get configmaps --all-namespaces -o yaml > configmaps-backup-$(date +%Y%m%d).yaml && kubectl get secrets --all-namespaces -o yaml > secrets-backup-$(date +%Y%m%d).yaml
```

#### **CI/CD Pipeline Management**
```powershell
# Jenkins: Trigger build with parameters and monitor status
Invoke-RestMethod -Uri "http://jenkins:8080/job/myproject/buildWithParameters?token=mytoken&branch=main" -Method Post; Start-Sleep 10; (Invoke-RestMethod -Uri "http://jenkins:8080/job/myproject/lastBuild/api/json").result

# Git: Create release branch with version bump and changelog
$version = Get-Date -Format "yyyy.MM.dd"; git checkout -b "release/v$version"; $version | Out-File VERSION; git log --oneline --since="7 days ago" | Out-File CHANGELOG.md; git add .; git commit -m "Release v$version"

# Deploy application with health check and rollback capability
$commit = git rev-parse --short HEAD; kubectl set image deployment/myapp container="myapp:$commit"; if(!(kubectl rollout status deployment/myapp --timeout=300s)) {kubectl rollout undo deployment/myapp}

# Check deployment status across multiple environments
@('dev','staging','prod') | ForEach-Object {Write-Host "=== $_ ==="; kubectl --context=$_ get deployments -o wide | Where-Object {$_ -match "myapp"}}

# Automated testing and quality gate check
npm test; if($LASTEXITCODE -eq 0) {npm run lint; if($LASTEXITCODE -eq 0) {docker build -t test-image .; docker run --rm test-image npm run integration-tests; if($LASTEXITCODE -eq 0) {Write-Host "✅ All tests passed"}}}
```

### Site Reliability Engineer

#### **Service Monitoring & Alerting**
```powershell
# Check service health across multiple endpoints with response times
@('https://api.example.com/health','https://web.example.com/ping') | ForEach-Object {$start = Get-Date; try {$response = Invoke-WebRequest $_ -UseBasicParsing; $time = (Get-Date) - $start; "$($response.StatusCode) $($time.TotalSeconds)s $_"} catch {"Error: $_"}}

# Monitor SSL certificate expiration across multiple domains
@('api.example.com','web.example.com') | ForEach-Object {$cert = [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $req = [Net.WebRequest]::Create("https://$_"); $req.GetResponse().Close(); $cert = $req.ServicePoint.Certificate; "Certificate for $_`: Expires $($cert.GetExpirationDateString())"}

# Database connection health check with query performance
Measure-Command {Invoke-Sqlcmd -ServerInstance "db-server" -Query "SELECT COUNT(*) FROM sys.tables"} | Select-Object TotalSeconds; Test-NetConnection redis-server -Port 6379

# Memory leak detection by monitoring process growth
$proc1 = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10; Start-Sleep 300; $proc2 = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10; Compare-Object $proc1 $proc2 -Property Name,WorkingSet

# Check disk I/O performance and identify bottlenecks
Get-Counter "\PhysicalDisk(*)\% Disk Time","\PhysicalDisk(*)\Disk Transfers/sec" -SampleInterval 1 -MaxSamples 5 | ForEach-Object {$_.CounterSamples | Where-Object {$_.CookedValue -gt 80} | Select-Object Path,CookedValue}
```

#### **Performance Monitoring**
```powershell
# Application performance metrics with system counters
$url = "http://localhost:8080/metrics"; $response = Invoke-RestMethod $url; $response | ConvertFrom-Json | Select-Object response_time; Get-Counter "\Network Interface(*)\Bytes Total/sec" -MaxSamples 1

# Memory usage breakdown by process with page file usage
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Name,@{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet/1MB,2)}},@{Name="PagedMem(MB)";Expression={[math]::Round($_.PagedMemorySize64/1MB,2)}}; Get-Counter "\Paging File(_Total)\% Usage"

# Network throughput and connection monitoring
(Get-NetTCPConnection | Measure-Object).Count; Get-Counter "\Network Interface(*)\Bytes Total/sec" -MaxSamples 3 | ForEach-Object {$_.CounterSamples | Sort-Object CookedValue -Descending | Select-Object -First 3}

# Load average analysis with CPU utilization trend
Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 10 | ForEach-Object {$sum = 0; $_.CounterSamples | ForEach-Object {$sum += $_.CookedValue}; "Average CPU: $([math]::Round($sum/$_.CounterSamples.Count,2))%"}

# Real-time application error monitoring from Event Log
Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE Logfile='Application' AND Type='Error'" -SourceIdentifier "AppErrors" -Action {Write-Host "$(Get-Date): Application Error - $($Event.SourceEventArgs.NewEvent.Message.Substring(0,100))"}
```

#### **Incident Response**
```powershell
# Emergency system snapshot for post-incident analysis
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"; $folder = "incident-$timestamp"; New-Item -ItemType Directory $folder; Set-Location $folder; Get-Process > processes.txt; Get-NetTCPConnection > network.txt; Get-WmiObject Win32_LogicalDisk > disk.txt; Get-Counter "\Memory\Available MBytes" > memory.txt; Get-WinEvent -LogName System -MaxEvents 100 > system-events.txt

# Quick service restart with logging and notification
Stop-Service W3SVC; Start-Sleep 2; Start-Service W3SVC; $message = "IIS restarted at $(Get-Date)"; Send-MailMessage -To "admin@company.com" -Subject "Service Restart Alert" -Body $message -SmtpServer "mail.company.com"

# Find and terminate problematic processes consuming resources
Get-Process | Where-Object {$_.CPU -gt 80} | ForEach-Object {Write-Host "Terminating high CPU process: $($_.Name) (PID: $($_.Id))"; Stop-Process -Id $_.Id -Force}

# Network connectivity troubleshooting matrix
@('google.com','8.8.8.8','internal-server.com') | ForEach-Object {$result = Test-NetConnection $_ -InformationLevel Quiet; "$_`: $(if($result){'✅'}else{'❌'})"}

# Log correlation for incident timeline from multiple sources
$time = (Get-Date).AddHours(-1); Get-WinEvent -FilterHashtable @{LogName='System','Application','Security'; StartTime=$time} | Sort-Object TimeCreated | Select-Object TimeCreated,LogName,Id,Message | Format-Table -Wrap
```

### Network Engineer

#### **Network Diagnostics**
```powershell
# Comprehensive network connectivity test with traceroute
@('8.8.8.8','1.1.1.1','google.com') | ForEach-Object {Write-Host "=== Testing $_ ==="; Test-NetConnection $_ -TraceRoute | Select-Object ComputerName,RemoteAddress,PingSucceeded,@{Name="Hops";Expression={$_.TraceRoute.Count}}}

# Port scan and service detection on critical servers
1..254 | ForEach-Object {$ip = "192.168.1.$_"; Test-NetConnection $ip -Port 80,443,22,3389 -InformationLevel Quiet -WarningAction SilentlyContinue | Where-Object {$_.TcpTestSucceeded} | Select-Object ComputerName,RemotePort}

# Network adapter statistics and performance monitoring
Get-NetAdapterStatistics | Select-Object Name,BytesReceived,BytesSent,PacketsReceived,PacketsSent | Format-Table -AutoSize; Get-Counter "\Network Interface(*)\Bytes Total/sec" -MaxSamples 1

# DNS resolution performance testing
@('8.8.8.8','1.1.1.1','208.67.222.222') | ForEach-Object {$dns = $_; $time = Measure-Command {Resolve-DnsName google.com -Server $dns -ErrorAction SilentlyContinue}; "$dns`: $($time.TotalMilliseconds)ms"}

# Network interface configuration and error detection
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name,InterfaceDescription,LinkSpeed,FullDuplex; Get-NetAdapterStatistics | Where-Object {$_.InErrors -gt 0 -or $_.OutErrors -gt 0} | Select-Object Name,InErrors,OutErrors
```

#### **Firewall & Security**
```powershell
# Active connection monitoring with suspicious activity detection
Get-NetTCPConnection | Group-Object RemoteAddress | Where-Object {$_.Count -gt 10} | Select-Object Name,Count | Sort-Object Count -Descending | Select-Object -First 10

# Windows Firewall rules analysis and management
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Group-Object Direction | Select-Object Name,Count; Get-NetFirewallRule | Where-Object {$_.Action -eq "Block"} | Select-Object DisplayName,Direction,Protocol | Format-Table

# Real-time security event monitoring from Windows logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625,4648,4771} -MaxEvents 20 | Select-Object TimeCreated,Id,@{Name="Account";Expression={$_.Properties[5].Value}},@{Name="SourceIP";Expression={$_.Properties[19].Value}} | Format-Table

# Network security scan with service enumeration
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress,LocalPort,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object LocalPort

# Certificate validation and SSL/TLS security check
[Net.ServicePointManager]::ServerCertificateValidationCallback = {param($sender,$cert,$chain,$errors) Write-Host "Certificate for $($sender.Address): Valid until $($cert.GetExpirationDateString()), Errors: $errors"; $true}; Invoke-WebRequest https://target-server.com -UseBasicParsing
```

#### **Network Configuration**
```powershell
# Network configuration backup and validation
Get-NetIPConfiguration | Export-Clixml "network-config-$(Get-Date -Format 'yyyyMMdd').xml"; Get-NetRoute | Export-Clixml "routes-$(Get-Date -Format 'yyyyMMdd').xml"

# Network adapter and VLAN configuration analysis
Get-NetAdapter | Select-Object Name,InterfaceDescription,VlanID,MacAddress | Format-Table; Get-NetLbfoTeam | Select-Object Name,TeamMembers,LoadBalancingAlgorithm

# Network performance and optimization settings
Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -match "Offload|RSS|Chimney"} | Select-Object Name,DisplayName,RegistryValue | Format-Table -AutoSize

# Wireless network monitoring and signal strength
netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {$profile = ($_ -split ":")[1].Trim(); netsh wlan show profile name="$profile" key=clear}

# Network namespace equivalent - Network compartments
Get-NetCompartment | Select-Object CompartmentId,CompartmentDescription; Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address | Format-Table
```

### Database Administrator

#### **SQL Server Operations**
```powershell
# SQL Server performance monitoring with blocking detection
Invoke-Sqlcmd -Query "SELECT r.session_id, r.start_time, r.status, r.command, s.login_name, r.wait_type, r.wait_time, r.blocking_session_id FROM sys.dm_exec_requests r JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id WHERE r.blocking_session_id <> 0 OR r.wait_time > 5000"

# Database size analysis and growth tracking
Invoke-Sqlcmd -Query "SELECT DB_NAME(database_id) AS Database_Name, CAST(SUM(size * 8.0 / 1024) AS DECIMAL(10,2)) AS Size_MB FROM sys.master_files GROUP BY database_id ORDER BY Size_MB DESC" | Format-Table

# Backup all databases with verification
Get-SqlDatabase | ForEach-Object {$backupFile = "C:\Backups\$($_.Name)_$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"; Backup-SqlDatabase -Database $_.Name -BackupFile $backupFile; Test-SqlDatabaseBackup -BackupFile $backupFile}

# Find missing indexes and performance optimization opportunities
Invoke-Sqlcmd -Query "SELECT TOP 10 ROUND(s.avg_total_user_cost * s.avg_user_impact * (s.user_seeks + s.user_scans),0) AS [Total Cost], d.[statement] AS [Table Name], equality_columns, inequality_columns, included_columns FROM sys.dm_db_missing_index_groups g INNER JOIN sys.dm_db_missing_index_group_stats s ON s.group_handle = g.index_group_handle INNER JOIN sys.dm_db_missing_index_details d ON d.index_handle = g.index_handle ORDER BY [Total Cost] DESC"

# Monitor database connections and active sessions
Invoke-Sqlcmd -Query "SELECT login_name, COUNT(*) as connection_count FROM sys.dm_exec_sessions WHERE is_user_process = 1 GROUP BY login_name ORDER BY connection_count DESC"; Invoke-Sqlcmd -Query "SELECT @@CONNECTIONS as TotalConnections, @@MAX_CONNECTIONS as MaxConnections"
```

#### **MySQL Operations (via PowerShell)**
```powershell
# MySQL performance monitoring using mysql command
$mysqlCmd = "mysql -e `"SHOW PROCESSLIST;`" | Where-Object {`$_.Split()[5] -gt 10}"; Invoke-Expression $mysqlCmd; mysql -e "SHOW STATUS LIKE 'Slow_queries';"

# Database size analysis across all MySQL databases
mysql -e "SELECT table_schema AS 'Database', ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) AS 'Size_MB' FROM information_schema.tables GROUP BY table_schema ORDER BY Size_MB DESC;" | ConvertFrom-String -PropertyNames Database,Size_MB

# Automated MySQL backup with compression and verification
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"; mysqldump --all-databases --single-transaction --routines --triggers | gzip > "mysql_backup_$timestamp.sql.gz"; Test-Path "mysql_backup_$timestamp.sql.gz"

# Find unused indexes in MySQL for optimization
mysql -e "SELECT table_schema, table_name, index_name FROM information_schema.statistics WHERE cardinality IS NULL OR cardinality = 0 LIMIT 10;" | Format-Table

# MySQL replication monitoring and lag detection
mysql -e "SHOW MASTER STATUS;"; mysql -e "SHOW SLAVE STATUS\G" | Select-String "Seconds_Behind_Master|Slave_IO_Running|Slave_SQL_Running"
```

#### **MongoDB Operations**
```powershell
# MongoDB performance monitoring and connection stats
mongo --eval "db.serverStatus().connections" | ConvertFrom-Json; mongo --eval "db.runCommand({dbStats: 1})" | Select-String "dataSize|indexSize|fileSize"

# Collection statistics and index efficiency analysis
mongo --eval "db.collection.getIndexes()" | ConvertFrom-Json; mongo --eval "db.collection.aggregate([{`$indexStats:{}}])" | ConvertFrom-Json | Select-Object -First 10

# MongoDB backup with point-in-time recovery capability
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"; mongodump --host localhost --port 27017 --out "backup_$timestamp" --oplog; Compress-Archive -Path "backup_$timestamp" -DestinationPath "mongodb_backup_$timestamp.zip"

# Analyze large documents and query performance
mongo --eval "db.collection.find().sort({_id:-1}).limit(10).forEach(function(doc){print(Object.bsonsize(doc))})" | Sort-Object {[int]$_} -Descending | Select-Object -First 5

# Replica set and sharding status monitoring
mongo --eval "rs.status()" | Select-String "name|health|state"; mongo --eval "sh.status()" | Select-String "shard|chunks"
```

### Systems Engineer

#### **Performance Tuning**
```powershell
# System performance baseline with detailed metrics
Get-Counter "\Processor(_Total)\% Processor Time","\Memory\Available MBytes","\PhysicalDisk(_Total)\% Disk Time" -SampleInterval 1 -MaxSamples 5 | ForEach-Object {$_.CounterSamples | ForEach-Object {"$($_.Path): $([math]::Round($_.CookedValue,2))"}}

# Memory optimization and cache analysis
[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Get-Counter "\Memory\Available MBytes","\Memory\Cache Bytes","\Memory\Pool Nonpaged Bytes" | ForEach-Object {$_.CounterSamples | Select-Object Path,CookedValue}

# Disk I/O performance analysis and bottleneck identification
Get-PhysicalDisk | ForEach-Object {$disk = $_; Get-Counter "\PhysicalDisk($($disk.FriendlyName))\Disk Transfers/sec","\PhysicalDisk($($disk.FriendlyName))\% Disk Time" -MaxSamples 3 | ForEach-Object {$_.CounterSamples}}

# CPU performance and power management validation
Get-WmiObject Win32_Processor | Select-Object Name,CurrentClockSpeed,MaxClockSpeed,LoadPercentage; powercfg /query | Select-String "Power Scheme|CPU"

# Network performance tuning validation
Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -match "Receive|Transmit|Offload"} | Select-Object Name,DisplayName,RegistryValue | Format-Table -AutoSize
```

#### **Automation & Scripting**
```powershell
# Automated system health report generation
$report = "=== System Health Report $(Get-Date) ===`n"; $report += (Get-ComputerInfo | Select-Object WindowsProductName,TotalPhysicalMemory | Out-String); $report += (Get-Counter "\Processor(_Total)\% Processor Time" -MaxSamples 1 | Out-String); $report | Out-File "health_report_$(Get-Date -Format 'yyyyMMdd').txt"

# Bulk configuration deployment across servers
@('web1','web2','web3') | ForEach-Object {Copy-Item "config.xml" "\\$_\c$\Program Files\App\"; Invoke-Command -ComputerName $_ -ScriptBlock {Restart-Service AppService}; Write-Host "Updated $_"}

# Automated cleanup and maintenance tasks
Get-ChildItem -Path C:\Temp -Recurse -File | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} | Remove-Item -Force; Get-EventLog -LogName Application -After (Get-Date).AddDays(-7) | Where-Object {$_.EntryType -eq "Error"} | Export-Csv "errors_$(Get-Date -Format 'yyyyMMdd').csv"

# Service dependency validation and startup configuration
Get-Service | Where-Object {$_.StartType -eq "Automatic" -and $_.Status -ne "Running"} | Select-Object Name,Status,StartType; Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.State -ne "Running"} | Select-Object Name,State,StartMode

# Configuration compliance checking and drift detection
$configs = @("C:\Program Files\App\config.xml","C:\inetpub\wwwroot\web.config"); foreach($config in $configs) {$hash = Get-FileHash $config -Algorithm MD5; "$config`: $($hash.Hash)" | Out-File "config_hashes_$(Get-Date -Format 'yyyyMMdd').txt" -Append}
```

---

## 🔧 Cross-Platform Tools & Frameworks

### **Terraform Operations**
```bash
# Infrastructure drift detection and cost analysis
terraform plan -detailed-exitcode && terraform show -json | jq '.values.root_module.resources[] | select(.type | startswith("aws_")) | {type: .type, name: .name}' | head -20

# Multi-environment infrastructure deployment with validation
for env in dev staging prod; do echo "=== Deploying to $env ==="; terraform workspace select $env && terraform plan -var-file="$env.tfvars" && terraform apply -auto-approve -var-file="$env.tfvars"; done

# Resource cleanup and optimization suggestions
terraform state list | xargs -I {} terraform state show {} | grep -E "(instance_type|size|tier)" | awk '{print $1, $3}' | sort | uniq -c
```

### **Ansible Automation**
```bash
# Infrastructure compliance checking across inventory
ansible all -m setup -a "filter=ansible_distribution*" && ansible all -m shell -a "df -h | grep -E '8[0-9]%|9[0-9]%'" --become

# Bulk software deployment with rollback capability
ansible-playbook deploy.yml --limit production --check && ansible-playbook deploy.yml --limit production && ansible-playbook rollback.yml --limit production --tags "backup"

# Security hardening validation across fleet
ansible all -m shell -a "grep -E '^PasswordAuthentication|^PermitRootLogin' /etc/ssh/sshd_config" && ansible all -m shell -a "iptables -L | grep -c ACCEPT"
```

### **Prometheus/Grafana Monitoring**
```bash
# Query high cardinality metrics and memory usage
curl -s "http://prometheus:9090/api/v1/query?query=prometheus_tsdb_symbol_table_size_bytes" | jq '.data.result[0].value[1]' && curl -s "http://prometheus:9090/api/v1/label/__name__/values" | jq '.data | length'

# Alert rule validation and firing alerts summary
curl -s "http://prometheus:9090/api/v1/rules" | jq '.data.groups[].rules[] | select(.type=="alerting") | {name: .name, state: .state}' && curl -s "http://alertmanager:9093/api/v1/alerts" | jq '.data | length'

# Metrics retention and storage optimization
curl -s "http://prometheus:9090/api/v1/query?query=prometheus_tsdb_head_series" | jq '.data.result[0].value[1]' && du -sh /prometheus/data/
```

---

## 📊 Specialized Industry One-Liners

### **Cloud Platforms (AWS/Azure/GCP)**

#### **AWS CLI Operations**
```bash
# Multi-region resource inventory with cost analysis
for region in us-east-1 us-west-2 eu-west-1; do echo "=== $region ==="; aws ec2 describe-instances --region $region --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name]' --output table; done && aws ce get-cost-and-usage --time-period Start=2024-01-01,End=2024-01-31 --granularity MONTHLY --metrics BlendedCost

# Security group audit and compliance checking
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?FromPort==`22` && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' --output table && aws iam list-users --query 'Users[?PasswordLastUsed==null].[UserName,CreateDate]' --output table

# Auto-scaling and load balancer health monitoring
aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[].[AutoScalingGroupName,DesiredCapacity,MinSize,MaxSize]' --output table && aws elbv2 describe-target-health --target-group-arn $(aws elbv2 describe-target-groups --query 'TargetGroups[0].TargetGroupArn' --output text)
```

#### **Azure CLI Operations**
```bash
# Resource group analysis and cost optimization
az group list --query '[].{Name:name,Location:location}' --output table && az consumption usage list --start-date 2024-01-01 --end-date 2024-01-31 --query '[].{Date:usageStart,Cost:pretaxCost,Service:meterName}' --output table | head -20

# Virtual machine performance and scaling analysis
az vm list --show-details --query '[].{Name:name,Size:hardwareProfile.vmSize,PowerState:powerState,ResourceGroup:resourceGroup}' --output table && az monitor metrics list --resource-group myRG --resource myVM --metric "Percentage CPU"

# Network security group and firewall rule audit
az network nsg list --query '[].{Name:name,ResourceGroup:resourceGroup}' --output table && az network nsg rule list --nsg-name myNSG --resource-group myRG --query '[?access==`Allow` && direction==`Inbound`].{Name:name,Priority:priority,SourceAddress:sourceAddressPrefix,DestinationPort:destinationPortRange}'
```

### **Observability & APM**

#### **Elasticsearch/ELK Stack**
```bash
# Index health monitoring and optimization suggestions
curl -s "http://elasticsearch:9200/_cluster/health" | jq '.status, .number_of_nodes, .active_primary_shards' && curl -s "http://elasticsearch:9200/_cat/indices?v&s=store.size:desc" | head -10

# Log analysis and anomaly detection
curl -s "http://elasticsearch:9200/logs-*/_search" -H "Content-Type: application/json" -d '{"aggs":{"errors_over_time":{"date_histogram":{"field":"@timestamp","interval":"1h"},"aggs":{"error_count":{"filter":{"term":{"level":"ERROR"}}}}}},"size":0}' | jq '.aggregations.errors_over_time.buckets[] | {time: .key_as_string, errors: .error_count.doc_count}'

# Performance monitoring and slow query identification
curl -s "http://elasticsearch:9200/_nodes/stats" | jq '.nodes[] | {name: .name, heap_used: .jvm.mem.heap_used_percent, cpu: .process.cpu.percent}' && curl -s "http://elasticsearch:9200/_cat/thread_pool?v&h=node_name,name,active,queue,rejected"
```

#### **Jaeger Tracing**
```bash
# Distributed tracing analysis and latency monitoring
curl -s "http://jaeger:16686/api/services" | jq '.data[]' && curl -s "http://jaeger:16686/api/traces?service=myservice&start=$(date -d '1 hour ago' +%s)000000&end=$(date +%s)000000" | jq '.data[] | {traceID: .traceID, duration: .spans[0].duration}'

# Service dependency mapping and error rate analysis
curl -s "http://jaeger:16686/api/dependencies?endTs=$(date +%s)000" | jq '.data[] | {parent: .parent, child: .child, callCount: .callCount}' && curl -s "http://jaeger:16686/api/traces?tags=error:true" | jq '.data | length'
```

# Jenkins: Trigger build with parameters and monitor status
curl -X POST "http://jenkins:8080/job/myproject/buildWithParameters?token=mytoken&branch=main" && sleep 10 && curl -s "http://jenkins:8080/job/myproject/lastBuild/api/json" | jq '.result'

# Git: Create release branch with version bump and changelog
git checkout -b release/v$(date +%Y.%m.%d) && echo "v$(date +%Y.%m.%d)" > VERSION && git log --oneline --since="7 days ago" > CHANGELOG.md && git add . && git commit -m "Release v$(date +%Y.%m.%d)"

# Deploy application with health check and rollback capability
kubectl set image deployment/myapp container=myapp:$(git rev-parse --short HEAD) && kubectl rollout status deployment/myapp --timeout=300s || kubectl rollout undo deployment/myapp

# Check deployment status across multiple environments
for env in dev staging prod; do echo "=== $env ==="; kubectl --context=$env get deployments -o wide | grep myapp; done

# Automated testing and quality gate check
npm test && npm run lint && docker build -t test-image . && docker run --rm test-image npm run integration-tests && echo "✅ All tests passed"
```

### Site Reliability Engineer

#### **Service Monitoring & Alerting**
```bash
# Check service health across multiple endpoints with response times
for url in https://api.example.com/health https://web.example.com/ping; do time curl -s -o /dev/null -w "%{http_code} %{time_total}s" $url; echo " $url"; done

# Monitor SSL certificate expiration across multiple domains
echo "api.example.com:443 web.example.com:443" | tr ' ' '\n' | xargs -I {} openssl s_client -connect {} -servername {} 2>/dev/null | openssl x509 -noout -dates

# Database connection health check with query performance
time mysql -h db-server -e "SELECT COUNT(*) FROM information_schema.tables;" && time redis-cli -h redis-server ping

# Memory leak detection by monitoring process growth
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -10 && sleep 300 && ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -10

# Check disk I/O performance and identify bottlenecks
iostat -x 1 5 | awk '/^Device/ {print; getline; print} /^[a-z]/ && $10+0 > 80 {print "⚠️ High utilization: " $0}'
```

#### **Performance Monitoring**
```bash
# Application performance metrics with percentiles
curl -s http://localhost:8080/metrics | grep response_time | awk '{sum+=$2; count++} END {print "Avg response time:", sum/count "ms"}' && sar -n DEV 1 1 | grep eth0

# Memory usage breakdown by process with swap usage
ps aux --sort=-%mem | awk 'NR<=10 {mem+=$6} END {print "Top 10 processes using:", mem/1024 "MB"}' && free -h | grep Swap

# Network throughput and connection monitoring
ss -tuln | wc -l | xargs echo "Active connections:" && iftop -t -s 10 -B | tail -3

# Load average trend analysis with prediction
uptime | awk '{print $10,$11,$12}' | tr ',' ' ' && sar -u 1 10 | awk '/Average/ {print "CPU utilization trend:", $3"%"}'

# Real-time application error rate monitoring
tail -f /var/log/application.log | grep --line-buffered "ERROR" | while read line; do echo "$(date): $line"; done | pv -l -i 1 > /dev/null
```

#### **Incident Response**
```bash
# Emergency system snapshot for post-incident analysis
mkdir incident-$(date +%Y%m%d-%H%M%S) && cd incident-* && ps aux > processes.txt && netstat -tulpn > network.txt && df -h > disk.txt && free -h > memory.txt && dmesg > kernel.txt

# Quick service restart with logging and notification
service nginx stop && sleep 2 && service nginx start && echo "Nginx restarted at $(date)" | mail -s "Service Restart Alert" admin@company.com

# Find and kill problematic processes consuming resources
ps aux --sort=-%cpu | head -5 | awk '$3+0 > 80 {print "Killing high CPU process:", $2, $11; system("kill -9 " $2)}'

# Network connectivity troubleshooting matrix
for host in google.com 8.8.8.8 internal-server.com; do echo -n "$host: "; ping -c 1 -W 1 $host >/dev/null 2>&1 && echo "✅" || echo "❌"; done

# Log correlation for incident timeline
grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')" /var/log/syslog /var/log/application.log /var/log/nginx/error.log 2>/dev/null | sort -k1,2
```

### Network Engineer

#### **Network Diagnostics**
```bash
# Comprehensive network connectivity test with traceroute
for dest in 8.8.8.8 1.1.1.1 google.com; do echo "=== Testing $dest ==="; ping -c 3 $dest && traceroute -n $dest | head -10; done

# Port scan and service detection on critical servers
nmap -sS -O -sV --top-ports 1000 192.168.1.0/24 | grep -E "(open|filtered)" | head -20

# Bandwidth usage monitoring per interface
vnstat -i eth0 --json | jq '.interfaces[0].traffic.days[-1] | "Today: \(.rx)MB received, \(.tx)MB transmitted"'

# DNS resolution performance testing
for dns in 8.8.8.8 1.1.1.1 208.67.222.222; do echo -n "DNS $dns: "; time nslookup google.com $dns | grep "Non-authoritative" >/dev/null 2>&1 && echo "✅" || echo "❌"; done

# Network interface statistics and error detection
cat /proc/net/dev | awk 'NR>2 {print $1 $3 $11}' | column -t && ip -s link show | grep -E "(RX|TX).*errors" | grep -v "errors 0"
```

#### **Firewall & Security**
```bash
# Active connection monitoring with suspicious activity detection
netstat -tuln | awk '$1=="tcp" && $6=="LISTEN" {print $4}' && ss -tn | awk 'NR>1 {split($4,a,":"); ip[a[1]]++} END {for(i in ip) if(ip[i]>10) print "Suspicious:", i, ip[i], "connections"}'

# Iptables rules analysis and optimization suggestions
iptables -L -n -v --line-numbers | awk '/Chain/ {chain=$2} /^\s*[0-9]/ {if($1+0==0) print "Unused rule in", chain ":", $0}'

# Real-time intrusion detection from logs
tail -f /var/log/auth.log | grep --line-buffered -E "(Failed|Invalid)" | awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | awk '$1>5 {print "⚠️ Potential attack from", $5, "- attempts:", $1}'

# Network security scan with vulnerability assessment
nmap -sS -sV -sC --script vuln 192.168.1.1-254 2>/dev/null | grep -E "(open|VULNERABLE)" | head -20

# Certificate and SSL/TLS security validation
echo "443" | xargs -I {} nmap --script ssl-enum-ciphers -p {} target-server.com | grep -E "(TLS|SSL|cipher)"
```

#### **Network Configuration**
```bash
# Network interface configuration backup and validation
ip addr show | awk '/inet / {print $NF, $2}' > network-config-$(date +%Y%m%d).backup && ip route show table main > routes-$(date +%Y%m%d).backup

# VLAN and routing table analysis
ip link show | grep -E "(vlan|bond)" && ip route show | awk '{print $1,$3,$5}' | column -t

# Network performance optimization check
ethtool eth0 | grep -E "(Speed|Duplex|Auto-negotiation)" && tc qdisc show dev eth0

# Wireless network monitoring and optimization
iwconfig 2>/dev/null | grep -E "(ESSID|Quality|Signal)" && iw dev wlan0 scan | grep -E "(SSID|signal|freq)" | head -20

# Network namespace and container networking
ip netns list | while read ns; do echo "=== Namespace: $ns ==="; ip netns exec $ns ip addr show; done
```

### Database Administrator

#### **MySQL/MariaDB Operations**
```bash
# Database performance monitoring with slow query detection
mysql -e "SHOW PROCESSLIST;" | awk '$6+0 > 10 {print "Long running query:", $1, $6 "s:", $8}' && mysql -e "SHOW STATUS LIKE 'Slow_queries';"

# Database size analysis and growth tracking
mysql -e "SELECT table_schema, ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) AS 'DB Size in MB' FROM information_schema.tables GROUP BY table_schema;" | column -t

# Backup all databases with compression and verification
mysqldump --all-databases --single-transaction --routines --triggers | gzip > backup-$(date +%Y%m%d-%H%M%S).sql.gz && gunzip -t backup-$(date +%Y%m%d-%H%M%S).sql.gz && echo "✅ Backup verified"

# Find unused indexes and optimization opportunities
mysql -e "SELECT table_schema, table_name, index_name FROM information_schema.statistics WHERE cardinality IS NULL OR cardinality = 0;" | head -10

# Monitor database connections and resource usage
mysql -e "SHOW STATUS LIKE 'Connections';" && mysql -e "SHOW STATUS LIKE 'Threads_connected';" && mysql -e "SHOW STATUS LIKE 'Questions';" | awk '{sum+=$2} END {print "Total queries:", sum}'
```

#### **PostgreSQL Operations**
```bash
# PostgreSQL performance and connection monitoring
psql -c "SELECT datname, numbackends, xact_commit, xact_rollback FROM pg_stat_database WHERE datname NOT IN ('template0', 'template1', 'postgres');" | column -t

# Database vacuum and maintenance automation
psql -c "SELECT schemaname, tablename, n_dead_tup FROM pg_stat_user_tables WHERE n_dead_tup > 1000 ORDER BY n_dead_tup DESC;" | head -10 | awk 'NR>2 {print $1"."$2}' | xargs -I {} psql -c "VACUUM ANALYZE {};"

# Find long-running queries and blocking processes
psql -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query FROM pg_stat_activity WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';"

# Backup with point-in-time recovery capability
pg_basebackup -D backup-$(date +%Y%m%d) -Ft -z -P -U postgres && echo "✅ Base backup completed at $(date)"

# Database replication monitoring and lag detection
psql -c "SELECT client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn, sync_state FROM pg_stat_replication;" | column -t
```

#### **MongoDB Operations**
```bash
# MongoDB performance monitoring and optimization
mongo --eval "db.serverStatus().connections" && mongo --eval "db.runCommand({dbStats: 1})" | grep -E "(dataSize|indexSize|fileSize)"

# Collection statistics and index usage analysis
mongo --eval "db.collection.getIndexes()" && mongo --eval "db.collection.aggregate([{\$indexStats:{}}])" | head -10

# MongoDB backup with oplog for point-in-time recovery
mongodump --host localhost --port 27017 --out backup-$(date +%Y%m%d) --oplog && tar -czf mongodb-backup-$(date +%Y%m%d).tar.gz backup-$(date +%Y%m%d)

# Find large documents and optimize queries
mongo --eval "db.collection.find().sort({_id:-1}).limit(10).forEach(function(doc){print(Object.bsonsize(doc))})" | sort -nr | head -5

# Replica set status and sharding monitoring
mongo --eval "rs.status()" | grep -E "(name|health|state)" && mongo --eval "sh.status()" | grep -E "(shard|chunks)"
```

### Systems Engineer

#### **Performance Tuning**
```bash
# System performance baseline with recommendations
vmstat 1 5 | awk 'NR>2 {cpu+=$(NF-2); mem+=$4; io+=$10} END {print "Avg CPU:", cpu/(NR-2)"%, Free Memory:", mem/(NR-2)"MB, IO Wait:", io/(NR-2)"%"}' && sysctl vm.swappiness

# Memory optimization and cache analysis
echo 3 > /proc/sys/vm/drop_caches && free -h && echo "Cache cleared" && cat /proc/meminfo | grep -E "(Cached|Buffers|Available)" | awk '{print $1, $2/1024 "MB"}'

# Disk I/O optimization and bottleneck identification
for dev in $(lsblk -nd -o NAME); do echo "=== /dev/$dev ==="; hdparm -tT /dev/$dev 2>/dev/null; done && iostat -x 1 3 | grep -E "(Device|avg)"

# CPU frequency scaling and power management
cpupower frequency-info | grep "current CPU frequency" && cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c

# Network performance tuning validation
sysctl net.core.rmem_max net.core.wmem_max net.ipv4.tcp_window_scaling && ss -i | grep -E "(rto|rtt|cwnd)" | head -5
```

#### **Automation & Scripting**
```bash
# Automated system health report generation
echo "=== System Health Report $(date) ===" > health-report.txt && uptime >> health-report.txt && df -h >> health-report.txt && free -h >> health-report.txt && ps aux --sort=-%mem | head -5 >> health-report.txt

# Bulk configuration deployment across servers
for server in web1 web2 web3; do scp config.conf $server:/etc/app/ && ssh $server "systemctl reload app && echo 'Updated $server'"; done

# Log rotation and cleanup automation
find /var/log -name "*.log" -type f -size +100M -exec logrotate -f /etc/logrotate.conf {} \; && docker system prune -f && apt-get autoremove -y

# Service dependency validation and startup order
systemctl list-dependencies --reverse nginx | grep -E "(service|target)" && systemctl is-enabled nginx mysql redis

# Configuration drift detection and compliance checking
md5sum /etc/nginx/nginx.conf /etc/mysql/my.cnf /etc/redis/redis.conf > config-checksums-$(date +%Y%m%d).txt && diff config-checksums-baseline.txt config-checksums-$(date +%Y%m%d).txt
```

---

## 🪟 Windows/PowerShell One-Liners

### System Administrator

#### **System Monitoring & Health**
```powershell
# Real-time system resource monitoring with alerts
Get-Counter "\Processor(_Total)\% Processor Time","\Memory\Available MBytes" -SampleInterval 1 -MaxSamples 5 | ForEach-Object {$_.CounterSamples | ForEach-Object {Write-Host "$($_.Path): $($_.CookedValue)"}}

# Find processes consuming most memory with ability to stop them
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Name,Id,@{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet/1MB,2)}} | Format-Table -AutoSize

# Monitor failed login attempts in real-time
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 | Select-Object TimeCreated,@{Name="FailedUser";Expression={$_.Properties[5].Value}},@{Name="SourceIP";Expression={$_.Properties[19].Value}}

# Check system uptime, performance counters, and active sessions
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object @{Name="Uptime";Expression={(Get-Date) - $_.LastBootUpTime}} && (quser 2>$null | Measure-Object).Count

# Find large files consuming disk space (over 100MB)
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 100MB} | Sort-Object Length -Descending | Select-Object -First 20 Name,@{Name="Size(GB)";Expression={[math]::Round($_.Length/1GB,2)}},FullName
```

#### **Log Analysis & Troubleshooting**
```powershell
# Parse IIS logs for top IPs and status codes
Import-Csv (Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC1\*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Delimiter ' ' -Header @('date','time','s-sitename','s-computername','s-ip','cs-method','cs-uri-stem','cs-uri-query','s-port','cs-username','c-ip','cs-version','cs-user-agent','cs-cookie','cs-referer','cs-host','sc-status','sc-substatus','sc-win32-status','sc-bytes','cs-bytes','time-taken') | Group-Object 'c-ip','sc-status' | Sort-Object Count -Descending | Select-Object -First 20

# Find system errors from last 24 hours with context
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-1)} | Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-List

# Monitor Windows Event Log growth and critical events
Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | Sort-Object RecordCount -Descending | Select-Object -First 10 LogName,RecordCount,@{Name="Size(MB)";Expression={[math]::Round($_.FileSize/1MB,2)}}

# Extract unique error patterns from application logs
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 1000 | Group-Object Id | Sort-Object Count -Descending | Select-Object Count,Name,@{Name="Sample";Expression={$_.Group[0].Message.Substring(0,[math]::Min(100,$_.Group[0].Message.Length))}}

# Real-time monitoring of multiple event logs
Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE Logfile='System' OR Logfile='Application'" -Action {Write-Host "$(Get-Date): $($Event.SourceEventArgs.NewEvent.Message)"}
```

#### **User & Permission Management**
```powershell
# Audit user accounts with last login and password expiry
Get-LocalUser | ForEach-Object {$user = $_; $lastLogin = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; Data=$user.Name} -MaxEvents 1 -ErrorAction SilentlyContinue).TimeCreated; [PSCustomObject]@{User=$user.Name; LastLogin=$lastLogin; PasswordExpires=$user.PasswordExpires; Enabled=$user.Enabled}}

# Find files with weak permissions for security audit
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Attributes -notmatch "Directory"} | ForEach-Object {$acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue; if($acl.Access | Where-Object {$_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Write"}) {$_.FullName}}

# Check for administrative accounts and privileges
Get-LocalGroupMember -Group "Administrators" | Select-Object Name,ObjectClass,PrincipalSource && Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | Where-Object {$_.SID -like "*-500"} | Select-Object Name,Disabled

# Find recently modified files by specific users
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} -MaxEvents 100 | Where-Object {$_.Properties[1].Value -match "WRITE"} | Select-Object TimeCreated,@{Name="User";Expression={$_.Properties[3].Value}},@{Name="File";Expression={$_.Properties[6].Value}} | Sort-Object TimeCreated -Descending

# Generate security audit report for user activities
$users = Get-LocalUser; foreach($user in $users) {Write-Host "=== $($user.Name) ==="; Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4634; Data=$user.Name} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id | Format-Table}
```

### DevOps Engineer

#### **Docker & Containerization**
```powershell
# Clean up unused Docker resources and show space reclaimed
docker system df; docker system prune -af --volumes; Write-Host "=== After cleanup ==="; docker system df

# Monitor container resource usage in real-time
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Find and stop containers using most resources
docker stats --no-stream --format '{{.Container}} {{.CPUPerc}}' | ConvertFrom-String -PropertyNames Container,CPU | Sort-Object {[double]($_.CPU -replace '%','')} -Descending | Select-Object -First 5 | ForEach-Object {docker stop $_.Container}

# Build and tag Docker image with git commit hash
$commit = git rev-parse --short HEAD; docker build -t "myapp:$commit" .; docker tag "myapp:$commit" myapp:latest

# Export Docker container with timestamp for backup
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"; docker export $(docker ps -q --filter "name=myapp") | gzip > "myapp-backup-$timestamp.tar.gz"

# Update all running containers to latest images
docker ps --format '{{.Image}}' | Sort-Object -Unique | ForEach-Object {docker pull $_; docker ps --format "{{.Names}}" --filter "ancestor=$_" | ForEach-Object {docker restart $_}}
```

#### **Kubernetes Operations (with kubectl)**
```powershell
# Get pods consuming most CPU/Memory across all namespaces
kubectl top pods --all-namespaces --sort-by=cpu | Select-Object -First 10; Write-Host "=== MEMORY ==="; kubectl top pods --all-namespaces --sort-by=memory | Select-Object -First 10

# Check cluster health with node status and resource usage
kubectl get nodes -o wide; kubectl top nodes; kubectl get pods --all-namespaces | Where-Object {$_ -notmatch "Running"} | Select-Object -First 10

# Find failed pods and their logs
kubectl get pods --all-namespaces --field-selector=status.phase=Failed -o name | ForEach-Object {kubectl logs $_ --tail=50}

# Scale deployments based on current resource usage
$podCount = (kubectl top pods -l app=myapp --no-headers | Where-Object {($_ -split '\s+')[2] -replace 'Mi','' -as [int] -gt 80}).Count; kubectl scale deployment myapp --replicas=$podCount

# Backup all configmaps and secrets to files
$date = Get-Date -Format "yyyyMMdd"; kubectl get configmaps --all-namespaces -o yaml > "configmaps-backup-$date.yaml"; kubectl get secrets --all-namespaces -o yaml > "secrets-backup-$date.yaml"
```
