"""
Sample log data for testing
"""

# JSON logs
JSON_LOGS = [
    '{"timestamp": "2026-03-29T10:00:00.000000Z", "source_ip": "192.168.1.100", "severity": "error", "message": "Failed login attempt"}',
    '{"timestamp": "2026-03-29T10:00:01.000000Z", "source_ip": "192.168.1.101", "severity": "info", "message": "Successful login"}',
    '{"@timestamp": "2026-03-29T10:00:02Z", "client_ip": "10.0.0.1", "level": "warning", "msg": "High memory usage"}',
]

# Syslog format
SYSLOG_LOGS = [
    '<34>Mar 29 10:30:45 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2',
    '<86>Mar 29 10:30:46 server1 kernel: Out of memory: Kill process 1234',
    'Mar 29 10:30:47 server1 systemd: Started Session 1 of user root',
]

# Apache access logs
APACHE_LOGS = [
    '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234',
    '192.168.1.101 - - [29/Mar/2026:10:30:46 +0000] "POST /api/login HTTP/1.1" 401 0',
    '192.168.1.102 - - [29/Mar/2026:10:30:47 +0000] "GET /admin HTTP/1.1" 403 567',
    '192.168.1.103 - - [29/Mar/2026:10:30:48 +0000] "GET /missing HTTP/1.1" 404 0',
    '192.168.1.104 - - [29/Mar/2026:10:30:49 +0000] "GET /error HTTP/1.1" 500 0',
]

# CSV logs
CSV_LOGS = [
    '2026-03-29 10:00:00,192.168.1.100,10.0.0.1,Failed connection attempt',
    '2026-03-29 10:00:01,192.168.1.101,10.0.0.1,Successful connection',
    '2026-03-29 10:00:02,192.168.1.102,10.0.0.1,Connection timeout',
]

# Mixed format logs (for auto-detection)
MIXED_LOGS = [
    '{"timestamp": "2026-03-29T10:00:00Z", "message": "JSON format log"}',
    '<34>Mar 29 10:30:45 server1 sshd: Syslog format log',
    '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET / HTTP/1.1" 200 100',
]

# Security-related logs
SECURITY_LOGS = [
    '{"timestamp": "2026-03-29T10:00:00Z", "source_ip": "192.168.1.100", "severity": "critical", "message": "Multiple failed login attempts detected"}',
    '{"timestamp": "2026-03-29T10:00:05Z", "source_ip": "192.168.1.100", "severity": "critical", "message": "Possible brute force attack"}',
    '<34>Mar 29 10:30:45 firewall kernel: DROP IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.1',
    '192.168.1.100 - - [29/Mar/2026:10:30:45 +0000] "GET /admin HTTP/1.1" 403 0',
]
