"""Service signature database for banner matching."""

from __future__ import annotations

# Version extraction patterns for common services
VERSION_PATTERNS: dict[str, str] = {
    "ssh": r"SSH-[\d.]+-(\S+)",
    "apache": r"Apache/([\d.]+)",
    "nginx": r"nginx/([\d.]+)",
    "openssl": r"OpenSSL/([\d.a-z]+)",
    "iis": r"Microsoft-IIS/([\d.]+)",
    "lighttpd": r"lighttpd/([\d.]+)",
    "postfix": r"Postfix",
    "exim": r"Exim\s+([\d.]+)",
    "vsftpd": r"vsftpd\s+([\d.]+)",
    "proftpd": r"ProFTPD\s+([\d.]+)",
    "openssh": r"OpenSSH[_\s]+([\d.p]+)",
    "dropbear": r"dropbear[_\s]+([\d.]+)",
    "mysql": r"([\d.]+)-.*?MySQL",
    "mariadb": r"([\d.]+)-MariaDB",
    "postgresql": r"PostgreSQL\s+([\d.]+)",
    "redis": r"redis_version:([\d.]+)",
    "mongodb": r"MongoDB\s+([\d.]+)",
    "elasticsearch": r"elasticsearch/([\d.]+)",
}

# Common banner-to-service mappings for quick identification
QUICK_MATCH: dict[str, str] = {
    "SSH-": "ssh",
    "220 ": "ftp",
    "HTTP/": "http",
    "+OK": "pop3",
    "* OK": "imap",
    "* BYE": "imap",
    "RFB ": "vnc",
    "AMQP": "amqp",
    "-ERR": "redis",
    "+PONG": "redis",
}
