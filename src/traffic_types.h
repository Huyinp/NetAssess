#pragma once

#include <cstdint>

enum class TransportProtocol {
    Tcp,
    Udp,
};

enum class TrafficDirection {
    Send,
    Receive,
};

enum class ApplicationProtocol {
    Ftp,
    Ssh,
    Smtp,
    Dns,
    Dhcp,
    Http,
    Pop3,
    Ntp,
    Imap,
    Ldap,
    HttpsTls,
    Quic,
    Smb,
    IpsecIke,
    SqlServer,
    MySql,
    Rdp,
    PostgreSql,
    Redis,
    MongoDb,
    Other,
};
