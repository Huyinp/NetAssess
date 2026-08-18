#include "protocol_classifier.h"

namespace {

ApplicationProtocol Lookup(TransportProtocol transport_protocol, uint16_t port) {
    switch (transport_protocol) {
    case TransportProtocol::Tcp:
        switch (port) {
        case 20:
        case 21:
            return ApplicationProtocol::Ftp;
        case 22:
            return ApplicationProtocol::Ssh;
        case 25:
        case 465:
        case 587:
            return ApplicationProtocol::Smtp;
        case 53:
            return ApplicationProtocol::Dns;
        case 80:
            return ApplicationProtocol::Http;
        case 110:
        case 995:
            return ApplicationProtocol::Pop3;
        case 143:
        case 993:
            return ApplicationProtocol::Imap;
        case 389:
        case 636:
            return ApplicationProtocol::Ldap;
        case 443:
            return ApplicationProtocol::HttpsTls;
        case 445:
            return ApplicationProtocol::Smb;
        case 1433:
            return ApplicationProtocol::SqlServer;
        case 3306:
            return ApplicationProtocol::MySql;
        case 3389:
            return ApplicationProtocol::Rdp;
        case 5432:
            return ApplicationProtocol::PostgreSql;
        case 6379:
            return ApplicationProtocol::Redis;
        case 27017:
            return ApplicationProtocol::MongoDb;
        default:
            return ApplicationProtocol::Other;
        }
    case TransportProtocol::Udp:
        switch (port) {
        case 53:
            return ApplicationProtocol::Dns;
        case 67:
        case 68:
            return ApplicationProtocol::Dhcp;
        case 123:
            return ApplicationProtocol::Ntp;
        case 389:
            return ApplicationProtocol::Ldap;
        case 443:
            return ApplicationProtocol::Quic;
        case 500:
        case 4500:
            return ApplicationProtocol::IpsecIke;
        case 3389:
            return ApplicationProtocol::Rdp;
        default:
            return ApplicationProtocol::Other;
        }
    }

    return ApplicationProtocol::Other;
}

}  // namespace

ApplicationProtocol InferApplicationProtocol(TransportProtocol transport_protocol,
                                             TrafficDirection direction,
                                             uint16_t source_port,
                                             uint16_t destination_port) {
    const uint16_t primary_port = direction == TrafficDirection::Send ? destination_port : source_port;
    const uint16_t secondary_port = direction == TrafficDirection::Send ? source_port : destination_port;

    const ApplicationProtocol primary_protocol = Lookup(transport_protocol, primary_port);
    return primary_protocol == ApplicationProtocol::Other
               ? Lookup(transport_protocol, secondary_port)
               : primary_protocol;
}

std::wstring_view ApplicationProtocolName(ApplicationProtocol protocol) {
    switch (protocol) {
    case ApplicationProtocol::Ftp:
        return L"FTP（端口推断）";
    case ApplicationProtocol::Ssh:
        return L"SSH（端口推断）";
    case ApplicationProtocol::Smtp:
        return L"SMTP（端口推断）";
    case ApplicationProtocol::Dns:
        return L"DNS（端口推断）";
    case ApplicationProtocol::Dhcp:
        return L"DHCP（端口推断）";
    case ApplicationProtocol::Http:
        return L"HTTP（端口推断）";
    case ApplicationProtocol::Pop3:
        return L"POP3（端口推断）";
    case ApplicationProtocol::Ntp:
        return L"NTP（端口推断）";
    case ApplicationProtocol::Imap:
        return L"IMAP（端口推断）";
    case ApplicationProtocol::Ldap:
        return L"LDAP（端口推断）";
    case ApplicationProtocol::HttpsTls:
        return L"HTTPS/TLS（端口推断）";
    case ApplicationProtocol::Quic:
        return L"QUIC（端口推断）";
    case ApplicationProtocol::Smb:
        return L"SMB（端口推断）";
    case ApplicationProtocol::IpsecIke:
        return L"IPsec/IKE（端口推断）";
    case ApplicationProtocol::SqlServer:
        return L"SQL Server（端口推断）";
    case ApplicationProtocol::MySql:
        return L"MySQL（端口推断）";
    case ApplicationProtocol::Rdp:
        return L"RDP（端口推断）";
    case ApplicationProtocol::PostgreSql:
        return L"PostgreSQL（端口推断）";
    case ApplicationProtocol::Redis:
        return L"Redis（端口推断）";
    case ApplicationProtocol::MongoDb:
        return L"MongoDB（端口推断）";
    case ApplicationProtocol::Other:
        return L"其他";
    }

    return L"其他";
}
