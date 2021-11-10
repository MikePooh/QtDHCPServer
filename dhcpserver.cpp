#include "dhcpserver.h"
#include <QtEndian>
#include <QNetworkInterface>

quint32 DHCPServer::mask() const
{
    static quint32 mask = 0xFFFFFFFF << (32 - m_address.prefixLength());
    return mask;
}

quint32 DHCPServer::revMask() const
{
    static quint32 revMask = 0xFFFFFFFF >> m_address.prefixLength();
    return revMask;
}

bool DHCPServer::initializeDHCPServer()
{
    if (!m_socket.bind(dhcpServerPort, QUdpSocket::ShareAddress))
        return false;
    connect(&m_socket, &QUdpSocket::readyRead, this, [this]()
    {
        QByteArray datagram;
        while (m_socket.hasPendingDatagrams()) {
            datagram.resize(static_cast<int>(m_socket.pendingDatagramSize()));
            m_socket.readDatagram(datagram.data(), datagram.size());
            emit dhcpDatagramReceived(datagram);
            parseDatagram(datagram);
        }
    });
    emit serverStarted(m_address.ip(), m_address.netmask(), m_address.prefixLength());
    return true;
}

QVector<DHCPServer::DHCPTableEntry> DHCPServer::getDhcpTable()
{
    return m_DHCPTable;
}

bool DHCPServer::isRunning()
{
    return m_socket.state() == QAbstractSocket::BoundState;
}

void DHCPServer::stopDHCPServer()
{
    m_socket.close();
    emit serverStopped();
}

QString DHCPServer::getStartAddressStr()
{
    return m_startAddress.toString();
}

QString DHCPServer::getStopAddressStr()
{
    return m_stopAddress.toString();
}

void DHCPServer::parseDatagram(const QByteArray &datagram)
{
    DHCPMessage msg;

    msg.op = static_cast<quint8>(datagram.mid(0, 1).toHex().toUInt());

    if(static_cast<OpValue>(msg.op) != OpValue::BOOTREQUEST) return; //All incoming messages MUST be BOOTREQUEST

    msg.htype = static_cast<quint8>(datagram.mid(1, 1).toHex().toUShort());
    msg.hlen = static_cast<quint8>(datagram.mid(2, 1).toHex().toUInt());
    msg.hops = static_cast<quint8>(datagram.mid(3, 1).toHex().toUInt());
    msg.xid = datagram.mid(4, 4);
    msg.secs = static_cast<quint16>(datagram.mid(8, 2).toHex().toUInt());
    msg.flags = datagram.mid(10, 2);
    msg.ciaddr = datagram.mid(12, 4).toHex().toUInt();
    msg.yiaddr = datagram.mid(16, 4).toHex().toUInt();
    msg.siaddr = datagram.mid(20, 4).toHex().toUInt();
    msg.giaddr = datagram.mid(24, 4).toHex().toUInt();
    msg.chaddr = datagram.mid(28, 16);
    msg.sname = datagram.mid(44, 64);
    msg.file = datagram.mid(108, 128);

    QByteArray options = datagram.mid(236);

    if (options.mid(0, 4) != magicCookies) {
        qDebug() << "Magic cookies falut";
        return;
    }

    QVector<Option> ops;
    int offset = 4;
    DHCPOption option = DHCPOption::NONE;
    int size = 0;
    enum DHCPMessageType type = DHCPMessageType::NONE;
    while (true) {
        option = static_cast<DHCPOption>(options.mid(offset, 1).toHex().toInt(nullptr, 16));
        if (option == DHCPOption::END) break;
        size = options.mid(offset + 1, 1).toHex().toInt(nullptr, 16);
        QByteArray body = options.mid(offset + 2, size);

        if (option == DHCPOption::DHCPMessageType)
            type = static_cast<enum DHCPMessageType>(body.toHex().toInt());
        else
            ops.append({option, body});
        offset += 2 + size;
        if (offset > 576) { //576 octets is maximum datagram length according to RFC2131
            break;
        }
    }
    msg.options = ops;

    switch (type) {
    case DHCPMessageType::NONE:
        qDebug() << "Message type is NONE";
        return;
    case DHCPMessageType::DISCOVER:
        handleDhcpDiscover(msg);
        break;
    case DHCPMessageType::REQUEST:
        handleDhcpRequest(msg);
        break;
    case DHCPMessageType::DECLINE:
        handleDhcpDecline(msg);
        break;
    case DHCPMessageType::RELEASE:
        handleDhcpRelease(msg);
        break;
    }
}

void DHCPServer::handleDhcpDiscover(const DHCPMessage &request)
{
    if (static_cast<OpValue>(request.op) != OpValue::BOOTREQUEST) {
        qDebug() << "Bad OP Code";
        return;
    }

    emit dhcpMessageReveived(DHCPMessageType::DISCOVER, request.chaddr);

    DHCPMessage response;
    QHostAddress address;
    quint32 requestedAddress = 0;

    foreach (const Option& reqOption, request.options) {
        if (reqOption.first == DHCPOption::DHCPRequestAddress) {
            requestedAddress = reqOption.second.toHex().toUInt(nullptr, 16);
        }
    }
    address = getAddress(requestedAddress, request.chaddr, true);
    if (address.isNull()) return;

    response.op = static_cast<quint8>(OpValue::BOOTREPLY);
    response.htype = 1;
    response.hlen = 6;
    response.hops = 0;
    response.xid = request.xid;
    response.secs = 0;
    response.ciaddr = 0;
    response.yiaddr = address.toIPv4Address();
    response.siaddr = 0;
    response.flags = request.flags;
    response.giaddr = request.giaddr;
    response.chaddr = request.chaddr;
    response.sname = m_serverName;
    response.file = request.file;

    response.options.append({DHCPOption::DHCPMessageType, getBytes(DHCPMessageType::OFFER, quint8())});
    response.options.append({DHCPOption::DHCPLeaseTime, getBytes(m_leaseTime, quint32())});
    response.options.append({DHCPOption::DHCPServerIdentifier, getBytes(m_address.ip().toIPv4Address(), quint32())});

    DHCPTableEntry entry(request.chaddr, address);
    if (!m_offeredAddressesTable.contains(entry)) {
        m_offeredAddressesTable.append({request.chaddr, address});
        emit dhcpAddressOffered(request.chaddr, address);
    }

    QByteArray res;
    makePacket(response, res);
    m_socket.writeDatagram(res, m_address.broadcast(), dhcpClientPort);
}

void DHCPServer::handleDhcpRequest(const DHCPMessage &request)
{
    if (static_cast<OpValue>(request.op) != OpValue::BOOTREQUEST) {
        qDebug() << "Bad OP Code";
        return;
    }

    emit dhcpMessageReveived(DHCPMessageType::REQUEST, request.chaddr);

    DHCPMessage response;
    QHostAddress address;
    quint32 requestedAddress = 0;

    foreach (const Option& reqOption, request.options) {
        if (reqOption.first == DHCPOption::DHCPRequestAddress) {
            requestedAddress = reqOption.second.toHex().toUInt(nullptr, 16);
        }
    }
    address = getAddress(requestedAddress, request.chaddr, false);

    if ((requestedAddress && address.toIPv4Address() == requestedAddress) ||
            (!requestedAddress && !address.isNull()))
    {
        response.op = static_cast<quint8>(OpValue::BOOTREPLY);
        response.htype = 1;
        response.hlen = 6;
        response.hops = 0;
        response.xid = request.xid;
        response.secs = 0;
        response.ciaddr = request.ciaddr;
        response.yiaddr = address.toIPv4Address();
        response.siaddr = 0;
        response.flags = request.flags;
        response.giaddr = request.giaddr;
        response.chaddr = request.chaddr;
        response.sname = m_serverName;
        response.file = request.file;

        response.options.append({DHCPOption::DHCPMessageType, getBytes(DHCPMessageType::ACK, quint8())});
        response.options.append({DHCPOption::DHCPLeaseTime, getBytes(m_leaseTime, quint32())});

        DHCPTableEntry entry(request.chaddr, address);
        if (!m_DHCPTable.contains(entry)) {
            emit dhcpAddressAssigned(request.chaddr, address);
            m_DHCPTable.append(entry);
        }
        if (m_offeredAddressesTable.contains(entry)) m_offeredAddressesTable.removeAll(entry);

    }
    else //NAK
    {
        response.op = static_cast<quint8>(OpValue::BOOTREPLY);
        response.htype = 1;
        response.hlen = 6;
        response.hops = 0;
        response.xid = request.xid;
        response.secs = 0;
        response.ciaddr = 0;
        response.yiaddr = 0;
        response.siaddr = 0;
        response.flags = request.flags;
        response.giaddr = request.giaddr;
        response.chaddr = request.chaddr;
        response.sname = m_serverName;
        response.file = request.file;
    }

    response.options.append({DHCPOption::DHCPServerIdentifier, getBytes(m_address.ip().toIPv4Address(), quint32())});

    QByteArray res;
    makePacket(response, res);
    m_socket.writeDatagram(res, m_address.broadcast(), dhcpClientPort);
}

void DHCPServer::handleDhcpDecline(const DHCPMessage &request)
{
    if (static_cast<OpValue>(request.op) != OpValue::BOOTREQUEST) {
        qDebug() << "Bad OP Code";
        return;
    }

    emit dhcpMessageReveived(DHCPMessageType::DECLINE, request.chaddr);

    QHostAddress busyAddress;

    foreach (const DHCPTableEntry& entry, m_DHCPTable) {
        if (entry.first == request.chaddr) {
            busyAddress = entry.second;
            m_DHCPTable.removeAll(entry);
        }
    }

    QByteArray zero;
    zero.resize(16);
    for (int i = 0; i < 16; i++) {
        zero[i] = '\0';
    }
    m_DHCPTable.append({zero, busyAddress});
}

void DHCPServer::handleDhcpRelease(const DHCPMessage &request)
{
    if (static_cast<OpValue>(request.op) != OpValue::BOOTREQUEST) {
        qDebug() << "Bad OP Code";
        return;
    }

    emit dhcpMessageReveived(DHCPMessageType::RELEASE, request.chaddr);

    foreach (const DHCPTableEntry& entry, m_DHCPTable) {
        if (entry.first == request.chaddr) {
            m_DHCPTable.removeAll(entry);
        }
    }
}

void DHCPServer::handleDhcpInform(const DHCPMessage &request)
{
    if (static_cast<OpValue>(request.op) != OpValue::BOOTREQUEST) {
        qDebug() << "Bad OP Code";
        return;
    }

    emit dhcpMessageReveived(DHCPMessageType::INFORM, request.chaddr);

    DHCPMessage response;

    response.op = static_cast<quint8>(OpValue::BOOTREPLY);
    response.htype = 1;
    response.hlen = 6;
    response.hops = 0;
    response.xid = request.xid;
    response.secs = 0;
    response.ciaddr = request.ciaddr;
    response.yiaddr = 0;
    response.siaddr = 0;
    response.flags = request.flags;
    response.giaddr = request.giaddr;
    response.chaddr = request.chaddr;
    response.sname = m_serverName;
    response.file = request.file;

    response.options.append({DHCPOption::DHCPMessageType, getBytes(DHCPMessageType::ACK, quint8())});
    response.options.append({DHCPOption::DHCPServerIdentifier, getBytes(m_address.ip().toIPv4Address(), quint32())});

    QHostAddress ciaddr(request.ciaddr);

    DHCPTableEntry entry(request.chaddr, ciaddr);
    if (!m_DHCPTable.contains(entry)) m_DHCPTable.append(entry);

    QByteArray res;
    makePacket(response, res);
    m_socket.writeDatagram(res, ciaddr, dhcpClientPort);
}

void DHCPServer::makePacket(const DHCPMessage &response, QByteArray &result)
{
    result.append(getBytes(response.op, quint8()));
    result.append(getBytes(response.htype, quint8()));
    result.append(getBytes(response.hlen, quint8()));
    result.append(getBytes(response.hops, quint8()));
    result.append(response.xid);
    if (response.xid.size() < 4) result.append(4 - response.xid.size(), '\0');
    result.append(getBytes(response.secs, quint16()));
    result.append(response.flags);
    if (response.flags.size() < 2) result.append(2 - response.flags.size(), '\0');
    result.append(getBytes(response.ciaddr, quint32()));
    result.append(getBytes(response.yiaddr, quint32()));
    result.append(getBytes(response.siaddr, quint32()));
    result.append(getBytes(response.giaddr, quint32()));
    result.append(response.chaddr);
    if (response.chaddr.size() < 16) result.append(16 - response.chaddr.size(), '\0');
    result.append(response.sname);
    if (response.sname.size() < 64) result.append(64 - response.sname.size(), '\0');
    result.append(response.file);
    if (response.file.size() < 128) result.append(128 - response.file.size(), '\0');

    result.append(magicCookies);

    foreach (const Option& option, response.options) {
        result.append(getBytes(option.first, quint8()));
        result.append(getBytes(option.second.size(), quint8()));
        result.append(option.second);
    }

    result.append(QByteArray::fromHex("FF")); //End of options byte
}

QHostAddress DHCPServer::getAddress(quint32 requested, const QByteArray& chaddr, bool checkOffered)
{
    static const quint32 addr = m_address.ip().toIPv4Address();

    auto isAddressAvailable = [&chaddr](quint32 address, const QVector<DHCPTableEntry>& table) //table - DHCPTable or offeredTable
    {
        foreach (const DHCPTableEntry& entry, table) {
            if (entry.second.toIPv4Address() == address)
                if (entry.first != chaddr) return false;
        }
        return true;
    };

    auto getNewAddress = [this](quint32 address=0)
    {
        quint32 newaddr = 0;
        if (!address) {
            if (m_DHCPTable.isEmpty()) {
                if (!m_startAddress.isNull())
                    newaddr = m_startAddress.toIPv4Address();
                else
                    newaddr = (mask() & addr) + 1;
            }
            else
                newaddr = m_DHCPTable.last().second.toIPv4Address() + 1;
        }
        else
            newaddr = address + 1;
        if ((newaddr & revMask()) == 0x01) newaddr++; //not the first address in the subnet
        if (newaddr == addr) newaddr++; //if given address is equal to server address
        return newaddr;
    };

    auto isInRange = [this](quint32 address)
    {
        if (((!m_startAddress.isNull() && address >= m_startAddress.toIPv4Address()) &&
                (!m_stopAddress.isNull() && address <= m_stopAddress.toIPv4Address())) ||
                (m_startAddress.isNull() && m_stopAddress.isNull()))
            return true;
        return false;
    };

    QHostAddress reqAddr(requested);
    foreach (const DHCPTableEntry& entry, m_DHCPTable) {
        if (entry.first == chaddr) return entry.second;
    }
    if (m_DHCPTable.contains({chaddr, reqAddr})) return reqAddr;
    if (checkOffered && m_offeredAddressesTable.contains({chaddr, reqAddr})) return reqAddr;

    if (requested) {
        if (reqAddr.isInSubnet(m_address.ip(), m_address.prefixLength()))
            if (isAddressAvailable(requested, m_DHCPTable))
                if (!checkOffered || isAddressAvailable(requested, m_offeredAddressesTable))
                    if (isInRange(reqAddr.toIPv4Address()))
                        return reqAddr;
    }

    quint32 newaddr = getNewAddress();
    while (true)
    {
        if (isAddressAvailable(newaddr, m_DHCPTable)) {
            if (!checkOffered || isAddressAvailable(requested, m_offeredAddressesTable)) {
                QHostAddress retAddr(newaddr);
                if (retAddr.isInSubnet(m_address.ip(), m_address.prefixLength())) {
                    if (isInRange(newaddr)) {
                        return retAddr;
                    }
                }
                return QHostAddress();
            }
        }
        newaddr = getNewAddress(newaddr);
    }
}

QNetworkAddressEntry DHCPServer::getAddressEntry()
{
    QNetworkInterface interface;
    foreach (const QNetworkInterface& iface, QNetworkInterface::allInterfaces()) {
        if (iface.type() == QNetworkInterface::Loopback || iface.type() != QNetworkInterface::Ethernet)
            continue;
        interface = iface;
        break;
    }

    foreach (const QNetworkAddressEntry& entry, interface.addressEntries()) {
        if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol)
            return entry;
    }
    return QNetworkAddressEntry();
}

DHCPServer::DHCPServer(QObject *parent) : QObject(parent), m_address(getAddressEntry())
{

}

DHCPServer::DHCPServer(const QHostAddress &startAddress, const QHostAddress &stopAddress,
                       const QByteArray &serverName, int leaseTime, QObject *parent) :
    QObject(parent), m_startAddress(startAddress), m_stopAddress(stopAddress),
    m_serverName(serverName), m_leaseTime(leaseTime), m_address(getAddressEntry())
{

}

DHCPServer::DHCPServer(const QNetworkAddressEntry &address, const QHostAddress &startAddress,
                       const QHostAddress &stopAddress, const QByteArray &serverName, int leaseTime, QObject *parent) :
    QObject(parent), m_startAddress(startAddress), m_stopAddress(stopAddress), m_serverName(serverName),
    m_leaseTime(leaseTime), m_address(address)
{

}

DHCPServer::~DHCPServer()
{
    emit serverStopped();
}

template<typename T1, typename T2>
QByteArray DHCPServer::getBytes(T1 t1, T2)
{
    T2 number = qToBigEndian(static_cast<T2>(t1));
    return QByteArray(reinterpret_cast<const char*>(&number), sizeof(T2));
}
