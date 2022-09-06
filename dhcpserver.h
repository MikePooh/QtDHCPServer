#ifndef DHCPSERVER_H
#define DHCPSERVER_H

#include <QHostAddress>
#include <QUdpSocket>
#include <QNetworkAddressEntry>

class DHCPServer : public QObject
{
    Q_OBJECT

public:

    enum class OpValue
    {
        NONE = 0,
        BOOTREQUEST = 1,
        BOOTREPLY = 2
    };

    enum class DHCPOption
    {
        NONE = 0,
        DHCPRequestAddress = 50,
        DHCPLeaseTime = 51,
        DHCPMessageType = 53,
        DHCPServerIdentifier = 54,
        END = 255
    };

    enum class DHCPMessageType
    {
        NONE = 0,
        DISCOVER = 1,
        OFFER = 2,
        REQUEST = 3,
        DECLINE = 4,
        ACK = 5,
        NAK = 6,
        RELEASE = 7,
        INFORM = 8
    };

    typedef QPair<DHCPOption, QByteArray> Option;
    typedef QPair<QByteArray, QHostAddress> DHCPTableEntry;

private:

    struct DHCPMessage
    {
        quint8 op = 0;
        quint8 htype = 0;
        quint8 hlen = 0;
        quint8 hops = 0;
        QByteArray xid;
        quint16 secs = 0;
        QByteArray flags;
        quint32 ciaddr = 0;
        quint32 yiaddr = 0;
        quint32 siaddr = 0;
        quint32 giaddr = 0;
        QByteArray chaddr;
        QByteArray sname;
        QByteArray file;
        QVector<Option> options;
    };

    const QByteArray magicCookies = QByteArray::fromHex("63825363");

    const quint16 dhcpServerPort = 67;
    const quint16 dhcpClientPort = 68;    

    QUdpSocket m_socket;
    const QHostAddress m_startAddress;
    const QHostAddress m_stopAddress;
    const QByteArray m_serverName = "DHCP Server";
    const int m_leaseTime = 3600;

    const QNetworkAddressEntry m_address;
    quint32 mask() const;
    quint32 revMask() const;

    QVector<DHCPTableEntry> m_DHCPTable;
    QVector<DHCPTableEntry> m_offeredAddressesTable;

    void parseDatagram(const QByteArray& datagram);

    void handleDhcpDiscover(const DHCPMessage& request);
    void handleDhcpRequest(const DHCPMessage& request);
    void handleDhcpDecline(const DHCPMessage& request);
    void handleDhcpRelease(const DHCPMessage& request);
    void handleDhcpInform(const DHCPMessage& request);

    void makePacket(const DHCPMessage& response, QByteArray& result);
    QHostAddress getAddress(quint32 requested = 0, const QByteArray& chaddr = QByteArray(), bool checkOffered = false);
    template<typename T1, typename T2>
    QByteArray getBytes(T1 t1, T2);

public:

    explicit DHCPServer(QObject *parent = nullptr);
    explicit DHCPServer(const QNetworkAddressEntry &address, QObject *parent = nullptr);
    explicit DHCPServer(const QHostAddress& startAddress = QHostAddress(),
                        const QHostAddress& stopAddress = QHostAddress(),
                        const QByteArray& serverName = "DHCP Server",
                        int leaseTime = 3600, QObject* parent = nullptr);
    explicit DHCPServer(const QNetworkAddressEntry& address, const QHostAddress& startAddress = QHostAddress(),
                        const QHostAddress& stopAddress = QHostAddress(),
                        const QByteArray& serverName = "DHCP Server",
                        int leaseTime = 3600, QObject* parent = nullptr);

    virtual ~DHCPServer() override;
    static QNetworkAddressEntry getAddressEntry();
    bool initializeDHCPServer();
    QVector<DHCPTableEntry> getDhcpTable();
    bool isRunning();
    void stopDHCPServer();
    QString getStartAddressStr();
    QString getStopAddressStr();

signals:

    void serverStarted(const QHostAddress& address, const QHostAddress& mask, int prefixLength);
    void serverStopped();
    void dhcpDatagramReceived(const QByteArray& datagram);
    void dhcpMessageReveived(DHCPMessageType type, const QByteArray& from);
    void dhcpAddressOffered(const QByteArray& chaddr, const QHostAddress& addr);
    void dhcpAddressAssigned(const QByteArray& chaddr, const QHostAddress& addr);
};

#endif // DHCPSERVER_H
