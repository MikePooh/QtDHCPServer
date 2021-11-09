#include <QCoreApplication>
#include "dhcpserver.h"
#include "QHostAddress"
#include "QTimer"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QNetworkInterface interface;
    foreach (const QNetworkInterface& iface, QNetworkInterface::allInterfaces()) {
        if (iface.type() == QNetworkInterface::Loopback || iface.type() != QNetworkInterface::Ethernet)
            continue;
        interface = iface;
        break;
    }

    QNetworkAddressEntry address;

    foreach (const QNetworkAddressEntry& entry, interface.addressEntries()) {
        if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol)
            address = entry;
    }

    DHCPServer server(address, QHostAddress("192.168.0.49"), QHostAddress("192.168.0.60"),
                      "Trombon IP DHCP Server", 600, &a);    
    QObject::connect(&server, &DHCPServer::serverStarted, [](const QHostAddress& addr, const QHostAddress& mask, int pref){ qDebug() << addr << mask << pref; });
    QObject::connect(&server, &DHCPServer::dhcpMessageReveived, [](DHCPServer::DHCPMessageType type, const QByteArray& from){ qDebug() << static_cast<int>(type) << from; });
    QObject::connect(&server, &DHCPServer::dhcpAddressAssigned, [&server](const QByteArray& chaddr, const QHostAddress& address){ qDebug() << "Address assigned" << chaddr << address << server.getDhcpTable(); });
    QObject::connect(&server, &DHCPServer::serverStopped, []{ qDebug() << "Server stopped";});
    if (!server.initializeDHCPServer()) {
        qDebug() << "Unable to open DHCP port 67. Did you forget sudo?";
        return 1;
    }
    QTimer::singleShot(0, &server, [&server]{ qDebug() << "Is running" << server.isRunning(); });
    QTimer::singleShot(3000, &server, &DHCPServer::stopDHCPServer);
    QTimer::singleShot(5000, &server, [&server]{ qDebug() << "Is running" << server.isRunning(); });
    return a.exec();
//    return 0;
}
