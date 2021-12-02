//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "server.hpp"

#include <cstring>
#include <utils/common.hpp>

namespace udp
{

UdpServer::UdpServer(): socket4{Socket::CreateUdp4()}, socket6{Socket::CreateUdp6()}
{
}

UdpServer::UdpServer(const std::string &address, uint16_t port) : socket4{}, socket6{}
{
    if (utils::GetIpVersion(address) == 4)
        socket4 = Socket::CreateAndBindUdp({address, port});
    else
        socket6 = Socket::CreateAndBindUdp({address, port});

}

int UdpServer::Receive(uint8_t *buffer, size_t bufferSize, int timeoutMs, InetAddress &outPeerAddress) const
{
    if (outPeerAddress.getIpVersion() == 4)
        return socket4.receive(buffer, bufferSize, timeoutMs, outPeerAddress);
    else
        return socket6.receive(buffer, bufferSize, timeoutMs, outPeerAddress);
}

void UdpServer::Send(const InetAddress &address, const uint8_t *buffer, size_t bufferSize) const
{

    if (address.getIpVersion() == 4)
        socket4.send(address, buffer, bufferSize);
    else
        socket6.send(address, buffer, bufferSize);
}

UdpServer::~UdpServer()
{
    socket4.close();
    socket6.close();
}

} // namespace udp
