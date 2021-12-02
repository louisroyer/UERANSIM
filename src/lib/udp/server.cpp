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

UdpServer::UdpServer(): socket4{Socket::CreateUdp4()}, socket6{Socket::CreateUdp6()},
    isSocket4Binded{true}, isSocket6Binded{true}, socketRoundRobin{false}
{
}

UdpServer::UdpServer(const std::string &address, uint16_t port) : socket4{}, socket6{},
    isSocket4Binded{false}, isSocket6Binded{true}, socketRoundRobin{false}
{
    if (utils::GetIpVersion(address) == 4)
    {
        socket4 = Socket::CreateAndBindUdp({address, port});
        isSocket4Binded = true;
    }
    else
    {
        socket6 = Socket::CreateAndBindUdp({address, port});
        isSocket6Binded = true;
    }

}

int UdpServer::Receive(uint8_t *buffer, size_t bufferSize, int timeoutMs, InetAddress &outPeerAddress)
{
    // If UdpServer has 2 sockets binded (1 on IPv4 and 1 on IPv6), timeout is halfed because we want
    // the function to return before timeout is reached.
    // To avoid starvation, each time this function get called the socket checked first is not the same as last time.
    // (Starvation would have occured for the socket checked in second if the socket checked first always has a message)
    int ret = 0;
    Socket firstSocket = socketRoundRobin? socket4 : socket6;
    bool isFirstSocketBinded = socketRoundRobin? isSocket4Binded : isSocket6Binded;
    Socket secondSocket = socketRoundRobin? socket6 : socket4;
    bool isSecondSocketBinded = socketRoundRobin? isSocket6Binded : isSocket4Binded;
    socketRoundRobin = !socketRoundRobin;
    if (isFirstSocketBinded)
        ret = firstSocket.receive(buffer, bufferSize, (isSocket4Binded && isSocket6Binded) ? (timeoutMs / 2) : timeoutMs, outPeerAddress);
    if ((!ret) && isSecondSocketBinded)
        ret = secondSocket.receive(buffer, bufferSize, (isSocket4Binded && isSocket6Binded) ? (timeoutMs / 2) : timeoutMs, outPeerAddress);
    return ret;
}

void UdpServer::Send(const InetAddress &address, const uint8_t *buffer, size_t bufferSize) const
{

    if ((address.getIpVersion() == 4) && isSocket4Binded)
        socket4.send(address, buffer, bufferSize);
    else if ((address.getIpVersion() == 6) && isSocket6Binded)
        socket6.send(address, buffer, bufferSize);
}

UdpServer::~UdpServer()
{
    if (isSocket4Binded)
        socket4.close();
    if (isSocket6Binded)
        socket6.close();
}

} // namespace udp
