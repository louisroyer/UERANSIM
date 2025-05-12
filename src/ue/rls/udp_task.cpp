//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "udp_task.hpp"

#include <cstdint>
#include <cstring>
#include <set>

#include <ue/nts.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>
#include <arpa/inet.h>     // Pour inet_ntop
#include <netinet/in.h>    // Pour sockaddr_in / sockaddr_in6
#include <cstring>         // Pour memset éventuellement


static constexpr const int BUFFER_SIZE = 16384;
static constexpr const int LOOP_PERIOD = 1000;
static constexpr const int RECEIVE_TIMEOUT = 200;
static constexpr const int HEARTBEAT_THRESHOLD = 2000; // (LOOP_PERIOD + RECEIVE_TIMEOUT)'dan büyük olmalı




namespace nr::ue
{

RlsUdpTask::RlsUdpTask(TaskBase *base, RlsSharedContext *shCtx, const std::vector<std::string> &searchSpace)
    : m_server{}, m_ctlTask{}, m_shCtx{shCtx}, m_searchSpace{}, m_cells{}, m_cellIdToSti{}, m_lastLoop{},
      m_cellIdCounter{}
{
    m_logger = base->logBase->makeUniqueLogger(base->config->getLoggerPrefix() + "rls-udp");

    m_server = new udp::UdpServer();

    for (auto &ip : searchSpace)
        m_searchSpace.emplace_back(ip, cons::RadioLinkPort);

    m_simPos = Vector3{};
}

void RlsUdpTask::onStart()
{
}

void RlsUdpTask::onLoop()
{
    auto current = utils::CurrentTimeMillis();
    if (current - m_lastLoop > LOOP_PERIOD)
    {
        m_lastLoop = current;
        heartbeatCycle(current, m_simPos);
    }

    uint8_t buffer[BUFFER_SIZE];
    InetAddress peerAddress;

    int size = m_server->Receive(buffer, BUFFER_SIZE, RECEIVE_TIMEOUT, peerAddress);
    if (size > 0)
    {
        auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer, static_cast<size_t>(size)});
        if (rlsMsg == nullptr)
            m_logger->err("Unable to decode RLS message");
        else
            receiveRlsPdu(peerAddress, std::move(rlsMsg));
    }
}

void RlsUdpTask::onQuit()
{
    delete m_server;
}

void RlsUdpTask::sendRlsPdu(const InetAddress &addr, const rls::RlsMessage &msg)
{
    OctetString stream;
    rls::EncodeRlsMessage(msg, stream);

    m_server->Send(addr, stream.data(), static_cast<size_t>(stream.length()));
}

void RlsUdpTask::send(int cellId, const rls::RlsMessage &msg)
{
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        // LOG IP SOURCE
        char ipStr[INET6_ADDRSTRLEN] = {};
        auto *sockaddr6 = reinterpret_cast<const sockaddr_in6 *>(m_cells[sti].address.getSockAddr());
        inet_ntop(AF_INET6, &(sockaddr6->sin6_addr), ipStr, sizeof(ipStr));
        m_logger->debug("Sending Message to cellId[%d] sti[%lu] ip[%s]", cellId, sti, ipStr);
        // FIN LOG IP SOURCE
        sendRlsPdu(m_cells[sti].address, msg);
    }
}

void RlsUdpTask::receiveRlsPdu(const InetAddress &addr, std::unique_ptr<rls::RlsMessage> &&msg)
{
    if (msg->msgType == rls::EMessageType::HEARTBEAT_ACK)
    {
         // === LOG IP SOURCE ===
        // char ipStr[INET6_ADDRSTRLEN] = {};
        // const sockaddr *sa = addr.getSockAddr();

        // if (sa->sa_family == AF_INET)
        // {
        //     inet_ntop(AF_INET, &(((sockaddr_in *)sa)->sin_addr), ipStr, sizeof(ipStr));
        // }
        // else if (sa->sa_family == AF_INET6)
        // {
        //     inet_ntop(AF_INET6, &(((sockaddr_in6 *)sa)->sin6_addr), ipStr, sizeof(ipStr));
        // }

        // m_logger->info("Heartbeat reçu de {%s\n}", ipStr);

        // m_logger->info("HEARTBEAT_ACK received avec sti [%lu], dbm [%d]", msg->sti, ((const rls::RlsHeartBeatAck &)*msg).dbm);
        
        
        
        if (!m_cells.count(msg->sti))
        {
            m_cells[msg->sti].cellId = ++m_cellIdCounter;
            m_cellIdToSti[m_cells[msg->sti].cellId] = msg->sti;
        }

        int oldDbm = INT32_MIN;
        if (m_cells.count(msg->sti))
            oldDbm = m_cells[msg->sti].dbm;

        m_cells[msg->sti].address = addr;
        m_cells[msg->sti].lastSeen = utils::CurrentTimeMillis();

        int newDbm = ((const rls::RlsHeartBeatAck &)*msg).dbm;
        m_cells[msg->sti].dbm = newDbm;

        if (oldDbm != newDbm)
            onSignalChangeOrLost(m_cells[msg->sti].cellId);
        return;
    }

    if (!m_cells.count(msg->sti))
    {
        // if no HB-ACK received yet, and the message is not HB-ACK, then ignore the message
        return;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::RECEIVE_RLS_MESSAGE);
    w->cellId = m_cells[msg->sti].cellId;
    w->msg = std::move(msg);
    m_ctlTask->push(std::move(w));
}

void RlsUdpTask::onSignalChangeOrLost(int cellId)
{
    int dbm = INT32_MIN;
    m_logger->debug("[RLS]Signal changed for cell[%d]", cellId);
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        m_logger->debug("ACK reçu pour cellId=%d → sti=%u", cellId, sti);
        dbm = m_cells[sti].dbm;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::SIGNAL_CHANGED);
    w->cellId = cellId;
    w->dbm = dbm;
    m_ctlTask->push(std::move(w));
}

void RlsUdpTask::heartbeatCycle(uint64_t time, const Vector3 &simPos)
{
    std::set<std::pair<uint64_t, int>> toRemove;
    static bool     firstWindow      = true;
    static uint64_t firstWindowStart = 0;

    for (auto &cell : m_cells)
    {
        auto delta = time - cell.second.lastSeen;
        if (delta > HEARTBEAT_THRESHOLD)
            toRemove.insert({cell.first, cell.second.cellId});
    }
    for (auto cell : toRemove)
    {
        m_cells.erase(cell.first);
        m_cellIdToSti.erase(cell.second);
    }
    for (auto cell : toRemove)
        onSignalChangeOrLost(cell.second);
    
    if (firstWindow && !m_searchSpace.empty()) {
        if (firstWindowStart == 0)     // premier passage
            firstWindowStart = time;   // mémorise le début

        // HB uniquement vers le tout premier gNB
        rls::RlsHeartBeat hb{m_shCtx->sti}; 
        hb.simPos = simPos;
        sendRlsPdu(m_searchSpace.front(), hb);

        if (time - firstWindowStart >= 500)
            firstWindow = false;       // fenêtre terminée
    }
    else 
    {
        // diffusion normale à tous les gNB
        for (auto &addr : m_searchSpace)
        {
            rls::RlsHeartBeat msg{m_shCtx->sti};
            msg.simPos = simPos;
            sendRlsPdu(addr, msg);
        }
    }
    
    // if (!m_searchSpace.empty())
    // {
    // rls::RlsHeartBeat msg{m_shCtx->sti};
    // msg.simPos = simPos;
    // sendRlsPdu(m_searchSpace[0], msg);  // uniquement le premier gNB
    // }   
    // else
    // {
    //     m_logger->err("No search space found");
    // }
}

void RlsUdpTask::initialize(NtsTask *ctlTask)
{
    m_ctlTask = ctlTask;
}

} // namespace nr::ue
