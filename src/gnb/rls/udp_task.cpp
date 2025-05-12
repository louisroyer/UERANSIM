//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "udp_task.hpp"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <set>

#include <gnb/nts.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>
#include <utils/libc_error.hpp>

#include <gnb/ngap/task.hpp>   // <— pour NgapTask et findUeContext

static constexpr const int BUFFER_SIZE = 16384;

static constexpr const int LOOP_PERIOD = 1000;
static constexpr const int RECEIVE_TIMEOUT = 200;
static constexpr const int HEARTBEAT_THRESHOLD = 2000; // (LOOP_PERIOD + RECEIVE_TIMEOUT)'dan büyük olmalı

static constexpr const int MIN_ALLOWED_DBM = -120;

static int EstimateSimulatedDbm(const Vector3 &myPos, const Vector3 &uePos)
{
    int deltaX = myPos.x - uePos.x;
    int deltaY = myPos.y - uePos.y;
    int deltaZ = myPos.z - uePos.z;

    int distance = static_cast<int>(std::sqrt(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ));
    if (distance == 0)
        return -1; // 0 may be confusing for people
    return -distance;
}

namespace nr::gnb
{

RlsUdpTask::RlsUdpTask(TaskBase *base, uint64_t sti, Vector3 phyLocation)
    : m_base(base), m_server{}, m_ctlTask{}, m_sti{sti}, m_phyLocation{phyLocation}, m_lastLoop{}, m_stiToUe{}, m_ueMap{}, m_newIdCounter{}
{
    m_logger = base->logBase->makeUniqueLogger("rls-udp");

    try
    {
        m_server = new udp::UdpServer(base->config->linkIp, cons::RadioLinkPort);
    }
    catch (const LibError &e)
    {
        m_logger->err("RLS failure [%s]", e.what());
        quit();
        return;
    }
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
        heartbeatCycle(current);
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

void RlsUdpTask::updateStiToUe(uint64_t sti, int ueId)
{
    m_logger->debug("Remapping STI %llu → UE[%d] (handover)", sti, ueId);
    m_stiToUe[sti] = ueId;
}



int RlsUdpTask::getUeIdBySti(uint64_t sti) const
{
    auto it = m_stiToUe.find(sti);
    return it != m_stiToUe.end() ? it->second : -1;
}

std::optional<uint64_t> RlsUdpTask::getStiByUeId(int ueId) const
{
    auto it = m_ueMap.find(ueId);
    if (it != m_ueMap.end()) {
        return it->second.sti;
    }
    return std::nullopt;
}

void RlsUdpTask::setHandoverInProgress(bool active) {
    m_handoverInProgress = active;
}

void RlsUdpTask::clearStiMappingForUe(int ueId) {
    // Supprime toute entrée sti→ueId
    for (auto it = m_stiToUe.begin(); it != m_stiToUe.end(); ) {
        if (it->second == ueId) it = m_stiToUe.erase(it);
        else ++it;
    }
    // Supprime l’info UE (adresse, etc.)
    m_ueMap.erase(ueId);
}

void RlsUdpTask::receiveRlsPdu(const InetAddress &addr, std::unique_ptr<rls::RlsMessage> &&msg)
{
    if (msg->msgType == rls::EMessageType::HEARTBEAT)
    {
        int64_t now = utils::CurrentTimeMillis();
        int dbm = EstimateSimulatedDbm(m_phyLocation, ((const rls::RlsHeartBeat &)*msg).simPos);
        if (dbm < MIN_ALLOWED_DBM)
        {
            return; // Signal trop faible
        }
        m_logger->info("[HB] t=%lld  sti=%llu  dbm=%d  stiKnown=%d  hoPend=%d  mapSize=%zu",
            now,
            msg->sti,
            dbm,
            m_stiToUe.count(msg->sti) ? 1 : 0,
            /* y-a-t-il au moins un UE handoverPending ? */
            ([&]{
                for (auto &[_, ctx] : m_base->ngapTask->getAllUeContexts())
                    if (ctx && ctx->handoverPending) return 1;
                return 0;
            })(),
            m_stiToUe.size());


        // 1. Cas STI déjà connu → MAJ de l'adresse + association classique
        if (m_stiToUe.count(msg->sti))
        {
            int ueId = m_stiToUe[msg->sti];
            m_ueMap[ueId].sti = msg->sti;
            m_ueMap[ueId].address = addr;
            m_ueMap[ueId].lastSeen = utils::CurrentTimeMillis();
            m_logger->debug("STI[%llu] connu → UE[%d] tentative de mis à jour", msg->sti, ueId);

            // Gestion du flag handoverPending si encore actif
            auto *ngUe = m_base->ngapTask->getUeContext(ueId);
            if (ngUe && ngUe->handoverPending)
            {
                ngUe->handoverPending = false;
                ngUe->sti = msg->sti;

                m_logger->debug("STI[%llu] associé à UE[%d] (fin HO)", msg->sti, ueId);
            }
            else
            {
                if (!ngUe)
                    m_logger->warn("Impossible de récupérer le contexte NGAP pour UE[%d] depuis ueId=%d (STI=%llu)", ueId, ueId, msg->sti);
                else
                    m_logger->debug("UE[%d] trouvé mais pas en handoverPending (STI=%llu) → aucune action", ueId, msg->sti);
            }

        }
        else
        {
            // 2. Cas STI inconnu → cherche un UE avec handoverPending
            bool matchedHandover = false;

            const auto &ueCtxMap = m_base->ngapTask->getAllUeContexts();
            for (const auto &[ctxId, ctx] : ueCtxMap)
            {
                if (ctx && ctx->handoverPending)
                {
                    m_logger->info("[rls-udp] STI[%llu] reçu pour UE[%d] en handover → association établie", msg->sti, ctxId);
                    m_stiToUe[msg->sti] = ctxId;
                    m_ueMap[ctxId].address = addr;
                    m_ueMap[ctxId].lastSeen = utils::CurrentTimeMillis();
                    ctx->handoverPending = false;
                    ctx->sti = msg->sti;
                    matchedHandover = true;
                    break;
                }
                
            }

            if (!matchedHandover)
            {
                //3.1. Si on est en train d'exécuter un handover, on ne doit pas créer de nouvelle association
                if (m_handoverInProgress)
                {
                    m_logger->warn("[HB] STI inconnu et handover en cours → aucune action");
                    return; 
                }

                // 3.2. Cas normal → création d'un nouvel UE
                m_logger->warn("[HB] sti=%llu inconnu → tentative d’association", msg->sti);
                int ueId = ++m_newIdCounter;
                m_logger->debug("New UE id created : ueId=%d", ueId);
                m_stiToUe[msg->sti] = ueId;
                m_ueMap[ueId].address = addr;
                m_ueMap[ueId].lastSeen = utils::CurrentTimeMillis();

                m_logger->debug("New UE found from unknown STI: sti=%llu → ueId=%d", msg->sti, ueId);

                auto w = std::make_unique<NmGnbRlsToRls>(NmGnbRlsToRls::SIGNAL_DETECTED);
                w->ueId = ueId;
                m_ctlTask->push(std::move(w));
            }
        }

        // 4. Réponse Heartbeat dans tous les cas
        rls::RlsHeartBeatAck ack{m_sti};
        ack.dbm = dbm;
        sendRlsPdu(addr, ack);
        return;
    }

    // Si ce n’est pas un heartbeat mais que le STI est inconnu → on ignore
    if (!m_stiToUe.count(msg->sti))
    {
        return;
    }

    // Message RLS normal à transférer
    auto w = std::make_unique<NmGnbRlsToRls>(NmGnbRlsToRls::RECEIVE_RLS_MESSAGE);
    w->ueId = m_stiToUe[msg->sti];
    w->msg = std::move(msg);
    m_ctlTask->push(std::move(w));
}



void RlsUdpTask::sendRlsPdu(const InetAddress &addr, const rls::RlsMessage &msg)
{
    OctetString stream;
    rls::EncodeRlsMessage(msg, stream);

    m_server->Send(addr, stream.data(), static_cast<size_t>(stream.length()));
}

void RlsUdpTask::heartbeatCycle(int64_t time)
{
    std::set<int> lostUeId{};
    std::set<uint64_t> lostSti{};

    for (auto &item : m_ueMap)
    {
        if (time - item.second.lastSeen > HEARTBEAT_THRESHOLD)
        {
            lostUeId.insert(item.first);
            lostSti.insert(item.second.sti);
        }
    }

    for (uint64_t sti : lostSti)
        m_stiToUe.erase(sti);

    for (int ueId : lostUeId)
        m_ueMap.erase(ueId);

    for (int ueId : lostUeId)
    {
        auto w = std::make_unique<NmGnbRlsToRls>(NmGnbRlsToRls::SIGNAL_LOST);
        w->ueId = ueId;
        m_ctlTask->push(std::move(w));
    }
}

void RlsUdpTask::initialize(NtsTask *ctlTask)
{
    m_ctlTask = ctlTask;
}

void RlsUdpTask::send(int ueId, const rls::RlsMessage &msg)
{
    if (ueId == 0)
    {
        for (auto &ue : m_ueMap)
            send(ue.first, msg);
        return;
    }

    if (!m_ueMap.count(ueId))
    {
        // ignore the message
        return;
    }

    sendRlsPdu(m_ueMap[ueId].address, msg);
}



} // namespace nr::gnb
