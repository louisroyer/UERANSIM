//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "encode.hpp"
#include "task.hpp"
#include "utils.hpp"

#include <gnb/rrc/task.hpp>

#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_HandoverRequired.h>
#include <asn/ngap/ASN_NGAP_HandoverRequest.h>
#include <asn/ngap/ASN_NGAP_HandoverPreparationFailure.h>
#include <asn/ngap/ASN_NGAP_HandoverRequestAcknowledge.h>
#include <asn/ngap/ASN_NGAP_HandoverCommand.h>

#include <asn/ngap/ASN_NGAP_GlobalGNB-ID.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceItemHORqd.h>
#include <gnb/gtp/task.hpp>

#include <asn/ngap/ASN_NGAP_TargetRANNodeID.h>
#include <asn/ngap/ASN_NGAP_SourceToTarget-TransparentContainer.h>
#include <asn/ngap/ASN_NGAP_SourceNGRANNode-ToTargetNGRANNode-TransparentContainer.h>
#include <asn/rrc/ASN_RRC_HandoverPreparationInformation.h>
#include <asn/rrc/ASN_RRC_HandoverPreparationInformation-IEs.h>
#include <asn/rrc/ASN_RRC_UE-CapabilityRAT-ContainerList.h>
#include <asn/ngap/ASN_NGAP_NGRAN-CGI.h>
#include <lib/rrc/encode.hpp>

#include <asn/ngap/ASN_NGAP_ErrorIndication.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_DirectForwardingPathAvailability.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupItemHOReq.h>

#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupRequestTransfer.h>
#include <asn/ngap/ASN_NGAP_HandoverRequestAcknowledgeTransfer.h>
#include <asn/ngap/ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer.h>

#include <asn/ngap/ASN_NGAP_PDUSessionResourceAdmittedList.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceAdmittedItem.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceFailedToSetupListHOAck.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck.h>
#include <asn/ngap/ASN_NGAP_GTPTunnel.h>
#include <asn/ngap/ASN_NGAP_QosFlowItemWithDataForwarding.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestList.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>

#include <asn/ngap/ASN_NGAP_HandoverNotify.h>

namespace nr::gnb
{

void NgapTask::sendHandoverRequired(int ueId, int gnbTargetID)
{
    auto *ueCtx = findUeByRanId(ueId);
    if (ueCtx == nullptr)
    {
        m_logger->err("Could not find UE context[%d]", ueId);
        return;
    }

    if (ueCtx->pduSessions.empty())
    {
        m_logger->err("No PDU session found for UE[%d]", ueId);
        return;
    }

    auto *amfCtx = findAmfContext(ueCtx->associatedAmfId);
    if (amfCtx == nullptr)
    {
        m_logger->err("Could not find AMF context[%d]", ueCtx->associatedAmfId);
        return;
    }

    // Message type: Handover
    std::vector<ASN_NGAP_HandoverRequiredIEs*> ies;

    // Handover Type
    auto *ieHandoverType = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieHandoverType->id = ASN_NGAP_ProtocolIE_ID_id_HandoverType;
    ieHandoverType->criticality = ASN_NGAP_Criticality_reject;
    ieHandoverType->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_HandoverType;
    ieHandoverType->value.choice.HandoverType = ASN_NGAP_HandoverType_intra5gs;
    ies.push_back(ieHandoverType);

    // Cause
    auto *ieCause = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(NgapCause::RadioNetwork_unspecified, ieCause->value.choice.Cause);
    ies.push_back(ieCause);

    // Target ID
    auto *ieTargetId = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieTargetId->id = ASN_NGAP_ProtocolIE_ID_id_TargetID;
    ieTargetId->criticality = ASN_NGAP_Criticality_reject;
    ieTargetId->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_TargetID;

    ieTargetId->value.choice.TargetID.present = ASN_NGAP_TargetID_PR_targetRANNodeID;
    ieTargetId->value.choice.TargetID.choice.targetRANNodeID = asn::New<ASN_NGAP_TargetRANNodeID>();
    ieTargetId->value.choice.TargetID.choice.targetRANNodeID->globalRANNodeID.present = ASN_NGAP_GlobalRANNodeID_PR_globalGNB_ID;

    auto *globalGnbId = asn::New<ASN_NGAP_GlobalGNB_ID>();
    globalGnbId->gNB_ID.present = ASN_NGAP_GNB_ID_PR_gNB_ID;
    asn::SetBitString(globalGnbId->gNB_ID.choice.gNB_ID,
                      octet4{gnbTargetID << (32 - m_base->config->gnbIdLength)},
                      static_cast<size_t>(m_base->config->gnbIdLength));
    asn::SetOctetString3(globalGnbId->pLMNIdentity, ngap_utils::PlmnToOctet3(m_base->config->plmn));

    ieTargetId->value.choice.TargetID.choice.targetRANNodeID->globalRANNodeID.choice.globalGNB_ID = globalGnbId;

    asn::SetOctetString3(ieTargetId->value.choice.TargetID.choice.targetRANNodeID->selectedTAI.pLMNIdentity, ngap_utils::PlmnToOctet3(m_base->config->plmn));
    asn::SetOctetString3(ieTargetId->value.choice.TargetID.choice.targetRANNodeID->selectedTAI.tAC, octet3{m_base->config->tac});

    ies.push_back(ieTargetId);

    // PDU Session Resource List
    auto *iePduSessionList = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    iePduSessionList->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceListHORqd;
    iePduSessionList->criticality = ASN_NGAP_Criticality_reject;
    iePduSessionList->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_PDUSessionResourceListHORqd;

    for (int psi : ueCtx->pduSessions)
    {
        auto *sessionItem = asn::New<ASN_NGAP_PDUSessionResourceItemHORqd>();
        sessionItem->pDUSessionID = static_cast<ASN_NGAP_PDUSessionID_t>(psi);
        asn::SetOctetString1(sessionItem->handoverRequiredTransfer, static_cast<uint8_t>(ASN_NGAP_DirectForwardingPathAvailability_direct_path_available));
        asn::SequenceAdd(iePduSessionList->value.choice.PDUSessionResourceListHORqd, sessionItem);
        // Handover Required Transfer
    }

    ies.push_back(iePduSessionList);


    // Source To Target Transparent Container
    auto *ieSourceToTargetTransparentContainer = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieSourceToTargetTransparentContainer->id = ASN_NGAP_ProtocolIE_ID_id_SourceToTarget_TransparentContainer;
    ieSourceToTargetTransparentContainer->criticality = ASN_NGAP_Criticality_reject;
    ieSourceToTargetTransparentContainer->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_SourceToTarget_TransparentContainer;

    // temporary
    asn::SetOctetString4(ieSourceToTargetTransparentContainer->value.choice.SourceToTarget_TransparentContainer, static_cast<octet4>(ueId));

    // Source NG-RAN Node to Target NG-RAN Node Transparent Container
    //auto *container = asn::New<ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer>();
    //auto *handoverPreparationInfos = asn::New<ASN_RRC_HandoverPreparationInformation>();
    //handoverPreparationInfos->criticalExtensions.present = ASN_RRC_HandoverPreparationInformation__criticalExtensions_PR_c1;
    //handoverPreparationInfos->criticalExtensions.choice.c1 = asn::New<ASN_RRC_HandoverPreparationInformation::ASN_RRC_HandoverPreparationInformation__criticalExtensions::ASN_RRC_HandoverPreparationInformation__ASN_RRC_criticalExtensions_u::ASN_RRC_HandoverPreparationInformation__criticalExtensions__c1>();
    //handoverPreparationInfos->criticalExtensions.choice.c1->present = ASN_RRC_HandoverPreparationInformation__criticalExtensions__c1_PR_handoverPreparationInformation;

    //handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation = asn::New<ASN_RRC_HandoverPreparationInformation_IEs>();
    //handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation->ue_CapabilityRAT_List = ASN_RRC_UE_CapabilityRAT_ContainerList;
    //handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation->ue_CapabilityRAT_List.list = //TODO: empty list;

    //asn_fprint(stdout, &asn_DEF_ASN_RRC_HandoverPreparationInformation, handoverPreparationInfos);
    //OctetString handoverEncode = rrc::encode::EncodeS(asn_DEF_ASN_RRC_HandoverPreparationInformation, handoverPreparationInfos);

    //if (handoverEncode.length() == 0)
    //    throw std::runtime_error("HandoverPreparationInformation encoding failed");

    //asn::Free(asn_DEF_ASN_RRC_HandoverPreparationInformation, handoverPreparationInfos);
    //asn::SetOctetString(container->rRCContainer, handoverEncode);

    //auto list = container->pDUSessionResourceInformationList;
    //for (int psi : ueCtx->pduSessions)
    //{
        //TODO ajouter le pduSessionIdet le QFI
    //}

    //auto targetCell_ID = container->targetCell_ID = asn::New<ASN_NGAP_NGRAN_CGI>();
    // TODO: nrCGI, plmnid, nrcellid
                                              //
    //targetCell_ID->present = ASN_NGAP_NGRAN_CGI_PR_nR_CGI;
    //container->uEHistoryInformation; // TODO: lastvisitedcell

    //asn_fprint(stdout, &asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);
    //OctetString encodedContainer = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);

    //if (encodedContainer.length() == 0)
    //    throw std::runtime_error("SourceNGRANNode_ToTargetNGRANNode_TransparentContainer encoding failed");

    //asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);
    //asn::SetOctetString(ieSourceToTargetTransparentContainer->value.choice.SourceToTarget_TransparentContainer, encodedContainer);


    ies.push_back(ieSourceToTargetTransparentContainer);
    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequired>(ies);

    m_logger->debug("Sending Handover Required request");
    sendNgapUeAssociated(ueId, pdu);
}

void NgapTask::receiveHandoverRequest(int amfId, ASN_NGAP_HandoverRequest *msg)
{
    m_logger->debug("Handover request message received from AMF");

    auto *reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID);
    if (reqIe)
    {
        auto ueId= static_cast<int>(asn::GetUnsigned64(reqIe->AMF_UE_NGAP_ID ));
        int ueRanId={};

        if (m_ueCtx.count(ueId))
        {
            m_logger->err("UE context[%d] already exists", ueId);
            return;
        }
        // Creating new context for ue
        int32_t sst = -1; // FIXME: init SST with the actual value
        createUeContext(ueId, sst);
        auto *ue = findUeContext(ueId);
        if (ue == nullptr)
            return;
        ue->amfUeNgapId = ueId;

        /* (optionnal ?? )
          auto *amfCtx = findAmfContext(ue->associatedAmfId);
          if (amfCtx == nullptr)
            return;
            amfCtx->nextStream = (amfCtx->nextStream + 1) % amfCtx->association.outStreams;
        if ((amfCtx->nextStream == 0) && (amfCtx->association.outStreams > 1))
            amfCtx->nextStream += 1;
        ue-> uplinkStream = amfCtx->nextStream;

        */

        // adding Ue Bit rate informations to Ue context
        reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_UEAggregateMaximumBitRate);
        if (reqIe)
        {
            ue->ueAmbr.dlAmbr = asn::GetUnsigned64(reqIe->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateDL) / 8ull;
            ue-> ueAmbr.ulAmbr = asn::GetUnsigned64(reqIe->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateUL) / 8ull;
        }

        // sourceToTargetTransparentContainer
        reqIe=asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_SourceToTarget_TransparentContainer);
        if (reqIe)
        {
            ueRanId = static_cast<int>(asn::GetOctet4(reqIe->SourceToTarget_TransparentContainer));
        }

        // notify gtp task for new Ue
        auto w = std::make_unique<NmGnbNgapToGtp>(NmGnbNgapToGtp::UE_CONTEXT_UPDATE);
        w->update = std::make_unique<GtpUeContextUpdate>(true, ueRanId, ue->ueAmbr);
        m_base->gtpTask->push(std::move(w));
        std::vector<ASN_NGAP_HandoverRequestAcknowledgeIEs*> responseIes;

        // Handover PDU Session Resource Allocation

        std::vector<ASN_NGAP_PDUSessionResourceAdmittedItem*> successList;
        std::vector<ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck *> failedList;

        reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListHOReq);
        if (reqIe)
        {
            auto &list = reqIe->PDUSessionResourceSetupListHOReq.list;
            for (int i = 0; i < list.count; i++)
            {
                auto &item = list.array[i];
                auto *transfer = ngap_encode::Decode<ASN_NGAP_PDUSessionResourceSetupRequestTransfer>(
                asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, item->handoverRequestTransfer); // à voir aussi
                if (transfer == nullptr)
                {
                    m_logger->err("Unable to decode a PDU Session Resource Setup Request Transfer. Ignoring the relevant item");
                    asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer);
                    continue;
                }
                // Ressource allocation for each PDU Session
                auto *resource = new PduSessionResource(ueRanId, static_cast<int>(item->pDUSessionID));

                auto *ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate);
                if (ie)
                {
                    resource->sessionAmbr.dlAmbr = asn::GetUnsigned64(ie->PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL) / 8ull;
                    resource->sessionAmbr.ulAmbr = asn::GetUnsigned64(ie->PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL) / 8ull;
                }
                ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_DataForwardingNotPossible);
                if (ie)
                    resource->dataForwardingNotPossible = true;

                ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_PDUSessionType);
                if (ie)
                    resource->sessionType = ngap_utils::PduSessionTypeFromAsn(ie->PDUSessionType);

                ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation);
                if (ie)
                {
                    resource->upTunnel.teid = (uint32_t)asn::GetOctet4(ie->UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID);
                    resource->upTunnel.address = asn::GetOctetString(ie->UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress);
                }

                ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList);
                if (ie)
                {
                    auto *ptr = asn::New<ASN_NGAP_QosFlowSetupRequestList>();
                    asn::DeepCopy(asn_DEF_ASN_NGAP_QosFlowSetupRequestList, ie->QosFlowSetupRequestList, ptr);
                    resource->qosFlows = asn::WrapUnique(ptr, asn_DEF_ASN_NGAP_QosFlowSetupRequestList);
                }

                auto error = setupPduSessionResource(ue, resource);
                if (error.has_value())
                {
                    auto *tr = asn::New<ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer>();
                    ngap_utils::ToCauseAsn_Ref(error.value(), tr->cause);
                    OctetString encodedTr = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer, tr);
                    if (encodedTr.length() == 0)
                        throw std::runtime_error("HandoverResourceAllocationUnsuccessfulTransfer encoding failed");

                    asn::Free(asn_DEF_ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer, tr);
                    auto *res = asn::New<ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck>();
                    res->pDUSessionID = resource->psi;
                    asn::SetOctetString(res->handoverResourceAllocationUnsuccessfulTransfer, encodedTr);
                    failedList.push_back(res);
                }
                else
                {
                    auto *tr = asn::New<ASN_NGAP_HandoverRequestAcknowledgeTransfer >();

                    auto &upInfo = tr->dL_NGU_UP_TNLInformation;
                    upInfo.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
                    upInfo.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
                    asn::SetBitString(upInfo.choice.gTPTunnel->transportLayerAddress, resource->downTunnel.address);
                    asn::SetOctetString4(upInfo.choice.gTPTunnel->gTP_TEID, (octet4)resource->downTunnel.teid);

                    auto &dlForwardingUpTnlInformation = tr->dLForwardingUP_TNLInformation = asn::New<ASN_NGAP_UPTransportLayerInformation>();
                    dlForwardingUpTnlInformation->present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
                    dlForwardingUpTnlInformation->choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
                    asn::SetBitString(dlForwardingUpTnlInformation->choice.gTPTunnel->transportLayerAddress, resource->downTunnel.address);
                    asn::SetOctetString4(dlForwardingUpTnlInformation->choice.gTPTunnel->gTP_TEID, (octet4)resource->downTunnel.teid);

                    auto &qosList = resource->qosFlows->list;
                    for (int iQos = 0; iQos < qosList.count; iQos++)
                    {
                        auto *QosFlowItemWithDataForwarding = asn::New<ASN_NGAP_QosFlowItemWithDataForwarding>();
                        QosFlowItemWithDataForwarding->qosFlowIdentifier = qosList.array[iQos] -> qosFlowIdentifier;
                        asn::SequenceAdd(tr->qosFlowSetupResponseList, QosFlowItemWithDataForwarding);
                    }

                    OctetString encodedTr = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_HandoverRequestAcknowledgeTransfer, tr);
                    if (encodedTr.length() == 0)
                        throw std::runtime_error("HandoverRequestAcknowledgeTransfer encoding failed");

                    asn::Free(asn_DEF_ASN_NGAP_HandoverRequestAcknowledgeTransfer, tr);
                    auto *res = asn::New<ASN_NGAP_PDUSessionResourceAdmittedItem>();
                    res->pDUSessionID = static_cast<ASN_NGAP_PDUSessionID_t>(resource->psi);
                    asn::SetOctetString(res->handoverRequestAcknowledgeTransfer, encodedTr);
                    successList.push_back(res);
                    asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer); // à verifier
                }
            }
        }

        if (!successList.empty())
        {
            auto *ie = asn::New<ASN_NGAP_HandoverRequestAcknowledgeIEs>();
            ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceAdmittedList;
            ie->criticality = ASN_NGAP_Criticality_ignore;
            ie->value.present = ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceAdmittedList;

            for (auto &item : successList)
                asn::SequenceAdd(ie->value.choice.PDUSessionResourceAdmittedList, item);

            responseIes.push_back(ie);
        }

        if (!failedList.empty())
        {
            auto *ie = asn::New<ASN_NGAP_HandoverRequestAcknowledgeIEs>();
            ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListHOAck;
            ie->criticality = ASN_NGAP_Criticality_ignore;
            ie->value.present = ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceFailedToSetupListHOAck;

            for (auto &item : failedList)
                asn::SequenceAdd(ie->value.choice.PDUSessionResourceFailedToSetupListHOAck, item);

            responseIes.push_back(ie);
        }

        // adding other Ies for response

        // TargetToSource_TransparentContainer
        auto *ieTargetToSourceTransparentContainer = asn::New<ASN_NGAP_HandoverRequestAcknowledgeIEs>();
        ieTargetToSourceTransparentContainer->id = ASN_NGAP_ProtocolIE_ID_id_TargetToSource_TransparentContainer;
        ieTargetToSourceTransparentContainer->criticality = ASN_NGAP_Criticality_reject;
        ieTargetToSourceTransparentContainer->value.present = ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_TargetToSource_TransparentContainer;
        asn::SetOctetString4(ieTargetToSourceTransparentContainer->value.choice.TargetToSource_TransparentContainer, static_cast<octet4>(m_base->config->getGnbId()));
        responseIes.push_back(ieTargetToSourceTransparentContainer);

        // send HandoverRequestACK
        m_logger->debug("Sending handover request ACK to AMF");
        auto *response = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequestAcknowledge>(responseIes);
        sendNgapUeAssociated(ue->ctxId, response);
    }
}

void NgapTask::receiveHandoverCommand(int amfId, ASN_NGAP_HandoverCommand * msg)
{
    m_logger->debug("Handover Command message received from AMF");
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
    {
        m_logger->debug("Cannot find UE context[%d]", ue->ctxId);
        return;
    }

    // extracting information from targetToSourceTransparentContainer
    auto reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_TargetToSource_TransparentContainer);
    int targetGnbId={};

    if (reqIe)
        targetGnbId = static_cast<int>(asn::GetOctet4(reqIe->TargetToSource_TransparentContainer));

    // Sending Handover Command message to Ue
    // Notify RRC task
    auto w = std::make_unique<NmGnbNgapToRrc>(NmGnbNgapToRrc::HANDOVER);
    w->ueId = ue->ctxId;
    w->targetGnbId = targetGnbId;
    m_base->rrcTask->push(std::move(w));
}

void NgapTask::handleHandoverConfirm(int ueId)
{
    sendHandoverNotify(ueId);
}

void NgapTask::sendHandoverNotify(int ueId)
{
    m_logger->debug("Sending Handover Notify message to AMF");

    auto *ueCtx = findUeByRanId(ueId);
    if (ueCtx == nullptr)
    {
        m_logger->err("Could not find UE context[%d]", ueId);
        return;
    }

    auto *amfCtx = findAmfContext(ueCtx->associatedAmfId);
    if (amfCtx == nullptr)
    {
        m_logger->err("Could not find AMF context[%d]", ueCtx->associatedAmfId);
        return;
    }

    std::vector<ASN_NGAP_HandoverNotifyIEs*> ies;
    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverNotify>(ies);
    sendNgapUeAssociated(ueCtx->ctxId, pdu);
}

void NgapTask::receiveHandoverPreparationFailure(ASN_NGAP_HandoverPreparationFailure *msg)
{
    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_Cause) ;
    if (ie)
        m_logger->err("Handover procedure failure. Cause: %s", ngap_utils::CauseToString(ie->Cause).c_str());
    else
        m_logger->err("Handover procedure failure.");
}

void NgapTask::receivePathSwitchRequestFailure()
{
    m_logger->err("Path Switch Request failure.");
}


} //namespace nr::gnb