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
#include <asn/ngap/ASN_NGAP_HandoverCommandTransfer.h>
#include <asn/ngap/ASN_NGAP_NR-CGI.h>

#include <asn/ngap/ASN_NGAP_GlobalGNB-ID.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceItemHORqd.h>
#include <gnb/gtp/task.hpp>

#include <asn/ngap/ASN_NGAP_TargetRANNodeID.h>
#include <asn/ngap/ASN_NGAP_SourceToTarget-TransparentContainer.h>
#include <asn/ngap/ASN_NGAP_SourceNGRANNode-ToTargetNGRANNode-TransparentContainer.h>
#include <asn/rrc/ASN_RRC_HandoverPreparationInformation.h>
#include <asn/rrc/ASN_RRC_HandoverPreparationInformation-IEs.h>
#include <asn/rrc/ASN_RRC_UE-CapabilityRAT-Container.h>
#include <asn/ngap/ASN_NGAP_NGRAN-CGI.h>
#include <lib/rrc/encode.hpp>

#include <asn/ngap/ASN_NGAP_ErrorIndication.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_DirectForwardingPathAvailability.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupItemHOReq.h>

#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupRequestTransfer.h>
#include <asn/ngap/ASN_NGAP_HandoverRequestAcknowledgeTransfer.h>
#include <asn/ngap/ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceInformationItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowInformationList.h>
#include <asn/ngap/ASN_NGAP_QosFlowIdentifier.h>
#include <asn/ngap/ASN_NGAP_QosFlowInformationItem.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceInformationList.h>

#include <asn/ngap/ASN_NGAP_PDUSessionResourceAdmittedList.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceAdmittedItem.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceFailedToSetupListHOAck.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck.h>
#include <asn/ngap/ASN_NGAP_GTPTunnel.h>
#include <asn/ngap/ASN_NGAP_QosFlowItemWithDataForwarding.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestList.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>

#include <asn/ngap/ASN_NGAP_LastVisitedCellItem.h>
#include <asn/ngap/ASN_NGAP_LastVisitedCellInformation.h>
#include <asn/ngap/ASN_NGAP_LastVisitedNGRANCellInformation.h>

#include <asn/rrc/ASN_RRC_RRCReconfiguration.h>
#include <asn/rrc/ASN_RRC_RRCReconfiguration-IEs.h>
#include <asn/rrc/ASN_RRC_HandoverCommand.h>
#include <asn/ngap/ASN_NGAP_TargetNGRANNode-ToSourceNGRANNode-TransparentContainer.h>


#include <asn/ngap/ASN_NGAP_HandoverNotify.h>

#include <array>
#include <cstdint>


namespace nr::gnb
{

    //Affichage du contenu de ies (debug de vérification de la structure)
    void DebugPrintIes(const std::vector<ASN_NGAP_HandoverRequiredIEs*> &ies, Logger *logger)
    {
        logger->debug("Dumping contents of ies:");
        for (const auto *ie : ies)
        {
            if (ie == nullptr)
            {
                logger->debug("  IE: nullptr");
                continue;
            }
    
            logger->debug("  IE:");
            logger->debug("    id: %d", ie->id);
            logger->debug("    criticality: %d", ie->criticality);
    
            switch (ie->value.present)
            {
                case ASN_NGAP_HandoverRequiredIEs__value_PR_HandoverType:
                    logger->debug("    value.present: HandoverType");
                    logger->debug("    value.choice.HandoverType: %d", ie->value.choice.HandoverType);
                    break;
        
                case ASN_NGAP_HandoverRequiredIEs__value_PR_Cause:
                    logger->debug("    value.present: Cause");
                    logger->debug("    value.choice.Cause: %d", ie->value.choice.Cause.present);
                    break;
        
                case ASN_NGAP_HandoverRequiredIEs__value_PR_TargetID:
                    logger->debug("    value.present: TargetID");
                    logger->debug("    value.choice.TargetID.present: %d", ie->value.choice.TargetID.present);
                    break;
        
                // case ASN_NGAP_HandoverRequiredIEs__value_PR_PDUSessionResourceListHORqd:
                //     logger->debug("    value.present: PDUSessionResourceListHORqd");
                //     // Ici, on parcourt la séquence pour afficher chaque session
                //     if (ie->value.choice.PDUSessionResourceListHORqd) {
                //         logger->debug("    PDUSessionResourceListHORqd count: %d", ie->value.choice.PDUSessionResourceListHORqd->count);
                //         for (size_t i = 0; i < ie->value.choice.PDUSessionResourceListHORqd->count; i++) {
                //             auto *sessionItem = ie->value.choice.PDUSessionResourceListHORqd->array[i];
                //             if (sessionItem) {
                //                 logger->debug("      Session[%zu]:", i);
                //                 logger->debug("        pDUSessionID: %d", sessionItem->pDUSessionID);
                //                 // Affichage de handoverRequiredTransfer (par exemple, sous forme d'entier ou d'une chaîne hexadécimale)
                //                 // Ici, on utilise GetOctet1 ou une fonction de conversion similaire selon le type
                //                 logger->debug("        handoverRequiredTransfer: %d", (int)asn::GetOctet1(sessionItem->handoverRequiredTransfer));
                //             }
                //         }
                //     }
                //     break;
                default:
                    logger->debug("    value.present: Unknown (%d)", ie->value.present);
                    break;
            }
        } 
    }// Utilisation de la fonction : DebugPrintIes(ies, m_logger);


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
    // Affichage Ies
    DebugPrintIes(ies, m_logger.get());


    // Cause
    auto *ieCause = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(NgapCause::RadioNetwork_unspecified, ieCause->value.choice.Cause);
    ies.push_back(ieCause);
    DebugPrintIes(ies, m_logger.get());

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
    DebugPrintIes(ies, m_logger.get());

    // Source To Target Transparent Container
    // asn_sprintf(TYPE, struct)
    auto *ieSourceToTargetTransparentContainer = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieSourceToTargetTransparentContainer->id = ASN_NGAP_ProtocolIE_ID_id_SourceToTarget_TransparentContainer;
    ieSourceToTargetTransparentContainer->criticality = ASN_NGAP_Criticality_reject;
    ieSourceToTargetTransparentContainer->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_SourceToTarget_TransparentContainer;




    // Source NG-RAN Node to Target NG-RAN Node Transparent Container
    auto *container = asn::New<ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer>();

    // Sous-champ 1 : RRC 
    auto *handoverPreparationInfos = asn::New<ASN_RRC_HandoverPreparationInformation>();
    handoverPreparationInfos->criticalExtensions.present = ASN_RRC_HandoverPreparationInformation__criticalExtensions_PR_c1;
    handoverPreparationInfos->criticalExtensions.choice.c1 = asn::New<ASN_RRC_HandoverPreparationInformation::ASN_RRC_HandoverPreparationInformation__criticalExtensions::ASN_RRC_HandoverPreparationInformation__ASN_RRC_criticalExtensions_u::ASN_RRC_HandoverPreparationInformation__criticalExtensions__c1>();
    handoverPreparationInfos->criticalExtensions.choice.c1->present = ASN_RRC_HandoverPreparationInformation__criticalExtensions__c1_PR_handoverPreparationInformation;
    

    // coeur du message rRCContainer
    handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation = asn::New<ASN_RRC_HandoverPreparationInformation_IEs>();
    auto* hpi_ies = handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation; //Ne fait que "copier" le pointeur pour simplifier l’écriture,


    auto* ratItem = asn::New<ASN_RRC_UE_CapabilityRAT_Container>();
    ratItem->rat_Type = ASN_RRC_RAT_Type_nr;
    ratItem->ue_CapabilityRAT_Container.size = 4;
    ratItem->ue_CapabilityRAT_Container.buf = (uint8_t*)calloc(1, 4);
    if (ratItem->ue_CapabilityRAT_Container.buf == nullptr)
    {
        m_logger->err("Failed to allocate memory for ue_CapabilityRAT_Container");
        return;
    }
    ratItem->ue_CapabilityRAT_Container.buf[0] = 0xde;
    ratItem->ue_CapabilityRAT_Container.buf[1] = 0xad;
    ratItem->ue_CapabilityRAT_Container.buf[2] = 0xbe;
    ratItem->ue_CapabilityRAT_Container.buf[3] = 0xef;
    //Résultat = buffer de ad be ef → totalement valide syntaxiquement pour test.

    ASN_SEQUENCE_ADD(&hpi_ies->ue_CapabilityRAT_List.list, ratItem); //Ajoute le ratItem dans la liste ue_CapabilityRAT_List.list, qui est de type asn_sequence_of.
    



    //handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation->ue_CapabilityRAT_List = ASN_RRC_UE_CapabilityRAT_ContainerList;
    //handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation->ue_CapabilityRAT_List.list = //TODO: empty list;
    OctetString handoverEncode = rrc::encode::EncodeS(asn_DEF_ASN_RRC_HandoverPreparationInformation, handoverPreparationInfos);
    


    if (handoverEncode.length() == 0) {
        m_logger->err("HandoverPreparationInformation encoding failed");
        return;
    } else {
        m_logger->debug("Contenu de rRCContainer encodé : taille = %zu octets", handoverEncode.length());
        asn_fprint(stdout, &asn_DEF_ASN_RRC_HandoverPreparationInformation, handoverPreparationInfos);
    }
    
    asn::Free(asn_DEF_ASN_RRC_HandoverPreparationInformation, handoverPreparationInfos);
  
    asn::SetOctetString(container->rRCContainer, handoverEncode);

    // Sous-champ 2 : pDUSessionResourceInformationList
    // m_logger->debug("2ème partie : Nombre de sessions PDU : %lu", ueCtx->pduSessions.size());

    // container->pDUSessionResourceInformationList = asn::New<ASN_NGAP_PDUSessionResourceInformationList_t>();

    // for (int psi : ueCtx->pduSessions)
    // {
    //     // création d'un item pour cette session
    //     auto* pduItem = asn::New<ASN_NGAP_PDUSessionResourceInformationItem>();
    //     pduItem->pDUSessionID = psi;

    //     //  un QoS Flow fictif (par défaut QFI=1)
    //     auto* qosItem = asn::New<ASN_NGAP_QosFlowInformationItem>();
    //     qosItem->qosFlowIdentifier = 1;

    //     // ajout du QoS Flow à la liste
    //     ASN_SEQUENCE_ADD(&pduItem->qosFlowInformationList.list, qosItem);

    //     // ajout de l'item complet à la liste des ressources PDU
    //     ASN_SEQUENCE_ADD(&container->pDUSessionResourceInformationList->list, pduItem);
    //     m_logger->debug("Ajout de la session PDU ID = %d avec QFI = %d", psi, qosItem->qosFlowIdentifier);
    // }



    // auto list #define ASN_EMIT_DEBUG 1
// #include <asn/asn1c/asn_internal.h>= container->pDUSessionResourceInformationList;
    // for (int psi : ueCtx->pduSessions)
    // {
    //     TODO ajouter le pduSessionId et le QFI
    // }


    // === Sous-champ 3 : targetCell_ID ===
    container->targetCell_ID.present = ASN_NGAP_NGRAN_CGI_PR_nR_CGI;
    container->targetCell_ID.choice.nR_CGI = asn::New<ASN_NGAP_NR_CGI>();

    auto *nrCgi = container->targetCell_ID.choice.nR_CGI;

    // ==== Statique selon gnbTargetId ====
    uint8_t plmnId[3];
    uint64_t nci = 0;  // 36 bits

    switch (gnbTargetID)
    {
        case 1: // gNB1
            plmnId[0] = 0x00;
            plmnId[1] = 0xf1;
            plmnId[2] = 0x10;
            nci = 0x000000001; // Cell ID = 1
            break;

        case 2: // gNB2
            plmnId[0] = 0x00;
            plmnId[1] = 0xf1;
            plmnId[2] = 0x10;
            nci = 0x000000002; // Cell ID = 2
            break;

        default:
            m_logger->err("Unknown target gNB ID: %d", gnbTargetID);
            return;
    }

    // === PLMN ID ===
    nrCgi->pLMNIdentity.size = 3;
    nrCgi->pLMNIdentity.buf = (uint8_t*)calloc(1, 3);
    memcpy(nrCgi->pLMNIdentity.buf, plmnId, 3);

    // === NR Cell Identity (NCI) ===
    uint8_t *buf = (uint8_t*)calloc(1, 5);
    for (int i = 0; i < 5; ++i)
        buf[4 - i] = (nci >> (8 * i)) & 0xFF;

    nrCgi->nRCellIdentity.buf = buf;
    nrCgi->nRCellIdentity.size = 5;
    nrCgi->nRCellIdentity.bits_unused = 4; // 36 bits utiles

    m_logger->debug("Statically set targetCell_ID: PLMN=%02x%02x%02x, NCI=0x%09lx",
        plmnId[0], plmnId[1], plmnId[2], nci);



    // m_logger->debug("3ème partie : targetCellID défini dynamiquement : PLMN = %02x%02x%02x, CellID = 0x%08x",
    //     plmnId[0], plmnId[1], plmnId[2], nrCgi);
  

    asn_fprint(stdout, &asn_DEF_ASN_NGAP_NGRAN_CGI, &container->targetCell_ID);
    
    
    if (container->targetCell_ID.choice.nR_CGI->nRCellIdentity.buf == nullptr) {
        m_logger->err("Failed to allocate memory for nRCellIdentity");
        return;
    }
    else{
        m_logger->debug("nRCellIdentity allocated successfully");
    }

    // Affichage de targetCell_ID
    m_logger->debug("Affichage du contenu de targetCell_ID avant encodage :");
    asn_fprint(stdout, &asn_DEF_ASN_NGAP_NGRAN_CGI, &container->targetCell_ID);

    // Encodage de targetCell_ID
    // OctetString targetCellIdEncode = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_NGRAN_CGI, &container->targetCell_ID);
    // if (targetCellIdEncode.length() == 0) {
    //     m_logger->err("targetCell_ID encoding failed");
    //     // return;
    // } else {
    //     m_logger->debug("Contenu de targetCell_ID encodé : taille = %zu octets", targetCellIdEncode.length());
    //     asn_fprint(stdout, &asn_DEF_ASN_NGAP_NGRAN_CGI, &container->targetCell_ID);
    // }

    // Sous-champ 4 : LastVisitedCell
    // container->uEHistoryInformation = *asn::New<ASN_NGAP_UEHistoryInformation_t>();
    auto* cellItem = asn::New<ASN_NGAP_LastVisitedCellItem>();
    cellItem->lastVisitedCellInformation.present = ASN_NGAP_LastVisitedCellInformation_PR_nGRANCell;
    cellItem->lastVisitedCellInformation.choice.nGRANCell = asn::New<ASN_NGAP_LastVisitedNGRANCellInformation_t>();
    
    auto* ngran = cellItem->lastVisitedCellInformation.choice.nGRANCell;
    
    // === NR-CGI ===
    ngran->globalCellID.present = ASN_NGAP_NGRAN_CGI_PR_nR_CGI;
    ngran->globalCellID.choice.nR_CGI = asn::New<ASN_NGAP_NR_CGI>();
    
    // === PLMN ID ===
    asn::SetOctetString3(
        ngran->globalCellID.choice.nR_CGI->pLMNIdentity,
        ngap_utils::PlmnToOctet3(m_base->config->plmn)
    );
    
    // === NR Cell Identity (36 bits sur 40, bits_unused = 4) ===
    uint64_t fullNci = m_base->config->nci;
    buf = (uint8_t*)calloc(1, 5);
    for (int i = 0; i < 5; ++i) {
        buf[4 - i] = (fullNci >> (8 * i)) & 0xFF;
    }
    ngran->globalCellID.choice.nR_CGI->nRCellIdentity.buf = buf;
    ngran->globalCellID.choice.nR_CGI->nRCellIdentity.size = 5;
    ngran->globalCellID.choice.nR_CGI->nRCellIdentity.bits_unused = 4;
    
    // === Cell type + temps ===
    ngran->cellType.cellSize = ASN_NGAP_CellSize_medium;
    ngran->timeUEStayedInCell = 42;
    
    ngran->timeUEStayedInCellEnhancedGranularity = nullptr;
    ngran->hOCauseValue = nullptr;
    ngran->iE_Extensions = nullptr;
    
    // Ajout à la liste
    ASN_SEQUENCE_ADD(&container->uEHistoryInformation.list, cellItem);
    
    // Log
    m_logger->debug("Ajout ueHistoryInformation : PLMN = %d/%d, CellID = 0x%08x, durée = %d sec",
        m_base->config->plmn.mcc,
        m_base->config->plmn.mnc,
        static_cast<uint32_t>(fullNci),
        ngran->timeUEStayedInCell);
    
    

    // Encodage de uEHistoryInformation
    // OctetString uEHistoryInfoEncode = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_UEHistoryInformation, &container->uEHistoryInformation);
    // if (uEHistoryInfoEncode.length() == 0) {
    //     m_logger->err("uEHistoryInformation encoding failed");
    //     // return;
    // } else {
    //     m_logger->debug("Contenu de uEHistoryInformation encodé : taille = %zu octets", uEHistoryInfoEncode.length());
    //     asn_fprint(stdout, &asn_DEF_ASN_NGAP_UEHistoryInformation, &container->uEHistoryInformation);
    // }


    //targetCell_ID->present = ASN_NGAP_NGRAN_CGI_PR_nR_CGI;
    //container->uEHistoryInformation; // TODO: lastvisitedcell

    //asn_fprint(stdout, &asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);
    m_logger->debug("4 ème partie : 📦 Contenu du container ASN.1 juste avant encodage :\n ");
    asn_fprint(stdout, &asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);
    
    //OctetString containerEncoded = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);

    // if (containerEncoded.length() == 0) {
    //     m_logger->err("Échec de l'encodage du SourceToTargetTransparentContainer !");
    //     asn_fprint(stderr, &asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);
    //     throw std::runtime_error("SourceNGRANNode_ToTargetNGRANNode_TransparentContainer encoding failed");
    // }

    OctetString containerEncoded = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);
    std::stringstream ss;
    for (size_t i = 0; i < containerEncoded.length(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
        << static_cast<int>(containerEncoded.data()[i]) << " ";
    }
    m_logger->debug("Buffer encodé (%zd octets): %s", containerEncoded.length(), ss.str().c_str());


    //     if (containerEncoded.length() == 0) {
    //         throw std::runtime_error("Encodage échoué");
    //     }
    // } catch (const std::exception &e) {
    //     m_logger->err("Erreur d'encodage : %s", e.what());
    // }
    
    //asn_fprint(stderr, &asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, containerEncoded);
    //asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, container);
    asn::SetOctetString(ieSourceToTargetTransparentContainer->value.choice.SourceToTarget_TransparentContainer, containerEncoded);

    //asn::SetOctetString4(ieSourceToTargetTransparentContainer->value.choice.SourceToTarget_TransparentContainer, static_cast<octet4>(ueId));
    // m_logger->debug("Premier test: le champ SourceToTarget_TransparentContainer a été défini avec l'ueId = %d", ueId);


    
    ies.push_back(ieSourceToTargetTransparentContainer);
    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequired>(ies);

    m_logger->debug("Sending Handover Required request for UE[%d] to AMF[%d]", ueId, ueCtx->associatedAmfId);
    sendNgapUeAssociated(ueId, pdu);

        // temporary
}



void NgapTask::receiveHandoverRequest(int amfId, ASN_NGAP_HandoverRequest *msg)
{
    m_logger->debug("Handover request message received from AMF");

    auto *reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID);
    if (reqIe)
    {
        auto ueId= static_cast<int>(asn::GetUnsigned64(reqIe->AMF_UE_NGAP_ID ));
        int ueRanId={};
        int32_t sst = 1; // FIXME: init SST with the actual value

        if (m_ueCtx.count(ueId)) {
            m_logger->err("UE context[%d] already exists", ueId);
            return;
        }
        createUeContext(ueId, sst);
        auto *ue = findUeContext(ueId);
        if (!ue)
        {
            m_logger->err("Failed to create UE context[%d]", ueId);
            return;
        }
        ue->amfUeNgapId = ueId;
        ue->associatedAmfId = amfId;

        /* (optionnal ?? )
          auto *amfCtx = findAmfContext(ue->associatedAmfId);
          if (amfCtx == nullptr)
            return;
            amfCtx->nextStream = (amfCtx->nextStream + 1) % amfCtx->association.outStreams;
        if ((amfCtx->nextStream == 0) && (amfCtx->association.outStreams > 1))
            amfCtx->nextStream += 1;
        ue-> uplinkStream = amfCtx->nextStream;

        */
        // Récupération du contexte AMF
        auto *amfCtx = findAmfContext(amfId);
        if (!amfCtx) {
            m_logger->err("AMF context not found with id: %d", amfId);
            return;
        }
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
        ieTargetToSourceTransparentContainer->value.present =
            ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_TargetToSource_TransparentContainer;

        // 1. Créer un OctetString contenant le cellId cible
        OctetString cellIdEncoded;
        // Le container est censé contenir 32 bits, soit 4 octets. 
        // Le dernier octet devant être le targetGNB ID
    
        cellIdEncoded.appendOctet4(static_cast<octet4>(m_base->config->getGnbId())); // dernier octet = 1 ou 2 dépendamment du targetGNB

        // 2. Création de la structure ASN NGAP container
        auto *rrcContainer = asn::New<ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer>();
        asn::SetOctetString(rrcContainer->rRCContainer, cellIdEncoded);

        // 3. Encoder la structure en octets ASN.1
        OctetString encodedContainer = ngap_encode::EncodeS(
            asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer,
            rrcContainer
        );
        asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, rrcContainer);

        // 4. Lier le container encodé au champ du message
        asn::SetOctetString(
            ieTargetToSourceTransparentContainer->value.choice.TargetToSource_TransparentContainer,
            encodedContainer
        );

        // 5. Ajout à la liste des IEs
        responseIes.push_back(ieTargetToSourceTransparentContainer);

        // Envoi
        m_logger->debug("Sending handover request ACK to AMF");
        auto *response = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequestAcknowledge>(responseIes);
        sendNgapUeAssociated(ue->ctxId, response);
    }
}

void NgapTask::receiveHandoverCommand(int amfId, ASN_NGAP_HandoverCommand * msg)
{
    m_logger->debug("Handover Command message received from AMF[%d]", amfId);
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
    {
        m_logger->debug("Cannot find UE context[%d]", ue->ctxId);
        return;
    }

    // extracting information from targetToSourceTransparentContainer
    auto reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_TargetToSource_TransparentContainer);
    if (reqIe)
    {
        auto containerBytes = asn::GetOctetString(reqIe->TargetToSource_TransparentContainer);
        auto w = std::make_unique<NmGnbNgapToRrc>(NmGnbNgapToRrc::HANDOVER);
        w->ueId = ue->ctxId;
        w->rrcContainer = std::move(containerBytes);

        m_base->rrcTask->push(std::move(w));
    }
    else
    {
        m_logger->err("Missing TargetToSource_TransparentContainer IE");
    }
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