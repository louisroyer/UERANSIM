#include "encode.hpp"
#include "task.hpp"
#include "utils.hpp"

#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_HandoverRequired.h>
#include <asn/ngap/ASN_NGAP_HandoverRequest.h>
#include <asn/ngap/ASN_NGAP_HandoverPreparationFailure.h>
#include <asn/ngap/ASN_NGAP_HandoverRequestAcknowledge.h>
#include <asn/ngap/ASN_NGAP_HandoverCommand.h>

#include <asn/ngap/ASN_NGAP_GlobalGNB-ID.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceItemHORqd.h>


/*sourceToTargetTransparentContainer
#include <asn/ngap/ASN_NGAP_SourceToTarget-TransparentContainer.h>
#include <asn/ngap/ASN_NGAP_SourceNGRANNode-ToTargetNGRANNode-TransparentContainer.h>
#include <asn/rrc/ASN_RRC_HandoverPreparationInformation.h>
#include <asn/rrc/ASN_RRC_HandoverPreparationInformation-IEs.h>
 end sourceToTargetTransparentContainer */

#include <asn/ngap/ASN_NGAP_ErrorIndication.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_DirectForwardingPathAvailability.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupItemHOReq.h>

#include "asn/ngap/ASN_NGAP_PDUSessionResourceSetupRequestTransfer.h"
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



namespace nr::gnb
{
// Handover establishment messages
  void NgapTask::sendHandoverRequired(int ueId,int gnbTargetID)
{
    m_logger->debug("Current GNB-ID : [%d] ",m_base -> config -> getGnbId() );
    m_logger->debug("Sending Handover Required request ");

       auto *ueCtx = findUeContext (ueId);
    if (ueCtx == nullptr)
        return;

    auto *amfCtx = findAmfContext(ueCtx->associatedAmfId);
    if (amfCtx == nullptr)
        return;

    std::vector<ASN_NGAP_HandoverRequiredIEs*> ies;
    //m_logger->debug("Handover required message control: ");

    // Handover type
    auto *ies_HANDOVER_TYPE = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ies_HANDOVER_TYPE ->id = ASN_NGAP_ProtocolIE_ID_id_HandoverType;
    ies_HANDOVER_TYPE ->criticality = ASN_NGAP_Criticality_reject;
    ies_HANDOVER_TYPE ->value.present  = ASN_NGAP_HandoverRequiredIEs__value_PR_HandoverType ; 
    ies_HANDOVER_TYPE ->value.choice.HandoverType = ASN_NGAP_HandoverType_intra5gs;
    ies.push_back(ies_HANDOVER_TYPE);
   // m_logger->debug("HANDOVER_TYPE : OK ");

    //Cause
    auto *ies_CAUSE = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ies_CAUSE ->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ies_CAUSE ->criticality = ASN_NGAP_Criticality_ignore;
    ies_CAUSE ->value.present  = ASN_NGAP_HandoverRequiredIEs__value_PR_Cause ; 
    ngap_utils::ToCauseAsn_Ref(NgapCause::RadioNetwork_unspecified , ies_CAUSE ->value.choice.Cause);
    ies.push_back(ies_CAUSE);

    //m_logger->debug("CAUSE : OK ");

    //PDUSessionResourceListHORqd
    if (!ueCtx ->pduSessions.empty())
    {
      auto *ies_PDU_SESSION_LIST = asn::New<ASN_NGAP_HandoverRequiredIEs>();
      ies_PDU_SESSION_LIST  ->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceListHORqd;
      ies_PDU_SESSION_LIST  ->criticality = ASN_NGAP_Criticality_reject;
      ies_PDU_SESSION_LIST  ->value.present=  ASN_NGAP_HandoverRequiredIEs__value_PR_PDUSessionResourceListHORqd;

        for (int psi : ueCtx->pduSessions)
        {
            auto *sessionItem = asn::New<ASN_NGAP_PDUSessionResourceItemHORqd>();
            sessionItem-> pDUSessionID = static_cast<ASN_NGAP_PDUSessionID_t>(psi);
            asn::SetOctetString1(sessionItem->handoverRequiredTransfer,static_cast<uint8_t>(ASN_NGAP_DirectForwardingPathAvailability_direct_path_available));
            asn::SequenceAdd(ies_PDU_SESSION_LIST->value.choice.PDUSessionResourceListHORqd,sessionItem);
        }

        ies.push_back(ies_PDU_SESSION_LIST);
        //m_logger->debug("PDU_SESSION_LIST : OK ");
    }
    else
    {
      m_logger->err("No PDU sessions found for UE [%d]",ueId);
      return;
    }



    // Target ID 
    auto *ies_Target_ID = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ies_Target_ID  ->id = ASN_NGAP_ProtocolIE_ID_id_TargetID;
    ies_Target_ID ->criticality = ASN_NGAP_Criticality_reject;
    ies_Target_ID ->value.present  = ASN_NGAP_HandoverRequiredIEs__value_PR_TargetID ; 

    ies_Target_ID->value.choice.TargetID.present = ASN_NGAP_TargetID_PR_targetRANNodeID;
    ies_Target_ID->value.choice.TargetID.choice.targetRANNodeID =asn :: New <ASN_NGAP_TargetRANNodeID>(); 
    ies_Target_ID->value.choice.TargetID.choice.targetRANNodeID->globalRANNodeID.present = ASN_NGAP_GlobalRANNodeID_PR_globalGNB_ID;


    auto *globalGnbId = asn::New<ASN_NGAP_GlobalGNB_ID>();
    globalGnbId->gNB_ID.present = ASN_NGAP_GNB_ID_PR_gNB_ID;
    asn::SetBitString(globalGnbId->gNB_ID.choice.gNB_ID,
                      octet4{gnbTargetID << (32 - m_base->config->gnbIdLength)},
                      static_cast<size_t>(m_base->config->gnbIdLength));
    asn::SetOctetString3(globalGnbId->pLMNIdentity, ngap_utils::PlmnToOctet3(m_base->config->plmn));

    ies_Target_ID->value.choice.TargetID.choice.targetRANNodeID->globalRANNodeID.choice.globalGNB_ID = globalGnbId;

    asn::SetOctetString3(ies_Target_ID->value.choice.TargetID.choice.targetRANNodeID->selectedTAI.pLMNIdentity , ngap_utils::PlmnToOctet3(m_base->config->plmn));
    asn::SetOctetString3(ies_Target_ID->value.choice.TargetID.choice.targetRANNodeID->selectedTAI.tAC, octet3{m_base->config->tac});
    
    ies.push_back(ies_Target_ID);
    //m_logger->debug("TARGET_ID : OK ");

    //SourceToTarget_TransparentContainer
    auto *ies_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ies_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER  ->id = ASN_NGAP_ProtocolIE_ID_id_SourceToTarget_TransparentContainer;
    ies_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER  ->criticality = ASN_NGAP_Criticality_reject;
    ies_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER  ->value.present  = ASN_NGAP_HandoverRequiredIEs__value_PR_SourceToTarget_TransparentContainer ; 
    asn::SetOctetString1( ies_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER ->value.choice.SourceToTarget_TransparentContainer,static_cast<u_int8_t>(0));

    /*
        auto *container = asn::New<ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer>();

    container ->rRCContainer; // octet_string 
    auto *handoverPreparationInfos = asn::New<ASN_RRC_HandoverPreparationInformation>();
    handoverPreparationInfos->criticalExtensions.present = ASN_RRC_HandoverPreparationInformation__criticalExtensions_PR_c1;
    handoverPreparationInfos->criticalExtensions.choice.c1 = asn::New < ASN_RRC_HandoverPreparationInformation__criticalExtensions__c1 >();
    handoverPreparationInfos->criticalExtensions.choice.c1->present = ASN_RRC_HandoverPreparationInformation__criticalExtensions__c1_PR_handoverPreparationInformation;
    handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation = asn::New <ASN_RRC_HandoverPreparationInformation_IEs>();
    handoverPreparationInfos->criticalExtensions.choice.c1->choice.handoverPreparationInformation-> 

    container ->targetCell_ID; // à voir 
    container ->uEHistoryInformation; // à voir 
    container -> pDUSessionResourceInformationList; // optional (à voir)

    pistes 
    auto &upInfo = tr-> dL_NGU_UP_TNLInformation;
    upInfo.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
    upInfo.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
    asn::SetBitString(upInfo.choice.gTPTunnel->transportLayerAddress, resource->downTunnel.address);
    asn::SetOctetString4(upInfo.choice.gTPTunnel->gTP_TEID, (octet4)resource->downTunnel.teid);
    


    // encodage
    OctetString encodedContainer =
        ngap_encode::EncodeS(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer ,container);

    if (encodedContainer.length() == 0)
        throw std::runtime_error("SourceNGRANNode_ToTargetNGRANNode_TransparentContainer encoding failed");

    asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer ,container);
    asn::SetOctetString(ies_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER->value.choice.SourceToTarget_TransparentContainer, encodedContainer);

    */


    ies.push_back(ies_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER);

    //m_logger->debug("SOURCE_TO_TARGET_TRANSPARENT_CONTAINER : OK ");
    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequired>(ies);
    sendNgapUeAssociated (ueId,pdu);
} 

  void NgapTask::receiveHandoverRequest (int amfId, ASN_NGAP_HandoverRequest *msg)
  { // voir à quel moment on doit decider d'envoyer le msg Handover Failure ( c'est a dire à quel moment on considère que la procédure de handover à échoué)

    m_logger->debug("Handover request message received from AMF " );

    auto *reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID);
    if (reqIe)
    {
      auto ueId = static_cast<int>(asn::GetUnsigned64(reqIe -> AMF_UE_NGAP_ID ));
      if (m_ueCtx.count(ueId))
      {
        m_logger->err("UE context[%d] already exists", ueId);
        return;
      }

      // creating new context for ue
      createUeContext(ueId);

      auto *ue = findUeContext(ueId);
      if (ue == nullptr)
        return;
      
      ue ->amfUeNgapId = ueId; // ça marche 

      auto *amfCtx = findAmfContext(ue->associatedAmfId);
      if (amfCtx == nullptr)
        return;

    amfCtx->nextStream = (amfCtx->nextStream + 1) % amfCtx->association.outStreams;
    if ((amfCtx->nextStream == 0) && (amfCtx->association.outStreams > 1))
        amfCtx->nextStream += 1;
    ue-> uplinkStream = amfCtx->nextStream;


      std::vector<ASN_NGAP_HandoverRequestAcknowledgeIEs*> responseIes;


      //Handover PDU Session Resource Allocation 
 
      std::vector<ASN_NGAP_PDUSessionResourceAdmittedItem*> successList;
      std::vector<ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck *> failedList;
    
      reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListHOReq);
      if (reqIe)
      {
        auto &list = reqIe->PDUSessionResourceSetupListHOReq.list;
        for (int i = 0; i < list.count; i++)
        {
            auto &item = list.array[i];
            auto *transfer = ngap_encode::Decode<ASN_NGAP_PDUSessionResourceSetupRequestTransfer >(
                asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, item->handoverRequestTransfer ); // à voir aussi 
            if (transfer == nullptr)
            {
                m_logger->err(
                    "Unable to decode a PDU session resource setup request transfer. Ignoring the relevant item");
                asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer);
                continue;
            }
            // Ressource allocation for each pdu sessions 
            auto *resource = new PduSessionResource(ue->ctxId, static_cast<int>(item->pDUSessionID));

            auto *ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate);
            if (ie)
            {
                resource->sessionAmbr.dlAmbr =
                    asn::GetUnsigned64(ie->PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL) /
                    8ull;
                resource->sessionAmbr.ulAmbr =
                    asn::GetUnsigned64(ie->PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL) /
                    8ull;
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
                resource->upTunnel.teid =
                    (uint32_t)asn::GetOctet4(ie->UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID);

                resource->upTunnel.address =
                    asn::GetOctetString(ie->UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress);
            }

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList);
            if (ie)
            {
                auto *ptr = asn::New<ASN_NGAP_QosFlowSetupRequestList>();
                asn::DeepCopy(asn_DEF_ASN_NGAP_QosFlowSetupRequestList, ie->QosFlowSetupRequestList, ptr);

                resource->qosFlows = asn::WrapUnique(ptr, asn_DEF_ASN_NGAP_QosFlowSetupRequestList);
            }

            //auto error = setupPduSessionResource(ue, resource);


            std::string gtpIp = m_base->config->gtpAdvertiseIp.value_or(m_base->config->gtpIp);

            resource->downTunnel.address = utils::IpToOctetString(gtpIp);
            resource->downTunnel.teid = ++m_downlinkTeidCounter;

            //auto w = std::make_unique<NmGnbNgapToGtp>(NmGnbNgapToGtp::SESSION_CREATE);
            //w->resource = resource;
            //m_base->gtpTask->push(std::move(w));

            ue->pduSessions.insert(resource->psi);

            /*
    
            if (error.has_value())
            {
                auto *tr = asn::New<ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer>();
                ngap_utils::ToCauseAsn_Ref(error.value(), tr->cause);

                OctetString encodedTr =
                    ngap_encode::EncodeS(asn_DEF_ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer, tr);

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
            */
            auto *tr = asn::New<ASN_NGAP_HandoverRequestAcknowledgeTransfer >();
      
            auto &upInfo = tr->dL_NGU_UP_TNLInformation;
            upInfo.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
            upInfo.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
            asn::SetBitString(upInfo.choice.gTPTunnel->transportLayerAddress, resource->downTunnel.address);
            asn::SetOctetString4(upInfo.choice.gTPTunnel->gTP_TEID, (octet4)resource->downTunnel.teid);


            auto &qosList = resource->qosFlows->list;
            for (int iQos = 0; iQos < qosList.count; iQos++)
            {
                auto *QosFlowItemWithDataForwarding = asn::New<ASN_NGAP_QosFlowItemWithDataForwarding>();
                QosFlowItemWithDataForwarding->qosFlowIdentifier = qosList.array[iQos] -> qosFlowIdentifier;
                asn::SequenceAdd(tr->qosFlowSetupResponseList, QosFlowItemWithDataForwarding);
            }

            OctetString encodedTr =
                ngap_encode::EncodeS(asn_DEF_ASN_NGAP_HandoverRequestAcknowledgeTransfer , tr);

            if (encodedTr.length() == 0)
                throw std::runtime_error("HandoverRequestAcknowledgeTransfer encoding failed");

            asn::Free(asn_DEF_ASN_NGAP_HandoverRequestAcknowledgeTransfer , tr);

            auto *res = asn::New<ASN_NGAP_PDUSessionResourceAdmittedItem>();
            res->pDUSessionID = static_cast<ASN_NGAP_PDUSessionID_t>(resource->psi);
            asn::SetOctetString(res->handoverRequestAcknowledgeTransfer, encodedTr);

            successList.push_back(res);

            asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer); // à verifier 
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

      // adding Ue Bit rate informations to Ue context

      reqIe = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_UEAggregateMaximumBitRate);
      if (reqIe)
    {
      ue->ueAmbr.dlAmbr = asn::GetUnsigned64(reqIe->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateDL) / 8ull;
      ue-> ueAmbr.ulAmbr = asn::GetUnsigned64(reqIe->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateUL) / 8ull;
    }

      // adding other Ies for response

      //TargetToSource_TransparentContainer
      auto *ie_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER = asn::New<ASN_NGAP_HandoverRequestAcknowledgeIEs>();
      ie_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER ->id = ASN_NGAP_ProtocolIE_ID_id_TargetToSource_TransparentContainer;
      ie_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER  ->criticality = ASN_NGAP_Criticality_reject;
      ie_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER  -> value . present  = ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_TargetToSource_TransparentContainer ; 
      asn::SetOctetString1( ie_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER ->value.choice.TargetToSource_TransparentContainer,static_cast<u_int8_t>(0)); // à revoir
      responseIes.push_back(ie_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER);

      //m_logger->debug("TARGET_TO_SOURCE_TRANSPARENT_CONTAINER : OK ");

      // send HandoverRequestACK
        auto *response = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequestAcknowledge>(responseIes);
        sendNgapUeAssociated(ue->ctxId,response);
    }
    else
    {
      m_logger->debug("AMF_UE_NGAP_ID is not present, can not create new context for handover ");
      return;
    }

  }

  void NgapTask::receiveHandoverCommand (int amfId, ASN_NGAP_HandoverCommand * msg)
    {
      //TODO
    }
  void NgapTask::receiveHandoverConfirm (int amfId)
    {
      //TODO
    }
  void NgapTask::sendHandoverNotify(int amfId)
    {
      //TODO
    }

// Handover Failure messages
void NgapTask::receiveHandoverPreparationFailure ( ASN_NGAP_HandoverPreparationFailure *msg)
{
    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_Cause) ;
    if (ie)
        m_logger->err("Handover procedure is failed. Cause: %s", ngap_utils::CauseToString(ie->Cause).c_str() );
    else
        m_logger->err("Handover procedure is failed.");
}

   void NgapTask::receivePathSwitchRequestFailure ()
   {
        m_logger->err("Path Switch Request is failed.");

   }


}  //namespace nr::gnb



