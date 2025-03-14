/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-PDU-Descriptions"
 * 	found in "NGAP-PDU-Descriptions.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-OER -gen-PER -no-gen-example -D ngap`
 */

#ifndef	_ASN_NGAP_NGAP_PDU_H_
#define	_ASN_NGAP_NGAP_PDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ASN_NGAP_NGAP_PDU_PR {
	ASN_NGAP_NGAP_PDU_PR_NOTHING,	/* No components present */
	ASN_NGAP_NGAP_PDU_PR_initiatingMessage,
	ASN_NGAP_NGAP_PDU_PR_successfulOutcome,
	ASN_NGAP_NGAP_PDU_PR_unsuccessfulOutcome
	/* Extensions may appear below */
	
} ASN_NGAP_NGAP_PDU_PR;

/* Forward declarations */
struct ASN_NGAP_InitiatingMessage;
struct ASN_NGAP_SuccessfulOutcome;
struct ASN_NGAP_UnsuccessfulOutcome;

/* ASN_NGAP_NGAP-PDU */
typedef struct ASN_NGAP_NGAP_PDU {
	ASN_NGAP_NGAP_PDU_PR present;
	union ASN_NGAP_NGAP_PDU_u {
		struct ASN_NGAP_InitiatingMessage	*initiatingMessage;
		struct ASN_NGAP_SuccessfulOutcome	*successfulOutcome;
		struct ASN_NGAP_UnsuccessfulOutcome	*unsuccessfulOutcome;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ASN_NGAP_NGAP_PDU_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ASN_NGAP_NGAP_PDU;

#ifdef __cplusplus
}
#endif

#endif	/* _ASN_NGAP_NGAP_PDU_H_ */
#include <asn_internal.h>
