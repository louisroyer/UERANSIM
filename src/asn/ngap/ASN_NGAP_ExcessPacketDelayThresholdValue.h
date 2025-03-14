/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "NGAP-IEs.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-OER -gen-PER -no-gen-example -D ngap`
 */

#ifndef	_ASN_NGAP_ExcessPacketDelayThresholdValue_H_
#define	_ASN_NGAP_ExcessPacketDelayThresholdValue_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ASN_NGAP_ExcessPacketDelayThresholdValue {
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms0dot25	= 0,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms0dot5	= 1,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms1	= 2,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms2	= 3,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms4	= 4,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms5	= 5,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms10	= 6,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms20	= 7,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms30	= 8,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms40	= 9,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms50	= 10,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms60	= 11,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms70	= 12,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms80	= 13,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms90	= 14,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms100	= 15,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms150	= 16,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms300	= 17,
	ASN_NGAP_ExcessPacketDelayThresholdValue_ms500	= 18
	/*
	 * Enumeration is extensible
	 */
} e_ASN_NGAP_ExcessPacketDelayThresholdValue;

/* ASN_NGAP_ExcessPacketDelayThresholdValue */
typedef long	 ASN_NGAP_ExcessPacketDelayThresholdValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ASN_NGAP_ExcessPacketDelayThresholdValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ASN_NGAP_ExcessPacketDelayThresholdValue;
extern const asn_INTEGER_specifics_t asn_SPC_ASN_NGAP_ExcessPacketDelayThresholdValue_specs_1;
asn_struct_free_f ASN_NGAP_ExcessPacketDelayThresholdValue_free;
asn_struct_print_f ASN_NGAP_ExcessPacketDelayThresholdValue_print;
asn_constr_check_f ASN_NGAP_ExcessPacketDelayThresholdValue_constraint;
ber_type_decoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_decode_ber;
der_type_encoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_encode_der;
xer_type_decoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_decode_xer;
xer_type_encoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_encode_xer;
per_type_decoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_decode_uper;
per_type_encoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_encode_uper;
per_type_decoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_decode_aper;
per_type_encoder_f ASN_NGAP_ExcessPacketDelayThresholdValue_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _ASN_NGAP_ExcessPacketDelayThresholdValue_H_ */
#include <asn_internal.h>
