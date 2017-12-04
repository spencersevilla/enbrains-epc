/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "/home/spencer/Desktop/enbrains/src/s1ap/messages/asn1/r10.5/S1AP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_S1ap_CSGMembershipStatus_H_
#define	_S1ap_CSGMembershipStatus_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum S1ap_CSGMembershipStatus {
	S1ap_CSGMembershipStatus_member	= 0,
	S1ap_CSGMembershipStatus_not_member	= 1
} e_S1ap_CSGMembershipStatus;

/* S1ap-CSGMembershipStatus */
typedef long	 S1ap_CSGMembershipStatus_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1ap_CSGMembershipStatus;
asn_struct_free_f S1ap_CSGMembershipStatus_free;
asn_struct_print_f S1ap_CSGMembershipStatus_print;
asn_constr_check_f S1ap_CSGMembershipStatus_constraint;
ber_type_decoder_f S1ap_CSGMembershipStatus_decode_ber;
der_type_encoder_f S1ap_CSGMembershipStatus_encode_der;
xer_type_decoder_f S1ap_CSGMembershipStatus_decode_xer;
xer_type_encoder_f S1ap_CSGMembershipStatus_encode_xer;
per_type_decoder_f S1ap_CSGMembershipStatus_decode_uper;
per_type_encoder_f S1ap_CSGMembershipStatus_encode_uper;
per_type_decoder_f S1ap_CSGMembershipStatus_decode_aper;
per_type_encoder_f S1ap_CSGMembershipStatus_encode_aper;
type_compare_f     S1ap_CSGMembershipStatus_compare;

#ifdef __cplusplus
}
#endif

#endif	/* _S1ap_CSGMembershipStatus_H_ */
#include <asn_internal.h>
