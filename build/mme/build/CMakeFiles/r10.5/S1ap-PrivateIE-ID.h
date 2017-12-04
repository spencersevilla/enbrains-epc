/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-CommonDataTypes"
 * 	found in "/home/spencer/Desktop/enbrains/src/s1ap/messages/asn1/r10.5/S1AP-CommonDataTypes.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_S1ap_PrivateIE_ID_H_
#define	_S1ap_PrivateIE_ID_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <OBJECT_IDENTIFIER.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum S1ap_PrivateIE_ID_PR {
	S1ap_PrivateIE_ID_PR_NOTHING,	/* No components present */
	S1ap_PrivateIE_ID_PR_local,
	S1ap_PrivateIE_ID_PR_global
} S1ap_PrivateIE_ID_PR;

/* S1ap-PrivateIE-ID */
typedef struct S1ap_PrivateIE_ID {
	S1ap_PrivateIE_ID_PR present;
	union S1ap_PrivateIE_ID_u {
		long	 local;
		OBJECT_IDENTIFIER_t	 global;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} S1ap_PrivateIE_ID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1ap_PrivateIE_ID;

#ifdef __cplusplus
}
#endif

#endif	/* _S1ap_PrivateIE_ID_H_ */
#include <asn_internal.h>
