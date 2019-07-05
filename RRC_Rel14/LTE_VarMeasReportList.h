/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-UE-Variables"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_VarMeasReportList_H_
#define	_LTE_VarMeasReportList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LTE_VarMeasReport;

/* LTE_VarMeasReportList */
typedef struct LTE_VarMeasReportList {
	A_SEQUENCE_OF(struct LTE_VarMeasReport) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_VarMeasReportList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_VarMeasReportList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LTE_VarMeasReport.h"

#endif	/* _LTE_VarMeasReportList_H_ */
#include <asn_internal.h>
