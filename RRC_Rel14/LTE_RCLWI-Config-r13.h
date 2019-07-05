/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#ifndef	_LTE_RCLWI_Config_r13_H_
#define	_LTE_RCLWI_Config_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "LTE_WLAN-Id-List-r12.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LTE_RCLWI_Config_r13__command_PR {
	LTE_RCLWI_Config_r13__command_PR_NOTHING,	/* No components present */
	LTE_RCLWI_Config_r13__command_PR_steerToWLAN_r13,
	LTE_RCLWI_Config_r13__command_PR_steerToLTE_r13
} LTE_RCLWI_Config_r13__command_PR;

/* LTE_RCLWI-Config-r13 */
typedef struct LTE_RCLWI_Config_r13 {
	struct LTE_RCLWI_Config_r13__command {
		LTE_RCLWI_Config_r13__command_PR present;
		union LTE_RCLWI_Config_r13__LTE_command_u {
			struct LTE_RCLWI_Config_r13__command__steerToWLAN_r13 {
				LTE_WLAN_Id_List_r12_t	 mobilityConfig_r13;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} steerToWLAN_r13;
			NULL_t	 steerToLTE_r13;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} command;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LTE_RCLWI_Config_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LTE_RCLWI_Config_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_LTE_RCLWI_Config_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_LTE_RCLWI_Config_r13_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _LTE_RCLWI_Config_r13_H_ */
#include <asn_internal.h>
