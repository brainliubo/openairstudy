/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_SL-DiscConfigOtherInterFreq-r13.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static asn_per_constraints_t asn_PER_type_LTE_refCarrierCommon_r13_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static const asn_INTEGER_enum_map_t asn_MAP_LTE_refCarrierCommon_r13_value2enum_3[] = {
	{ 0,	5,	"pCell" }
};
static const unsigned int asn_MAP_LTE_refCarrierCommon_r13_enum2value_3[] = {
	0	/* pCell(0) */
};
static const asn_INTEGER_specifics_t asn_SPC_LTE_refCarrierCommon_r13_specs_3 = {
	asn_MAP_LTE_refCarrierCommon_r13_value2enum_3,	/* "tag" => N; sorted by tag */
	asn_MAP_LTE_refCarrierCommon_r13_enum2value_3,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_LTE_refCarrierCommon_r13_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_LTE_refCarrierCommon_r13_3 = {
	"refCarrierCommon-r13",
	"refCarrierCommon-r13",
	&asn_OP_NativeEnumerated,
	asn_DEF_LTE_refCarrierCommon_r13_tags_3,
	sizeof(asn_DEF_LTE_refCarrierCommon_r13_tags_3)
		/sizeof(asn_DEF_LTE_refCarrierCommon_r13_tags_3[0]) - 1, /* 1 */
	asn_DEF_LTE_refCarrierCommon_r13_tags_3,	/* Same as above */
	sizeof(asn_DEF_LTE_refCarrierCommon_r13_tags_3)
		/sizeof(asn_DEF_LTE_refCarrierCommon_r13_tags_3[0]), /* 2 */
	{ 0, &asn_PER_type_LTE_refCarrierCommon_r13_constr_3, NativeEnumerated_constraint },
	0, 0,	/* Defined elsewhere */
	&asn_SPC_LTE_refCarrierCommon_r13_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_LTE_SL_DiscConfigOtherInterFreq_r13_1[] = {
	{ ATF_POINTER, 4, offsetof(struct LTE_SL_DiscConfigOtherInterFreq_r13, txPowerInfo_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_SL_DiscTxPowerInfoList_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"txPowerInfo-r13"
		},
	{ ATF_POINTER, 3, offsetof(struct LTE_SL_DiscConfigOtherInterFreq_r13, refCarrierCommon_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_refCarrierCommon_r13_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"refCarrierCommon-r13"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_SL_DiscConfigOtherInterFreq_r13, discSyncConfig_r13),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_SL_SyncConfigListNFreq_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"discSyncConfig-r13"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_SL_DiscConfigOtherInterFreq_r13, discCellSelectionInfo_r13),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CellSelectionInfoNFreq_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"discCellSelectionInfo-r13"
		},
};
static const int asn_MAP_LTE_SL_DiscConfigOtherInterFreq_r13_oms_1[] = { 0, 1, 2, 3 };
static const ber_tlv_tag_t asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_SL_DiscConfigOtherInterFreq_r13_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* txPowerInfo-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* refCarrierCommon-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* discSyncConfig-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* discCellSelectionInfo-r13 */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_SL_DiscConfigOtherInterFreq_r13_specs_1 = {
	sizeof(struct LTE_SL_DiscConfigOtherInterFreq_r13),
	offsetof(struct LTE_SL_DiscConfigOtherInterFreq_r13, _asn_ctx),
	asn_MAP_LTE_SL_DiscConfigOtherInterFreq_r13_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_LTE_SL_DiscConfigOtherInterFreq_r13_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13 = {
	"SL-DiscConfigOtherInterFreq-r13",
	"SL-DiscConfigOtherInterFreq-r13",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13_tags_1,
	sizeof(asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13_tags_1)
		/sizeof(asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13_tags_1[0]), /* 1 */
	asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13_tags_1)
		/sizeof(asn_DEF_LTE_SL_DiscConfigOtherInterFreq_r13_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_SL_DiscConfigOtherInterFreq_r13_1,
	4,	/* Elements count */
	&asn_SPC_LTE_SL_DiscConfigOtherInterFreq_r13_specs_1	/* Additional specs */
};

