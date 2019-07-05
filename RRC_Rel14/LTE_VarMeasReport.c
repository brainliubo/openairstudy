/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-UE-Variables"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_VarMeasReport.h"

asn_TYPE_member_t asn_MBR_LTE_VarMeasReport_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_VarMeasReport, measId),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_MeasId,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measId"
		},
	{ ATF_POINTER, 4, offsetof(struct LTE_VarMeasReport, measId_v1250),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_MeasId_v1250,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measId-v1250"
		},
	{ ATF_POINTER, 3, offsetof(struct LTE_VarMeasReport, cellsTriggeredList),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CellsTriggeredList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellsTriggeredList"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_VarMeasReport, csi_RS_TriggeredList_r12),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_CSI_RS_TriggeredList_r12,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"csi-RS-TriggeredList-r12"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_VarMeasReport, poolsTriggeredList_r14),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_Tx_ResourcePoolMeasList_r14,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"poolsTriggeredList-r14"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_VarMeasReport, numberOfReportsSent),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"numberOfReportsSent"
		},
};
static const int asn_MAP_LTE_VarMeasReport_oms_1[] = { 1, 2, 3, 4 };
static const ber_tlv_tag_t asn_DEF_LTE_VarMeasReport_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_VarMeasReport_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* measId */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* measId-v1250 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* cellsTriggeredList */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* csi-RS-TriggeredList-r12 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* poolsTriggeredList-r14 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* numberOfReportsSent */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_VarMeasReport_specs_1 = {
	sizeof(struct LTE_VarMeasReport),
	offsetof(struct LTE_VarMeasReport, _asn_ctx),
	asn_MAP_LTE_VarMeasReport_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_LTE_VarMeasReport_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_VarMeasReport = {
	"VarMeasReport",
	"VarMeasReport",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_VarMeasReport_tags_1,
	sizeof(asn_DEF_LTE_VarMeasReport_tags_1)
		/sizeof(asn_DEF_LTE_VarMeasReport_tags_1[0]), /* 1 */
	asn_DEF_LTE_VarMeasReport_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_VarMeasReport_tags_1)
		/sizeof(asn_DEF_LTE_VarMeasReport_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_VarMeasReport_1,
	6,	/* Elements count */
	&asn_SPC_LTE_VarMeasReport_specs_1	/* Additional specs */
};

