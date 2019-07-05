/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "/home/guicliu/ue_folder/openair2/RRC/LTE/MESSAGES/asn1c/ASN1_files/lte-rrc-14.7.0.asn1"
 * 	`asn1c -pdu=all -fcompound-names -gen-PER -no-gen-OER -no-gen-example -D /home/guicliu/ue_folder/cmake_targets/lte_noS1_build_oai/build/CMakeFiles/RRC_Rel14`
 */

#include "LTE_RRCConnectionReestablishment-NB-r13-IEs.h"

asn_TYPE_member_t asn_MBR_LTE_RRCConnectionReestablishment_NB_r13_IEs_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RRCConnectionReestablishment_NB_r13_IEs, radioResourceConfigDedicated_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_RadioResourceConfigDedicated_NB_r13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"radioResourceConfigDedicated-r13"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LTE_RRCConnectionReestablishment_NB_r13_IEs, nextHopChainingCount_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_NextHopChainingCount,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nextHopChainingCount-r13"
		},
	{ ATF_POINTER, 2, offsetof(struct LTE_RRCConnectionReestablishment_NB_r13_IEs, lateNonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"lateNonCriticalExtension"
		},
	{ ATF_POINTER, 1, offsetof(struct LTE_RRCConnectionReestablishment_NB_r13_IEs, nonCriticalExtension),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LTE_RRCConnectionReestablishment_NB_v1430_IEs,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nonCriticalExtension"
		},
};
static const int asn_MAP_LTE_RRCConnectionReestablishment_NB_r13_IEs_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LTE_RRCConnectionReestablishment_NB_r13_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* radioResourceConfigDedicated-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* nextHopChainingCount-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* lateNonCriticalExtension */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* nonCriticalExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_LTE_RRCConnectionReestablishment_NB_r13_IEs_specs_1 = {
	sizeof(struct LTE_RRCConnectionReestablishment_NB_r13_IEs),
	offsetof(struct LTE_RRCConnectionReestablishment_NB_r13_IEs, _asn_ctx),
	asn_MAP_LTE_RRCConnectionReestablishment_NB_r13_IEs_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_LTE_RRCConnectionReestablishment_NB_r13_IEs_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs = {
	"RRCConnectionReestablishment-NB-r13-IEs",
	"RRCConnectionReestablishment-NB-r13-IEs",
	&asn_OP_SEQUENCE,
	asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs_tags_1,
	sizeof(asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs_tags_1)
		/sizeof(asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs_tags_1[0]), /* 1 */
	asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs_tags_1)
		/sizeof(asn_DEF_LTE_RRCConnectionReestablishment_NB_r13_IEs_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LTE_RRCConnectionReestablishment_NB_r13_IEs_1,
	4,	/* Elements count */
	&asn_SPC_LTE_RRCConnectionReestablishment_NB_r13_IEs_specs_1	/* Additional specs */
};

