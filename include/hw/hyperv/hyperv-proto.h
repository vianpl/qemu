/*
 * Definitions for Hyper-V guest/hypervisor interaction
 *
 * Copyright (c) 2017-2018 Virtuozzo International GmbH.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_HYPERV_HYPERV_PROTO_H
#define HW_HYPERV_HYPERV_PROTO_H

#include "qemu/bitmap.h"

#define HV_PARTITION_ID_SELF		((uint64_t)-1)
#define HV_VP_INDEX_SELF		    ((uint32_t)-2)

//TODO: 16?
#define HV_NUM_VTLS		2

/*
 * Hypercall status code
 */
#define HV_STATUS_SUCCESS                     0
#define HV_STATUS_INVALID_HYPERCALL_CODE      2
#define HV_STATUS_INVALID_HYPERCALL_INPUT     3
#define HV_STATUS_INVALID_ALIGNMENT           4
#define HV_STATUS_INVALID_PARAMETER           5
#define HV_STATUS_ACCESS_DENIED               6
#define HV_STATUS_INSUFFICIENT_MEMORY         11
#define HV_STATUS_INVALID_PARTITION_ID        13
#define HV_STATUS_INVALID_VP_INDEX		      14
#define HV_STATUS_INVALID_PORT_ID             17
#define HV_STATUS_INVALID_CONNECTION_ID       18
#define HV_STATUS_INSUFFICIENT_BUFFERS        19
#define HV_STATUS_NOT_ACKNOWLEDGED            20
#define HV_STATUS_NO_DATA                     27

#define HV_HYPERCALL_REP_COMP_OFFSET          32
#define HV_HYPERCALL_REP_START_OFFSET	      48

/*
 * Hypercall numbers
 */
#define HV_ENABLE_PARTITION_VTL               0x000d
#define HV_ENABLE_VP_VTL			          0x000f
#define HVCALL_GET_VP_REGISTERS	              0x0050
#define HVCALL_SET_VP_REGISTERS			      0x0051
#define HV_POST_MESSAGE                       0x005c
#define HV_SIGNAL_EVENT                       0x005d
#define HV_POST_DEBUG_DATA                    0x0069
#define HV_RETRIEVE_DEBUG_DATA                0x006a
#define HV_RESET_DEBUG_SESSION                0x006b
#define HV_HYPERCALL_FAST                     (1u << 16)

/*
 * Message size
 */
#define HV_MESSAGE_PAYLOAD_SIZE               240

/*
 * Message types
 */
#define HV_MESSAGE_NONE                       0x00000000
#define HV_MESSAGE_VMBUS                      0x00000001
#define HV_MESSAGE_UNMAPPED_GPA               0x80000000
#define HV_MESSAGE_GPA_INTERCEPT              0x80000001
#define HV_MESSAGE_TIMER_EXPIRED              0x80000010
#define HV_MESSAGE_INVALID_VP_REGISTER_VALUE  0x80000020
#define HV_MESSAGE_UNRECOVERABLE_EXCEPTION    0x80000021
#define HV_MESSAGE_UNSUPPORTED_FEATURE        0x80000022
#define HV_MESSAGE_EVENTLOG_BUFFERCOMPLETE    0x80000040
#define HV_MESSAGE_X64_IOPORT_INTERCEPT       0x80010000
#define HV_MESSAGE_X64_MSR_INTERCEPT          0x80010001
#define HV_MESSAGE_X64_CPUID_INTERCEPT        0x80010002
#define HV_MESSAGE_X64_EXCEPTION_INTERCEPT    0x80010003
#define HV_MESSAGE_X64_APIC_EOI               0x80010004
#define HV_MESSAGE_X64_LEGACY_FP_ERROR        0x80010005

/*
 * Message flags
 */
#define HV_MESSAGE_FLAG_PENDING               0x1

/*
 * Number of synthetic interrupts
 */
#define HV_SINT_COUNT                         16

/*
 * Event flags number per SINT
 */
#define HV_EVENT_FLAGS_COUNT                  (256 * 8)

/*
 * Connection id valid bits
 */
#define HV_CONNECTION_ID_MASK                 0x00ffffff

/*
 * VSM registers
 */
#define HV_X64_REGISTER_PENDING_EVENT0                      0x00010004
#define HV_X64_REGISTER_RSP                                 0x00020004
#define HV_X64_REGISTER_RIP                                 0x00020010
#define HV_X64_REGISTER_RFLAGS                              0x00020011
#define HV_X64_REGISTER_CR0                                 0x00040000
#define HV_X64_REGISTER_CR3                                 0x00040002
#define HV_X64_REGISTER_CR4                                 0x00040003
#define HV_X64_REGISTER_CR8                                 0x00040004
#define HV_X64_REGISTER_DR7                                 0x00050005
#define HV_X64_REGISTER_LDTR                                0x00060006
#define HV_X64_REGISTER_TR                                  0x00060007
#define HV_X64_REGISTER_IDTR                                0x00070000
#define HV_X64_REGISTER_GDTR                                0x00070001
#define HV_X64_REGISTER_EFER                                0x00080001
#define HV_X64_REGISTER_APIC_BASE                           0x00080003
#define HV_X64_REGISTER_SYSENTER_CS                         0x00080005
#define HV_X64_REGISTER_SYSENTER_EIP                        0x00080006
#define HV_X64_REGISTER_SYSENTER_ESP                        0x00080007
#define HV_X64_REGISTER_STAR                                0x00080008
#define HV_X64_REGISTER_LSTAR                               0x00080009
#define HV_X64_REGISTER_CSTAR                               0x0008000A
#define HV_X64_REGISTER_SFMASK                              0x0008000B
#define HV_X64_REGISTER_TSC_AUX                             0x0008007B
#define HV_X64_REGISTER_CR_INTERCEPT_CONTROL                0x000E0000
#define HV_X64_REGISTER_CR_INTERCEPT_CR0_MASK               0x000E0001
#define HV_X64_REGISTER_CR_INTERCEPT_CR4_MASK               0x000E0002
#define HV_X64_REGISTER_CR_INTERCEPT_IA32_MISC_ENABLE_MASK	0x000E0003
#define HV_REGISTER_VP_ASSIST_PAGE		                    0x00090013
#define HV_REGISTER_VSM_CODE_PAGE_OFFSETS                   0x000D0002
#define HV_REGISTER_VSM_VP_STATUS		                    0x000D0003
#define HV_REGISTER_VSM_PARTITION_STATUS                    0x000D0004
#define HV_REGISTER_VSM_VINA                                0x000D0005
#define HV_REGISTER_VSM_CAPABILITIES                        0x000D0006
#define HV_REGISTER_VSM_PARTITION_CONFIG                    0x000D0007
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0               0x000D0010
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL1               0x000D0011
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL2               0x000D0012
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL3               0x000D0013
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL4               0x000D0014
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL5               0x000D0015
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL6               0x000D0016
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL7               0x000D0017
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL8               0x000D0018
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL9               0x000D0019
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL10              0x000D001A
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL11              0x000D001B
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL12              0x000D001C
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL13              0x000D001D
#define HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14              0x000D001E

#define HV_X64_MSR_VP_ASSIST_PAGE_ENABLE	0x00000001
#define HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT	12
#define HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK	\
		(~((1ull << HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT) - 1))

/*
 * Input structure for POST_MESSAGE hypercall
 */
struct hyperv_post_message_input {
    uint32_t connection_id;
    uint32_t _reserved;
    uint32_t message_type;
    uint32_t payload_size;
    uint8_t  payload[HV_MESSAGE_PAYLOAD_SIZE];
};

/*
 * Input structure for SIGNAL_EVENT hypercall
 */
struct hyperv_signal_event_input {
    uint32_t connection_id;
    uint16_t flag_number;
    uint16_t _reserved_zero;
};

/*
 * SynIC message structures
 */
struct hyperv_message_header {
    uint32_t message_type;
    uint8_t  payload_size;
    uint8_t  message_flags; /* HV_MESSAGE_FLAG_XX */
    uint8_t  _reserved[2];
    uint64_t sender;
};

struct hyperv_message {
    struct hyperv_message_header header;
    uint8_t payload[HV_MESSAGE_PAYLOAD_SIZE];
};

struct hv_x64_segment_register {
	uint64_t base;
	uint32_t limit;
	uint16_t selector;
	union {
		struct {
			uint16_t segment_type : 4;
			uint16_t non_system_segment : 1;
			uint16_t descriptor_privilege_level : 2;
			uint16_t present : 1;
			uint16_t reserved : 4;
			uint16_t available : 1;
			uint16_t _long : 1;
			uint16_t _default : 1;
			uint16_t granularity : 1;
		} __attribute__ ((__packed__));
		uint16_t attributes;
	};
} __attribute__ ((__packed__));

struct hyperv_message_page {
    struct hyperv_message slot[HV_SINT_COUNT];
};

/*
 * SynIC event flags structures
 */
struct hyperv_event_flags {
    DECLARE_BITMAP(flags, HV_EVENT_FLAGS_COUNT);
};

struct hyperv_event_flags_page {
    struct hyperv_event_flags slot[HV_SINT_COUNT];
};

/*
 * Kernel debugger structures
 */

/* Options flags for hyperv_reset_debug_session */
#define HV_DEBUG_PURGE_INCOMING_DATA        0x00000001
#define HV_DEBUG_PURGE_OUTGOING_DATA        0x00000002
struct hyperv_reset_debug_session_input {
    uint32_t options;
} __attribute__ ((__packed__));

struct hyperv_reset_debug_session_output {
    uint32_t host_ip;
    uint32_t target_ip;
    uint16_t host_port;
    uint16_t target_port;
    uint8_t host_mac[6];
    uint8_t target_mac[6];
} __attribute__ ((__packed__));

/* Options for hyperv_post_debug_data */
#define HV_DEBUG_POST_LOOP                  0x00000001

struct hyperv_post_debug_data_input {
    uint32_t count;
    uint32_t options;
    /*uint8_t data[HV_HYP_PAGE_SIZE - 2 * sizeof(uint32_t)];*/
} __attribute__ ((__packed__));

struct hyperv_post_debug_data_output {
    uint32_t pending_count;
} __attribute__ ((__packed__));

/* Options for hyperv_retrieve_debug_data */
#define HV_DEBUG_RETRIEVE_LOOP              0x00000001
#define HV_DEBUG_RETRIEVE_TEST_ACTIVITY     0x00000002

struct hyperv_retrieve_debug_data_input {
    uint32_t count;
    uint32_t options;
    uint64_t timeout;
} __attribute__ ((__packed__));

struct hyperv_retrieve_debug_data_output {
    uint32_t retrieved_count;
    uint32_t remaining_count;
} __attribute__ ((__packed__));

union hv_input_vtl {
	uint8_t as_uint8;
	struct {
		uint8_t target_vtl: 4;
		uint8_t use_target_vtl: 1;
		uint8_t reserved_z: 3;
	};
} __attribute__ ((__packed__));

union hv_register_vsm_capabilities {
	uint64_t as_u64;
	struct {
		uint64_t reserved:46;
		uint64_t deny_lower_vtl_startup:1;
		uint64_t mbec_vtl_mask:16;
		uint64_t dr6_shared:1;
	} __attribute__ ((__packed__));
};

union hv_register_vsm_partition_config {
	uint64_t as_u64;
	struct {
		uint64_t enable_vtl_protection:1;
		uint64_t default_vtl_protection_mask:4;
		uint64_t zero_memory_on_reset:1;
		uint64_t deny_lower_vtl_startup:1;
		uint64_t reserved0:2;
		uint64_t intercept_vp_startup:1;
		uint64_t reserved1:54;
	} __attribute__ ((__packed__));
};

union hv_register_vsm_vp_status {
	uint64_t as_u64;
	struct {
		uint64_t active_vtl:4;
		uint64_t active_mbec_enabled:1;
		uint64_t reserved0:11;
		uint64_t enabled_vtl_set:16;
		uint64_t reserved1:32;
	} __attribute__ ((__packed__));
};

union hv_register_vsm_vp_secure_vtl_config {
	uint64_t as_u64;
	struct {
		uint64_t mbec_enabled:1;
		uint64_t tlb_locked:1;
		uint64_t reserved0:62;
	} __attribute__ ((__packed__));
};

struct hv_nested_enlightenments_control {
	struct {
		uint32_t directhypercall:1;
		uint32_t reserved:31;
	} features;
	struct {
		uint32_t inter_partition_comm:1;
		uint32_t reserved:31;
	} hypercallControls;
} __attribute__ ((__packed__));

struct hv_vp_vtl_control {
	uint32_t vtl_entry_reason;

	union {
		uint8_t as_u8;
		struct {
			uint8_t vina_asserted:1;
			uint8_t reserved0:7;
		};
	};

	uint8_t reserved1[3];

	union {
		struct {
			uint64_t vtl_ret_x64rax;
			uint64_t vtl_ret_x64rcx;
		};

		struct {
			uint32_t vtl_return_x86_eax;
			uint32_t vtl_return_x86_ecx;
			uint32_t vtl_return_x86_edx;
			uint32_t reserved2;
		};
	};
};

/* Define virtual processor assist page structure. */
struct hv_vp_assist_page {
	uint32_t apic_assist;
	uint32_t reserved1;
	struct hv_vp_vtl_control vtl_control;
	struct hv_nested_enlightenments_control nested_control;
	uint8_t enlighten_vmentry;
	uint8_t reserved2[7];
	uint64_t current_nested_vmcs;
	uint8_t synthetic_time_unhalted_timer_expired;
	uint8_t reserved3[7];
	uint8_t virtualization_fault_information[40];
	uint8_t reserved4[8];
	uint8_t intercept_message[256];
	uint8_t vtl_ret_actions[256];
} __attribute__ ((__packed__));

struct hv_get_set_vp_registers {
	uint64_t partition_id;
	uint32_t vp_index;
	union hv_input_vtl input_vtl;
	uint8_t padding[3];
};

struct hv_vp_register_val {
	uint64_t low;
	uint64_t high;
};

#endif
