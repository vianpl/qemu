/*
 * Definitions for Hyper-V guest/hypervisor interaction - x86-specific part
 *
 * Copyright (c) 2017-2018 Virtuozzo International GmbH.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef TARGET_I386_HYPERV_PROTO_H
#define TARGET_I386_HYPERV_PROTO_H

#include "hw/hyperv/hyperv-proto.h"

#define HV_CPUID_VENDOR_AND_MAX_FUNCTIONS     0x40000000
#define HV_CPUID_INTERFACE                    0x40000001
#define HV_CPUID_VERSION                      0x40000002
#define HV_CPUID_FEATURES                     0x40000003
#define HV_CPUID_ENLIGHTMENT_INFO             0x40000004
#define HV_CPUID_IMPLEMENT_LIMITS             0x40000005
#define HV_CPUID_NESTED_FEATURES              0x4000000A
#define HV_CPUID_SYNDBG_VENDOR_AND_MAX_FUNCTIONS    0x40000080
#define HV_CPUID_SYNDBG_INTERFACE                   0x40000081
#define HV_CPUID_SYNDBG_PLATFORM_CAPABILITIES       0x40000082
#define HV_CPUID_MIN                          0x40000005
#define HV_CPUID_MAX                          0x4000ffff
#define HV_HYPERVISOR_PRESENT_BIT             0x80000000

/*
 * HV_CPUID_FEATURES.EAX bits
 */
#define HV_VP_RUNTIME_AVAILABLE      (1u << 0)
#define HV_TIME_REF_COUNT_AVAILABLE  (1u << 1)
#define HV_SYNIC_AVAILABLE           (1u << 2)
#define HV_SYNTIMERS_AVAILABLE       (1u << 3)
#define HV_APIC_ACCESS_AVAILABLE     (1u << 4)
#define HV_HYPERCALL_AVAILABLE       (1u << 5)
#define HV_VP_INDEX_AVAILABLE        (1u << 6)
#define HV_RESET_AVAILABLE           (1u << 7)
#define HV_REFERENCE_TSC_AVAILABLE   (1u << 9)
#define HV_ACCESS_FREQUENCY_MSRS     (1u << 11)
#define HV_ACCESS_REENLIGHTENMENTS_CONTROL  (1u << 13)

/*
 * HV_CPUID_FEATURES.EBX bits
 */
#define HV_POST_MESSAGES             (1u << 4)
#define HV_SIGNAL_EVENTS             (1u << 5)
#define HV_ACCESS_VSM                (1u << 16)
#define HV_ACCESS_VP_REGS            (1u << 17)
#define HV_START_VP                  (1u << 21)

/*
 * HV_CPUID_FEATURES.EDX bits
 */
#define HV_MWAIT_AVAILABLE                      (1u << 0)
#define HV_GUEST_DEBUGGING_AVAILABLE            (1u << 1)
#define HV_PERF_MONITOR_AVAILABLE               (1u << 2)
#define HV_CPU_DYNAMIC_PARTITIONING_AVAILABLE   (1u << 3)
#define HV_HYPERCALL_XMM_INPUT_AVAILABLE        (1u << 4)
#define HV_GUEST_IDLE_STATE_AVAILABLE           (1u << 5)
#define HV_FREQUENCY_MSRS_AVAILABLE             (1u << 8)
#define HV_GUEST_CRASH_MSR_AVAILABLE            (1u << 10)
#define HV_FEATURE_DEBUG_MSRS_AVAILABLE         (1u << 11)
#define HV_EXT_GVA_RANGES_FLUSH_AVAILABLE       (1u << 14)
#define HV_HYPERCALL_XMM_OUPUT_AVAILABLE        (1u << 15)
#define HV_STIMER_DIRECT_MODE_AVAILABLE         (1u << 19)

/*
 * HV_CPUID_FEATURES.EBX bits
 */
#define HV_PARTITION_DEBUGGING_ALLOWED          (1u << 12)

/*
 * HV_CPUID_ENLIGHTMENT_INFO.EAX bits
 */
#define HV_AS_SWITCH_RECOMMENDED            (1u << 0)
#define HV_LOCAL_TLB_FLUSH_RECOMMENDED      (1u << 1)
#define HV_REMOTE_TLB_FLUSH_RECOMMENDED     (1u << 2)
#define HV_APIC_ACCESS_RECOMMENDED          (1u << 3)
#define HV_SYSTEM_RESET_RECOMMENDED         (1u << 4)
#define HV_RELAXED_TIMING_RECOMMENDED       (1u << 5)
#define HV_DEPRECATING_AEOI_RECOMMENDED     (1u << 9)
#define HV_CLUSTER_IPI_RECOMMENDED          (1u << 10)
#define HV_EX_PROCESSOR_MASKS_RECOMMENDED   (1u << 11)
#define HV_ENLIGHTENED_VMCS_RECOMMENDED     (1u << 14)
#define HV_NO_NONARCH_CORESHARING           (1u << 18)

/*
 * HV_CPUID_SYNDBG_PLATFORM_CAPABILITIES.EAX bits
 */
#define HV_SYNDBG_CAP_ALLOW_KERNEL_DEBUGGING    (1u << 1)

/*
 * HV_CPUID_NESTED_FEATURES.EAX bits
 */
#define HV_NESTED_DIRECT_FLUSH              (1u << 17)
#define HV_NESTED_MSR_BITMAP                (1u << 19)

/*
 * Basic virtualized MSRs
 */
#define HV_X64_MSR_GUEST_OS_ID                0x40000000
#define HV_X64_MSR_HYPERCALL                  0x40000001
#define HV_X64_MSR_VP_INDEX                   0x40000002
#define HV_X64_MSR_RESET                      0x40000003
#define HV_X64_MSR_VP_RUNTIME                 0x40000010
#define HV_X64_MSR_TIME_REF_COUNT             0x40000020
#define HV_X64_MSR_REFERENCE_TSC              0x40000021
#define HV_X64_MSR_TSC_FREQUENCY              0x40000022
#define HV_X64_MSR_APIC_FREQUENCY             0x40000023

/*
 * Virtual APIC MSRs
 */
#define HV_X64_MSR_EOI                        0x40000070
#define HV_X64_MSR_ICR                        0x40000071
#define HV_X64_MSR_TPR                        0x40000072
#define HV_X64_MSR_APIC_ASSIST_PAGE           0x40000073

/*
 * Synthetic interrupt controller MSRs
 */
#define HV_X64_MSR_SCONTROL                   0x40000080
#define HV_X64_MSR_SVERSION                   0x40000081
#define HV_X64_MSR_SIEFP                      0x40000082
#define HV_X64_MSR_SIMP                       0x40000083
#define HV_X64_MSR_EOM                        0x40000084
#define HV_X64_MSR_SINT0                      0x40000090
#define HV_X64_MSR_SINT1                      0x40000091
#define HV_X64_MSR_SINT2                      0x40000092
#define HV_X64_MSR_SINT3                      0x40000093
#define HV_X64_MSR_SINT4                      0x40000094
#define HV_X64_MSR_SINT5                      0x40000095
#define HV_X64_MSR_SINT6                      0x40000096
#define HV_X64_MSR_SINT7                      0x40000097
#define HV_X64_MSR_SINT8                      0x40000098
#define HV_X64_MSR_SINT9                      0x40000099
#define HV_X64_MSR_SINT10                     0x4000009A
#define HV_X64_MSR_SINT11                     0x4000009B
#define HV_X64_MSR_SINT12                     0x4000009C
#define HV_X64_MSR_SINT13                     0x4000009D
#define HV_X64_MSR_SINT14                     0x4000009E
#define HV_X64_MSR_SINT15                     0x4000009F

/*
 * Synthetic timer MSRs
 */
#define HV_X64_MSR_STIMER0_CONFIG               0x400000B0
#define HV_X64_MSR_STIMER0_COUNT                0x400000B1
#define HV_X64_MSR_STIMER1_CONFIG               0x400000B2
#define HV_X64_MSR_STIMER1_COUNT                0x400000B3
#define HV_X64_MSR_STIMER2_CONFIG               0x400000B4
#define HV_X64_MSR_STIMER2_COUNT                0x400000B5
#define HV_X64_MSR_STIMER3_CONFIG               0x400000B6
#define HV_X64_MSR_STIMER3_COUNT                0x400000B7

/*
 * Hyper-V Synthetic debug options MSR
 */
#define HV_X64_MSR_SYNDBG_CONTROL               0x400000F1
#define HV_X64_MSR_SYNDBG_STATUS                0x400000F2
#define HV_X64_MSR_SYNDBG_SEND_BUFFER           0x400000F3
#define HV_X64_MSR_SYNDBG_RECV_BUFFER           0x400000F4
#define HV_X64_MSR_SYNDBG_PENDING_BUFFER        0x400000F5
#define HV_X64_MSR_SYNDBG_OPTIONS               0x400000FF

#define HV_X64_SYNDBG_OPTION_USE_HCALLS         BIT(2)

/*
 * Guest crash notification MSRs
 */
#define HV_X64_MSR_CRASH_P0                     0x40000100
#define HV_X64_MSR_CRASH_P1                     0x40000101
#define HV_X64_MSR_CRASH_P2                     0x40000102
#define HV_X64_MSR_CRASH_P3                     0x40000103
#define HV_X64_MSR_CRASH_P4                     0x40000104
#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)
#define HV_X64_MSR_CRASH_CTL                    0x40000105
#define HV_CRASH_CTL_NOTIFY                     (1ull << 63)

/*
 * Reenlightenment notification MSRs
 */
#define HV_X64_MSR_REENLIGHTENMENT_CONTROL      0x40000106
#define HV_REENLIGHTENMENT_ENABLE_BIT           (1u << 16)
#define HV_X64_MSR_TSC_EMULATION_CONTROL        0x40000107
#define HV_X64_MSR_TSC_EMULATION_STATUS         0x40000108

/*
 * Hypercall MSR bits
 */
#define HV_HYPERCALL_ENABLE                   (1u << 0)

/*
 * Synthetic interrupt controller definitions
 */
#define HV_SYNIC_VERSION                      1
#define HV_SYNIC_ENABLE                       (1u << 0)
#define HV_SIMP_ENABLE                        (1u << 0)
#define HV_SIEFP_ENABLE                       (1u << 0)
#define HV_SINT_MASKED                        (1u << 16)
#define HV_SINT_AUTO_EOI                      (1u << 17)
#define HV_SINT_VECTOR_MASK                   0xff

#define HV_STIMER_COUNT                       4

#define HV_VTL_COUNT                          2

/*
 * Synthetic debugger control definitions
 */
#define HV_SYNDBG_CONTROL_SEND              (1u << 0)
#define HV_SYNDBG_CONTROL_RECV              (1u << 1)
#define HV_SYNDBG_CONTROL_SEND_SIZE(ctl)    ((ctl >> 16) & 0xffff)
#define HV_SYNDBG_STATUS_INVALID            (0)
#define HV_SYNDBG_STATUS_SEND_SUCCESS       (1u << 0)
#define HV_SYNDBG_STATUS_RECV_SUCCESS       (1u << 2)
#define HV_SYNDBG_STATUS_RESET              (1u << 3)
#define HV_SYNDBG_STATUS_SET_SIZE(st, sz)   (st | (sz << 16))

struct hv_x64_table_register {
	uint16_t pad[3];
	uint16_t limit;
	uint64_t base;
} __attribute__ ((__packed__));

struct kvm_hv_vcpu_per_vtl_state {
	uint64_t rip;
	uint64_t rsp;
	uint64_t rflags;
	uint64_t efer;
	uint64_t cr0;
	uint64_t cr3;
	uint64_t cr4;
    uint64_t dr7;
	uint64_t msr_cr_pat;
	uint64_t msr_kernel_gsbase;
    uint64_t msr_gsbase;
    uint64_t msr_fsbase;
	uint64_t msr_tsc_aux;
	uint64_t msr_sysenter_cs;
	uint64_t msr_sysenter_esp;
	uint64_t msr_sysenter_eip;
	uint64_t msr_star;
	uint64_t msr_lstar;
	uint64_t msr_cstar;
	uint64_t msr_sfmask;
    uint64_t msr_hv_synic_control;
    uint64_t msr_hv_synic_evt_page;
    uint64_t msr_hv_synic_msg_page;
    uint64_t msr_hv_synic_sint[HV_SINT_COUNT];
    uint64_t msr_hv_stimer_config[HV_STIMER_COUNT];
    uint64_t msr_hv_stimer_count[HV_STIMER_COUNT];
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_tsc;
    uint64_t msr_hv_vp_assist;

    uint64_t apic_base;

	struct hv_x64_segment_register cs;
	struct hv_x64_segment_register ds;
	struct hv_x64_segment_register es;
	struct hv_x64_segment_register fs;
	struct hv_x64_segment_register gs;
	struct hv_x64_segment_register ss;
	struct hv_x64_segment_register tr;
	struct hv_x64_segment_register ldtr;

	struct hv_x64_table_register idtr;
	struct hv_x64_table_register gdtr;

    int32_t exception_nr;
    int32_t interrupt_injected;
    uint8_t soft_interrupt;
    uint8_t exception_pending;
    uint8_t exception_injected;
    uint8_t has_error_code;
    uint8_t exception_has_payload;
    uint64_t exception_payload;
    uint8_t triple_fault_pending;
    uint32_t ins_len;
    uint32_t sipi_vector;
};

struct hv_init_vp_context {
	uint64_t rip;
	uint64_t rsp;
	uint64_t rflags;

	struct hv_x64_segment_register cs;
	struct hv_x64_segment_register ds;
	struct hv_x64_segment_register es;
	struct hv_x64_segment_register fs;
	struct hv_x64_segment_register gs;
	struct hv_x64_segment_register ss;
	struct hv_x64_segment_register tr;
	struct hv_x64_segment_register ldtr;

	struct hv_x64_table_register idtr;
	struct hv_x64_table_register gdtr;

	uint64_t efer;
	uint64_t cr0;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t msr_cr_pat;
} __attribute__ ((__packed__));

struct hv_enable_vp_vtl {
	uint64_t partition_id;
	uint32_t vp_index;
	uint8_t target_vtl;
	uint8_t	mbz0;
	uint16_t mbz1;
	struct hv_init_vp_context vp_context;
} __attribute__ ((__packed__));

union hv_enable_partition_vtl_flags {
	uint8_t as_u8;
	struct {
		uint8_t enable_mbec:1;
		uint8_t reserved:7;
	} __attribute__ ((__packed__));
};

union hv_enable_partition_vtl {
    uint64_t as_u64[2];
    struct {
        uint64_t target_partition_id;
        uint8_t target_vtl;
        union hv_enable_partition_vtl_flags flags;
        uint8_t reserved[6];
    } __attribute__((__packed__));
};

union hv_register_vsm_partition_status {
	uint64_t as_u64;
	struct {
		uint64_t enabled_vtl_set:16;
		uint64_t maximum_vtl:4;
		uint64_t mbec_enabled_vtl_set:16;
		uint64_t reserved:28;
	} __attribute__ ((__packed__));
};

#define HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_SHIFT	12
#define HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK	\
		(~((1ull << HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_SHIFT) - 1))


enum hv_x64_pending_event_type {
	HV_X64_PENDING_EVENT_EXCEPTION = 0,
	HV_X64_PENDING_EVENT_MEMORY_INTERCEPT = 1,
	HV_X64_PENDING_EVENT_NESTED_MEMORY_INTERCEPT = 2,
	HV_X64_PENDING_EVENT_VIRTUALIZATION_FAULT = 3,
	HV_X64_PENDING_EVENT_HYPERCALL_OUTPUT = 4,
	HV_X64_PENDING_EXT_INT = 5,
	HV_X64_PENDING_EVENT_SHADOW_IPT = 6
};

union hv_x64_pending_exception_event {
	uint64_t as_u64[2];
	struct {
		struct {
			uint32_t event_pending:1;
			uint32_t event_type:3;
			uint32_t _reserved0:4;
			uint32_t deliver_error_code:1;
			uint32_t _reserved1:7;
			uint32_t vector:16;
		};
		uint32_t error_code;
		uint64_t exception_parameter;
	};
};

#endif
