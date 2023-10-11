/*
 * Hyper-V guest/hypervisor interaction
 *
 * Copyright (c) 2015-2018 Virtuozzo International GmbH.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_HYPERV_HYPERV_H
#define HW_HYPERV_HYPERV_H

#include <linux/kvm.h>

#include "cpu-qom.h"
#include "hw/hyperv/hyperv-proto.h"
#include "cpu.h"

typedef struct HvSintRoute HvSintRoute;

/*
 * Callback executed in a bottom-half when the status of posting the message
 * becomes known, before unblocking the connection for further messages
 */
typedef void (*HvSintMsgCb)(void *data, int status);

HvSintRoute *hyperv_sint_route_new(uint32_t vp_index, uint32_t sint,
                                   HvSintMsgCb cb, void *cb_data);
void hyperv_sint_route_ref(HvSintRoute *sint_route);
void hyperv_sint_route_unref(HvSintRoute *sint_route);

int hyperv_sint_route_set_sint(HvSintRoute *sint_route);

/*
 * Submit a message to be posted in vcpu context.  If the submission succeeds,
 * the status of posting the message is reported via the callback associated
 * with the @sint_route; until then no more messages are accepted.
 */
int hyperv_post_msg(HvSintRoute *sint_route, struct hyperv_message *msg);
/*
 * Set event flag @eventno, and signal the SINT if the flag has changed.
 */
int hyperv_set_event_flag(HvSintRoute *sint_route, unsigned eventno);

/*
 * Handler for messages arriving from the guest via HV_POST_MESSAGE hypercall.
 * Executed in vcpu context.
 */
typedef uint16_t (*HvMsgHandler)(const struct hyperv_post_message_input *msg,
                                 void *data);
/*
 * Associate @handler with the message connection @conn_id, such that @handler
 * is called with @data when the guest executes HV_POST_MESSAGE hypercall on
 * @conn_id.  If @handler is NULL clear the association.
 */
int hyperv_set_msg_handler(uint32_t conn_id, HvMsgHandler handler, void *data);
/*
 * Associate @notifier with the event connection @conn_id, such that @notifier
 * is signaled when the guest executes HV_SIGNAL_EVENT hypercall on @conn_id.
 * If @notifier is NULL clear the association.
 */
int hyperv_set_event_flag_handler(uint32_t conn_id, EventNotifier *notifier);

int hyperv_init_vsm(struct KVMState *s);
uint64_t hyperv_hcall_vtl_protection_mask(CPUState *cs, struct kvm_hyperv_exit *exit);
uint16_t hyperv_hcall_vtl_enable_partition_vtl(CPUState *cs, uint64_t param1,
                                               uint64_t param2, bool fast);
int hyperv_hcall_vtl_call(CPUState *cs);
int hyperv_hcall_vtl_return(CPUState *cs);
uint64_t hyperv_hcall_get_set_vp_register(CPUState *cs, struct kvm_hyperv_exit *exit,
                                          bool set);
uint16_t hyperv_hcall_vtl_enable_vp_vtl(CPUState *cs, uint64_t param, bool fast);

void hyperv_setup_vp_assist(CPUState *cs, uint64_t gpa);
int kvm_hv_handle_fault(CPUState *cs, uint64_t gpa, uint64_t size, uint64_t flags);

/*
 * Process HV_POST_MESSAGE hypercall: parse the data in the guest memory as
 * specified in @param, and call the HvMsgHandler associated with the
 * connection on the message contained therein.
 */
uint16_t hyperv_hcall_post_message(uint64_t param, bool fast);
/*
 * Process HV_SIGNAL_EVENT hypercall: signal the EventNotifier associated with
 * the connection as specified in @param.
 */
uint16_t hyperv_hcall_signal_event(uint64_t param, bool fast);

static inline uint32_t hyperv_vp_index(CPUState *cs)
{
    return x86_get_phys_apic_id(cs->cpu_index);
}

static inline int hyperv_vsm_vp_index(CPUState *cs)
{
    return hyperv_vp_index(cs);
}

static inline CPUState *hyperv_vsm_vcpu(uint32_t vp_index, uint32_t vtl)
{
    CPUState *cs = cpu_by_arch_id(x86_apic_id_set_group(vp_index, vtl));
    assert(cs);
    return cs;
}

void hyperv_synic_add(CPUState *cs);
void hyperv_synic_reset(CPUState *cs);
void hyperv_synic_update(CPUState *cs, bool enable,
                         hwaddr msg_page_addr, hwaddr event_page_addr);
bool hyperv_is_synic_enabled(void);

/*
 * Process HVCALL_RESET_DEBUG_SESSION hypercall.
 */
uint16_t hyperv_hcall_reset_dbg_session(uint64_t outgpa);
/*
 * Process HVCALL_RETREIVE_DEBUG_DATA hypercall.
 */
uint16_t hyperv_hcall_retreive_dbg_data(uint64_t ingpa, uint64_t outgpa,
                                        bool fast);
/*
 * Process HVCALL_POST_DEBUG_DATA hypercall.
 */
uint16_t hyperv_hcall_post_dbg_data(uint64_t ingpa, uint64_t outgpa, bool fast);

uint32_t hyperv_syndbg_send(uint64_t ingpa, uint32_t count);
uint32_t hyperv_syndbg_recv(uint64_t ingpa, uint32_t count);
void hyperv_syndbg_set_pending_page(uint64_t ingpa);
uint64_t hyperv_syndbg_query_options(void);

typedef enum HvSynthDbgMsgType {
    HV_SYNDBG_MSG_CONNECTION_INFO,
    HV_SYNDBG_MSG_SEND,
    HV_SYNDBG_MSG_RECV,
    HV_SYNDBG_MSG_SET_PENDING_PAGE,
    HV_SYNDBG_MSG_QUERY_OPTIONS
} HvDbgSynthMsgType;

typedef struct HvSynDbgMsg {
    HvDbgSynthMsgType type;
    union {
        struct {
            uint32_t host_ip;
            uint16_t host_port;
        } connection_info;
        struct {
            uint64_t buf_gpa;
            uint32_t count;
            uint32_t pending_count;
            bool is_raw;
        } send;
        struct {
            uint64_t buf_gpa;
            uint32_t count;
            uint32_t options;
            uint64_t timeout;
            uint32_t retrieved_count;
            bool is_raw;
        } recv;
        struct {
            uint64_t buf_gpa;
        } pending_page;
        struct {
            uint64_t options;
        } query_options;
    } u;
} HvSynDbgMsg;
typedef uint16_t (*HvSynDbgHandler)(void *context, HvSynDbgMsg *msg);
void hyperv_set_syndbg_handler(HvSynDbgHandler handler, void *context);

bool hyperv_are_vmbus_recommended_features_enabled(void);
void hyperv_set_vmbus_recommended_features_enabled(void);

#endif
