/*
 * QEMU KVM Hyper-V support
 *
 * Copyright (C) 2015 Andrey Smetanin <asmetanin@virtuozzo.com>
 *
 * Authors:
 *  Andrey Smetanin <asmetanin@virtuozzo.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "hyperv.h"
#include "hw/hyperv/hyperv.h"
#include "hyperv-proto.h"

int hyperv_x86_synic_add(X86CPU *cpu)
{
    hyperv_synic_add(CPU(cpu));
    return 0;
}

/*
 * All devices possibly using SynIC have to be reset before calling this to let
 * them remove their SINT routes first.
 */
void hyperv_x86_synic_reset(X86CPU *cpu)
{
    hyperv_synic_reset(CPU(cpu));
}

void hyperv_x86_synic_update(X86CPU *cpu, int vtl)
{
    CPUX86State *env = &cpu->env;
    bool enable = env->msr_hv_synic_control[vtl] & HV_SYNIC_ENABLE;
    hwaddr msg_page_addr = (env->msr_hv_synic_msg_page[vtl] & HV_SIMP_ENABLE) ?
        (env->msr_hv_synic_msg_page[vtl] & TARGET_PAGE_MASK) : 0;
    hwaddr event_page_addr = (env->msr_hv_synic_evt_page[vtl] & HV_SIEFP_ENABLE) ?
        (env->msr_hv_synic_evt_page[vtl] & TARGET_PAGE_MASK) : 0;
    hyperv_synic_update(CPU(cpu), vtl, enable, msg_page_addr, event_page_addr);
}

static void async_synic_update(CPUState *cs, run_on_cpu_data data)
{
    qemu_mutex_lock_iothread();
    hyperv_x86_synic_update(X86_CPU(cs), data.host_int);
    qemu_mutex_unlock_iothread();
}

int kvm_hv_handle_exit(X86CPU *cpu, struct kvm_hyperv_exit *exit)
{
    CPUX86State *env = &cpu->env;

    fprintf(stderr, "kvm_hv_handle_exit: 0x%x\n", exit->type);
    switch (exit->type) {
    case KVM_EXIT_HYPERV_SYNIC: {
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNIC)) {
            return -1;
        }

        fprintf(stderr, "kvm_hv_handle_exit synic msr: %d\n", exit->u.synic.msr);
        int vtl = exit->u.synic.vtl;
        switch (exit->u.synic.msr) {
        case HV_X64_MSR_SCONTROL:
            env->msr_hv_synic_control[vtl] = exit->u.synic.control;
            break;
        case HV_X64_MSR_SIMP:
            env->msr_hv_synic_msg_page[vtl] = exit->u.synic.msg_page;
            break;
        case HV_X64_MSR_SIEFP:
            env->msr_hv_synic_evt_page[vtl] = exit->u.synic.evt_page;
            break;
        default:
            return -1;
        }

        /*
         * this will run in this cpu thread before it returns to KVM, but in a
         * safe environment (i.e. when all cpus are quiescent) -- this is
         * necessary because memory hierarchy is being changed
         */
        async_safe_run_on_cpu(CPU(cpu), async_synic_update, RUN_ON_CPU_HOST_INT(vtl));

        return 0;
    }
    case KVM_EXIT_HYPERV_HCALL: {
        uint16_t code = exit->u.hcall.input & 0xffff;
        bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
        uint64_t in_param = exit->u.hcall.params.post_message.ingpa;
        uint64_t out_param = exit->u.hcall.params.post_message.outgpa;

        fprintf(stderr, "kvm_hv_handle_exit: hvcall 0x%x\n", code);
        switch (code) {
        case HV_MODIFY_VTL_PROTECTION_MASK:
            exit->u.hcall.result = hyperv_hcall_vtl_protection_mask(CPU(cpu),
                fast, (struct hyperv_prot_mask *)&exit->u.hcall.params.prot_mask);
            break;
        case HV_POST_MESSAGE:
            exit->u.hcall.result = hyperv_hcall_post_message(in_param, fast);
            break;
        case HV_SIGNAL_EVENT:
            exit->u.hcall.result = hyperv_hcall_signal_event(in_param, fast);
            break;
        case HV_POST_DEBUG_DATA:
            exit->u.hcall.result =
                hyperv_hcall_post_dbg_data(in_param, out_param, fast);
            break;
        case HV_RETRIEVE_DEBUG_DATA:
            exit->u.hcall.result =
                hyperv_hcall_retreive_dbg_data(in_param, out_param, fast);
            break;
        case HV_RESET_DEBUG_SESSION:
            exit->u.hcall.result =
                hyperv_hcall_reset_dbg_session(out_param);
            break;
        default:
            exit->u.hcall.result = HV_STATUS_INVALID_HYPERCALL_CODE;
        }
        return 0;
    }

    case KVM_EXIT_HYPERV_SYNDBG:
        if (!hyperv_feat_enabled(cpu, HYPERV_FEAT_SYNDBG)) {
            return -1;
        }

        switch (exit->u.syndbg.msr) {
        case HV_X64_MSR_SYNDBG_CONTROL: {
            uint64_t control = exit->u.syndbg.control;
            env->msr_hv_syndbg_control = control;
            env->msr_hv_syndbg_send_page = exit->u.syndbg.send_page;
            env->msr_hv_syndbg_recv_page = exit->u.syndbg.recv_page;
            exit->u.syndbg.status = HV_STATUS_SUCCESS;
            if (control & HV_SYNDBG_CONTROL_SEND) {
                exit->u.syndbg.status =
                    hyperv_syndbg_send(env->msr_hv_syndbg_send_page,
                            HV_SYNDBG_CONTROL_SEND_SIZE(control));
            } else if (control & HV_SYNDBG_CONTROL_RECV) {
                exit->u.syndbg.status =
                    hyperv_syndbg_recv(env->msr_hv_syndbg_recv_page,
                            TARGET_PAGE_SIZE);
            }
            break;
        }
        case HV_X64_MSR_SYNDBG_PENDING_BUFFER:
            env->msr_hv_syndbg_pending_page = exit->u.syndbg.pending_page;
            hyperv_syndbg_set_pending_page(env->msr_hv_syndbg_pending_page);
            break;
        default:
            return -1;
        }

        return 0;

    case KVM_EXIT_HYPERV_OVERLAY:
      fprintf(stderr, "kvm_hv_handle_exit: overlay msr 0x%x, vtl %d, gpa 0x%llx\n",
              exit->u.overlay.msr, exit->u.overlay.vtl, exit->u.overlay.gpa);
      return 0;

    default:
        return -1;
    }
}
