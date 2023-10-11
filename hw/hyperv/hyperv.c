/*
 * Hyper-V guest/hypervisor interaction
 *
 * Copyright (c) 2015-2018 Virtuozzo International GmbH.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "sysemu/kvm.h"
#include "qemu/bitops.h"
#include "qemu/error-report.h"
#include "qemu/lockable.h"
#include "qemu/queue.h"
#include "qemu/rcu.h"
#include "qemu/rcu_queue.h"
#include "hw/hyperv/hyperv.h"
#include "hw/i386/x86.h"
#include "hw/i386/apic_internal.h"
#include "qom/object.h"
#include "target/i386/kvm/hyperv-proto.h"
#include "target/i386/cpu.h"
#include "exec/cpu-all.h"
#include "kvm/kvm_i386.h"
#include "sysemu/hw_accel.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "trace.h"

struct SynICState {
    DeviceState parent_obj;

    CPUState *cs;

    bool sctl_enabled;
    hwaddr msg_page_addr;
    hwaddr event_page_addr;
    MemoryRegion msg_page_mr;
    MemoryRegion event_page_mr;
    struct hyperv_message_page *msg_page;
    struct hyperv_event_flags_page *event_page;

    QemuMutex sint_routes_mutex;
    QLIST_HEAD(, HvSintRoute) sint_routes;
};

#define TYPE_SYNIC "hyperv-synic"
OBJECT_DECLARE_SIMPLE_TYPE(SynICState, SYNIC)

static bool synic_enabled;

bool hyperv_is_synic_enabled(void)
{
    return synic_enabled;
}

static SynICState *get_synic(CPUState *cs)
{
    return SYNIC(object_resolve_path_component(OBJECT(cs), "synic"));
}

static void synic_update(SynICState *synic, bool sctl_enable,
                         hwaddr msg_page_addr, hwaddr event_page_addr)
{

    synic->sctl_enabled = sctl_enable;
    if (synic->msg_page_addr != msg_page_addr) {
        if (synic->msg_page_addr) {
            memory_region_del_subregion(get_system_memory(),
                                        &synic->msg_page_mr);
        }
        if (msg_page_addr) {
            memory_region_add_subregion(get_system_memory(), msg_page_addr,
                                        &synic->msg_page_mr);
        }
        synic->msg_page_addr = msg_page_addr;
    }
    if (synic->event_page_addr != event_page_addr) {
        if (synic->event_page_addr) {
            memory_region_del_subregion(get_system_memory(),
                                        &synic->event_page_mr);
        }
        if (event_page_addr) {
            memory_region_add_subregion(get_system_memory(), event_page_addr,
                                        &synic->event_page_mr);
        }
        synic->event_page_addr = event_page_addr;
    }
}

void hyperv_synic_update(CPUState *cs, bool sctl_enable,
                         hwaddr msg_page_addr, hwaddr event_page_addr)
{
    SynICState *synic = get_synic(cs);

    if (!synic) {
        return;
    }

    synic_update(synic, sctl_enable, msg_page_addr, event_page_addr);
}

static void synic_realize(DeviceState *dev, Error **errp)
{
    Object *obj = OBJECT(dev);
    SynICState *synic = SYNIC(dev);
    char *msgp_name, *eventp_name;
    uint32_t vp_index;

    /* memory region names have to be globally unique */
    vp_index = hyperv_vp_index(synic->cs);
    msgp_name = g_strdup_printf("synic-%u-msg-page", vp_index);
    eventp_name = g_strdup_printf("synic-%u-event-page", vp_index);

    memory_region_init_ram(&synic->msg_page_mr, obj, msgp_name,
                           sizeof(*synic->msg_page), &error_abort);
    memory_region_init_ram(&synic->event_page_mr, obj, eventp_name,
                           sizeof(*synic->event_page), &error_abort);
    synic->msg_page = memory_region_get_ram_ptr(&synic->msg_page_mr);
    synic->event_page = memory_region_get_ram_ptr(&synic->event_page_mr);
    qemu_mutex_init(&synic->sint_routes_mutex);
    QLIST_INIT(&synic->sint_routes);

    g_free(msgp_name);
    g_free(eventp_name);
}

static void synic_reset(DeviceState *dev)
{
    SynICState *synic = SYNIC(dev);
    memset(synic->msg_page, 0, sizeof(*synic->msg_page));
    memset(synic->event_page, 0, sizeof(*synic->event_page));
    synic_update(synic, false, 0, 0);
    assert(QLIST_EMPTY(&synic->sint_routes));
}

static void synic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = synic_realize;
    dc->reset = synic_reset;
    dc->user_creatable = false;
}

void hyperv_synic_add(CPUState *cs)
{
    Object *obj;
    SynICState *synic;

    obj = object_new(TYPE_SYNIC);
    synic = SYNIC(obj);
    synic->cs = cs;
    object_property_add_child(OBJECT(cs), "synic", obj);
    object_unref(obj);
    qdev_realize(DEVICE(obj), NULL, &error_abort);
    synic_enabled = true;
}

void hyperv_synic_reset(CPUState *cs)
{
    SynICState *synic = get_synic(cs);

    if (synic) {
        device_cold_reset(DEVICE(synic));
    }
}

static const TypeInfo synic_type_info = {
    .name = TYPE_SYNIC,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(SynICState),
    .class_init = synic_class_init,
};

static void synic_register_types(void)
{
    type_register_static(&synic_type_info);
}

type_init(synic_register_types)

/*
 * KVM has its own message producers (SynIC timers).  To guarantee
 * serialization with both KVM vcpu and the guest cpu, the messages are first
 * staged in an intermediate area and then posted to the SynIC message page in
 * the vcpu thread.
 */
typedef struct HvSintStagedMessage {
    /* message content staged by hyperv_post_msg */
    struct hyperv_message msg;
    /* callback + data (r/o) to complete the processing in a BH */
    HvSintMsgCb cb;
    void *cb_data;
    /* message posting status filled by cpu_post_msg */
    int status;
    /* passing the buck: */
    enum {
        /* initial state */
        HV_STAGED_MSG_FREE,
        /*
         * hyperv_post_msg (e.g. in main loop) grabs the staged area (FREE ->
         * BUSY), copies msg, and schedules cpu_post_msg on the assigned cpu
         */
        HV_STAGED_MSG_BUSY,
        /*
         * cpu_post_msg (vcpu thread) tries to copy staged msg to msg slot,
         * notify the guest, records the status, marks the posting done (BUSY
         * -> POSTED), and schedules sint_msg_bh BH
         */
        HV_STAGED_MSG_POSTED,
        /*
         * sint_msg_bh (BH) verifies that the posting is done, runs the
         * callback, and starts over (POSTED -> FREE)
         */
    } state;
} HvSintStagedMessage;

struct HvSintRoute {
    uint32_t sint;
    SynICState *synic;
    int gsi;
    EventNotifier sint_set_notifier;
    EventNotifier sint_ack_notifier;

    HvSintStagedMessage *staged_msg;

    unsigned refcount;
    QLIST_ENTRY(HvSintRoute) link;
};

static CPUState *hyperv_find_vcpu(uint32_t vp_index)
{
    CPUState *cs = qemu_get_cpu(vp_index);
    assert(hyperv_vp_index(cs) == vp_index);
    return cs;
}

/*
 * BH to complete the processing of a staged message.
 */
static void sint_msg_bh(void *opaque)
{
    HvSintRoute *sint_route = opaque;
    HvSintStagedMessage *staged_msg = sint_route->staged_msg;

    if (qatomic_read(&staged_msg->state) != HV_STAGED_MSG_POSTED) {
        /* status nor ready yet (spurious ack from guest?), ignore */
        return;
    }

    staged_msg->cb(staged_msg->cb_data, staged_msg->status);
    staged_msg->status = 0;

    /* staged message processing finished, ready to start over */
    qatomic_set(&staged_msg->state, HV_STAGED_MSG_FREE);
    /* drop the reference taken in hyperv_post_msg */
    hyperv_sint_route_unref(sint_route);
}

/*
 * Worker to transfer the message from the staging area into the SynIC message
 * page in vcpu context.
 */
static void cpu_post_msg(CPUState *cs, run_on_cpu_data data)
{
    HvSintRoute *sint_route = data.host_ptr;
    HvSintStagedMessage *staged_msg = sint_route->staged_msg;
    SynICState *synic = sint_route->synic;
    struct hyperv_message *dst_msg;
    bool wait_for_sint_ack = false;

    assert(staged_msg->state == HV_STAGED_MSG_BUSY);

    if (!synic->msg_page_addr) {
        staged_msg->status = -ENXIO;
        goto posted;
    }

    dst_msg = &synic->msg_page->slot[sint_route->sint];

    if (dst_msg->header.message_type != HV_MESSAGE_NONE) {
        dst_msg->header.message_flags |= HV_MESSAGE_FLAG_PENDING;
        staged_msg->status = -EAGAIN;
        wait_for_sint_ack = true;
    } else {
        memcpy(dst_msg, &staged_msg->msg, sizeof(*dst_msg));
        staged_msg->status = hyperv_sint_route_set_sint(sint_route);
    }

    memory_region_set_dirty(&synic->msg_page_mr, 0, sizeof(*synic->msg_page));

posted:
    qatomic_set(&staged_msg->state, HV_STAGED_MSG_POSTED);
    /*
     * Notify the msg originator of the progress made; if the slot was busy we
     * set msg_pending flag in it so it will be the guest who will do EOM and
     * trigger the notification from KVM via sint_ack_notifier
     */
    if (!wait_for_sint_ack) {
        aio_bh_schedule_oneshot(qemu_get_aio_context(), sint_msg_bh,
                                sint_route);
    }
}

/*
 * Post a Hyper-V message to the staging area, for delivery to guest in the
 * vcpu thread.
 */
int hyperv_post_msg(HvSintRoute *sint_route, struct hyperv_message *src_msg)
{
    HvSintStagedMessage *staged_msg = sint_route->staged_msg;

    assert(staged_msg);

    /* grab the staging area */
    if (qatomic_cmpxchg(&staged_msg->state, HV_STAGED_MSG_FREE,
                       HV_STAGED_MSG_BUSY) != HV_STAGED_MSG_FREE) {
        return -EAGAIN;
    }

    memcpy(&staged_msg->msg, src_msg, sizeof(*src_msg));

    /* hold a reference on sint_route until the callback is finished */
    hyperv_sint_route_ref(sint_route);

    /* schedule message posting attempt in vcpu thread */
    async_run_on_cpu(sint_route->synic->cs, cpu_post_msg,
                     RUN_ON_CPU_HOST_PTR(sint_route));
    return 0;
}

static void sint_ack_handler(EventNotifier *notifier)
{
    HvSintRoute *sint_route = container_of(notifier, HvSintRoute,
                                           sint_ack_notifier);
    event_notifier_test_and_clear(notifier);

    /*
     * the guest consumed the previous message so complete the current one with
     * -EAGAIN and let the msg originator retry
     */
    aio_bh_schedule_oneshot(qemu_get_aio_context(), sint_msg_bh, sint_route);
}

/*
 * Set given event flag for a given sint on a given vcpu, and signal the sint.
 */
int hyperv_set_event_flag(HvSintRoute *sint_route, unsigned eventno)
{
    int ret;
    SynICState *synic = sint_route->synic;
    unsigned long *flags, set_mask;
    unsigned set_idx;

    if (eventno > HV_EVENT_FLAGS_COUNT) {
        return -EINVAL;
    }
    if (!synic->sctl_enabled || !synic->event_page_addr) {
        return -ENXIO;
    }

    set_idx = BIT_WORD(eventno);
    set_mask = BIT_MASK(eventno);
    flags = synic->event_page->slot[sint_route->sint].flags;

    if ((qatomic_fetch_or(&flags[set_idx], set_mask) & set_mask) != set_mask) {
        memory_region_set_dirty(&synic->event_page_mr, 0,
                                sizeof(*synic->event_page));
        ret = hyperv_sint_route_set_sint(sint_route);
    } else {
        ret = 0;
    }
    return ret;
}

HvSintRoute *hyperv_sint_route_new(uint32_t vp_index, uint32_t sint,
                                   HvSintMsgCb cb, void *cb_data)
{
    HvSintRoute *sint_route = NULL;
    EventNotifier *ack_notifier = NULL;
    int r, gsi;
    CPUState *cs;
    SynICState *synic;
    bool ack_event_initialized = false;

    cs = hyperv_find_vcpu(vp_index);
    if (!cs) {
        return NULL;
    }

    synic = get_synic(cs);
    if (!synic) {
        return NULL;
    }

    sint_route = g_new0(HvSintRoute, 1);
    if (!sint_route) {
        return NULL;
    }

    sint_route->synic = synic;
    sint_route->sint = sint;
    sint_route->refcount = 1;

    ack_notifier = cb ? &sint_route->sint_ack_notifier : NULL;
    if (ack_notifier) {
        sint_route->staged_msg = g_new0(HvSintStagedMessage, 1);
        if (!sint_route->staged_msg) {
            goto cleanup_err_sint;
        }
        sint_route->staged_msg->cb = cb;
        sint_route->staged_msg->cb_data = cb_data;

        r = event_notifier_init(ack_notifier, false);
        if (r) {
            goto cleanup_err_sint;
        }
        event_notifier_set_handler(ack_notifier, sint_ack_handler);
        ack_event_initialized = true;
    }

    /* See if we are done or we need to setup a GSI for this SintRoute */
    if (!synic->sctl_enabled) {
        goto cleanup;
    }

    /* We need to setup a GSI for this SintRoute */
    r = event_notifier_init(&sint_route->sint_set_notifier, false);
    if (r) {
        goto cleanup_err_sint;
    }

    gsi = kvm_irqchip_add_hv_sint_route(kvm_state, vp_index, sint);
    if (gsi < 0) {
        goto cleanup_err_sint_notifier;
    }

    r = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state,
                                           &sint_route->sint_set_notifier,
                                           ack_notifier, gsi);
    if (r) {
        goto cleanup_err_irqfd;
    }
    sint_route->gsi = gsi;
cleanup:
    qemu_mutex_lock(&synic->sint_routes_mutex);
    QLIST_INSERT_HEAD(&synic->sint_routes, sint_route, link);
    qemu_mutex_unlock(&synic->sint_routes_mutex);
    return sint_route;

cleanup_err_irqfd:
    kvm_irqchip_release_virq(kvm_state, gsi);

cleanup_err_sint_notifier:
    event_notifier_cleanup(&sint_route->sint_set_notifier);

cleanup_err_sint:
    if (ack_notifier) {
        if (ack_event_initialized) {
            event_notifier_set_handler(ack_notifier, NULL);
            event_notifier_cleanup(ack_notifier);
        }

        g_free(sint_route->staged_msg);
    }

    g_free(sint_route);
    return NULL;
}

void hyperv_sint_route_ref(HvSintRoute *sint_route)
{
    sint_route->refcount++;
}

void hyperv_sint_route_unref(HvSintRoute *sint_route)
{
    SynICState *synic;

    if (!sint_route) {
        return;
    }

    assert(sint_route->refcount > 0);

    if (--sint_route->refcount) {
        return;
    }

    synic = sint_route->synic;
    qemu_mutex_lock(&synic->sint_routes_mutex);
    QLIST_REMOVE(sint_route, link);
    qemu_mutex_unlock(&synic->sint_routes_mutex);

    if (sint_route->gsi) {
        kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state,
                                              &sint_route->sint_set_notifier,
                                              sint_route->gsi);
        kvm_irqchip_release_virq(kvm_state, sint_route->gsi);
        event_notifier_cleanup(&sint_route->sint_set_notifier);
    }

    if (sint_route->staged_msg) {
        event_notifier_set_handler(&sint_route->sint_ack_notifier, NULL);
        event_notifier_cleanup(&sint_route->sint_ack_notifier);
        g_free(sint_route->staged_msg);
    }
    g_free(sint_route);
}

int hyperv_sint_route_set_sint(HvSintRoute *sint_route)
{
    if (!sint_route->gsi) {
        return 0;
    }

    return event_notifier_set(&sint_route->sint_set_notifier);
}

typedef struct MsgHandler {
    struct rcu_head rcu;
    QLIST_ENTRY(MsgHandler) link;
    uint32_t conn_id;
    HvMsgHandler handler;
    void *data;
} MsgHandler;

typedef struct EventFlagHandler {
    struct rcu_head rcu;
    QLIST_ENTRY(EventFlagHandler) link;
    uint32_t conn_id;
    EventNotifier *notifier;
} EventFlagHandler;

static QLIST_HEAD(, MsgHandler) msg_handlers;
static QLIST_HEAD(, EventFlagHandler) event_flag_handlers;
static QemuMutex handlers_mutex;

static void __attribute__((constructor)) hv_init(void)
{
    QLIST_INIT(&msg_handlers);
    QLIST_INIT(&event_flag_handlers);
    qemu_mutex_init(&handlers_mutex);
}

int hyperv_set_msg_handler(uint32_t conn_id, HvMsgHandler handler, void *data)
{
    int ret;
    MsgHandler *mh;

    QEMU_LOCK_GUARD(&handlers_mutex);
    QLIST_FOREACH(mh, &msg_handlers, link) {
        if (mh->conn_id == conn_id) {
            if (handler) {
                ret = -EEXIST;
            } else {
                QLIST_REMOVE_RCU(mh, link);
                g_free_rcu(mh, rcu);
                ret = 0;
            }
            return ret;
        }
    }

    if (handler) {
        mh = g_new(MsgHandler, 1);
        mh->conn_id = conn_id;
        mh->handler = handler;
        mh->data = data;
        QLIST_INSERT_HEAD_RCU(&msg_handlers, mh, link);
        ret = 0;
    } else {
        ret = -ENOENT;
    }

    return ret;
}

static bool hyperv_vp_assist_page_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
{
    if (msr != HV_X64_MSR_APIC_ASSIST_PAGE) {
        printf("In %s with MSR %x\n", __func__, msr);
        return false;
    }

    hyperv_setup_vp_assist(CPU(cpu), val);
    kvm_put_hv_vp_assist(cpu, val);

    return true;
}

int hyperv_init_vsm(struct KVMState *s)
{
    if (!kvm_filter_msr(s, HV_X64_MSR_APIC_ASSIST_PAGE, NULL, hyperv_vp_assist_page_wrmsr)) {
        printf("Failed to set HV_X64_MSR_HYPERCALL MSR handler\n");
        return -1;
    }

    return 0;
}

static int get_active_vtl(CPUState *cpu)
{
    return x86_get_apic_id_goup(kvm_arch_vcpu_id(cpu));
}

struct VpVsmState {
    DeviceState parent_obj;

    CPUState *cs;
    union hv_register_vsm_vp_status vsm_vp_status;
    union hv_register_vsm_vp_secure_vtl_config vsm_vtl_config[HV_NUM_VTLS];
    void *vp_assist;
    struct kvm_hv_vcpu_per_vtl_state priv_state;
};

static CPUState *hyperv_get_next_vtl(CPUState *cs)
{
    return hyperv_vsm_vcpu(hyperv_vsm_vp_index(cs), get_active_vtl(cs) + 1);
}

static CPUState *hyperv_get_prev_vtl(CPUState *cs)
{
    return hyperv_vsm_vcpu(hyperv_vsm_vp_index(cs), get_active_vtl(cs) - 1);
}

#define TYPE_VP_VSM "hyperv-vp-vsm"
OBJECT_DECLARE_SIMPLE_TYPE(VpVsmState, VP_VSM)

static VpVsmState *get_vp_vsm(CPUState *cs)
{
    return VP_VSM(object_resolve_path_component(OBJECT(cs), "vp-vsm"));
}

static void hyperv_set_seg(SegmentCache *lhs, const struct hv_x64_segment_register *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->flags = (rhs->segment_type << DESC_TYPE_SHIFT) |
                 (rhs->present * DESC_P_MASK) |
                 (rhs->descriptor_privilege_level << DESC_DPL_SHIFT) |
                 (rhs->_default << DESC_B_SHIFT) |
                 (rhs->non_system_segment * DESC_S_MASK) |
                 (rhs->_long << DESC_L_SHIFT) |
                 (rhs->granularity * DESC_G_MASK) |
                 (rhs->available * DESC_AVL_MASK);
}

static void hyperv_get_seg(const SegmentCache *lhs, struct hv_x64_segment_register *rhs)
{
    unsigned flags = lhs->flags;

    rhs->selector = lhs->selector;
    rhs->base = lhs->base;
    rhs->limit = lhs->limit;
    rhs->segment_type = (flags >> DESC_TYPE_SHIFT) & 15;
    rhs->non_system_segment = (flags & DESC_S_MASK) != 0;
    rhs->descriptor_privilege_level = (flags >> DESC_DPL_SHIFT) & 3;
    rhs->present = (flags & DESC_P_MASK) != 0;
    rhs->reserved = 0;
    rhs->available = (flags & DESC_AVL_MASK) != 0;
    rhs->_long = (flags >> DESC_L_SHIFT) & 1;
    rhs->_default = (flags >> DESC_B_SHIFT) & 1;
    rhs->granularity = (flags & DESC_G_MASK) != 0;
}

static void hyperv_set_vtl_cpu_state(CPUX86State *env, struct hv_init_vp_context *c)
{
    env->regs[R_ESP] = c->rsp;
    env->eip = c->rip;
    env->eflags = c->rflags;

    hyperv_set_seg(&env->segs[R_CS], &c->cs);
    hyperv_set_seg(&env->segs[R_DS], &c->ds);
    hyperv_set_seg(&env->segs[R_ES], &c->es);
    hyperv_set_seg(&env->segs[R_FS], &c->fs);
    hyperv_set_seg(&env->segs[R_GS], &c->gs);
    hyperv_set_seg(&env->segs[R_SS], &c->ss);
    hyperv_set_seg(&env->tr, &c->tr);
    hyperv_set_seg(&env->ldt, &c->ldtr);

    env->idt.limit = c->idtr.limit;
    env->idt.base = c->idtr.base;
    env->gdt.limit = c->gdtr.limit;
    env->gdt.base = c->gdtr.base;

    env->efer = c->efer;
    env->cr[0] = c->cr0;
    env->cr[3] = c->cr3;
    env->cr[4] = c->cr4;
    env->pat = c->msr_cr_pat;

    env->mp_state = KVM_MP_STATE_RUNNABLE;

    /*
     * Propagate gs.base and fs.base to initial values for MSR_GS_BASE and
     * MSR_FS_BASE, which are isolated per-VTL but don't have their own fields
     * in initial VP context.
     */
    env->gsbase = c->gs.base;
    env->fsbase = c->fs.base;
}

static void hyperv_save_priv_vtl_state(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    VpVsmState *vpvsm = get_vp_vsm(cs);
    struct kvm_hv_vcpu_per_vtl_state *priv_state = &vpvsm->priv_state;
    struct hv_x64_segment_register rhs;

    priv_state->msr_kernel_gsbase = env->kernelgsbase;
    priv_state->msr_gsbase = env->gsbase;
    priv_state->msr_fsbase = env->fsbase;
    priv_state->msr_tsc_aux = env->tsc_aux;
    priv_state->msr_sysenter_cs = env->sysenter_cs;
    priv_state->msr_sysenter_esp = env->sysenter_esp;
    priv_state->msr_sysenter_eip = env->sysenter_eip;
    priv_state->msr_star = env->star;
    priv_state->msr_lstar = env->lstar;
    priv_state->msr_cstar = env->cstar;
    priv_state->msr_sfmask = env->fmask;
    priv_state->msr_cr_pat = env->pat;
    priv_state->msr_hv_synic_control = env->msr_hv_synic_control;
    priv_state->msr_hv_synic_evt_page = env->msr_hv_synic_evt_page;
    priv_state->msr_hv_synic_msg_page = env->msr_hv_synic_msg_page;
    for (int i = 0; i < HV_SINT_COUNT; i++)
        priv_state->msr_hv_synic_sint[i] = env->msr_hv_synic_sint[i];
    for (int i = 0; i < HV_STIMER_COUNT; i++)
        priv_state->msr_hv_stimer_config[i] = env->msr_hv_stimer_config[i];
    for (int i = 0; i < HV_STIMER_COUNT; i++)
        priv_state->msr_hv_stimer_count[i] = env->msr_hv_stimer_count[i];
    priv_state->msr_hv_guest_os_id = env->msr_hv_guest_os_id;
    priv_state->msr_hv_hypercall = env->msr_hv_hypercall;
    priv_state->msr_hv_tsc = env->msr_hv_tsc;
    priv_state->msr_hv_vp_assist = env->msr_hv_vapic;

    priv_state->rip = env->eip;
    priv_state->rsp = env->regs[R_ESP];
    priv_state->rflags = env->eflags;
    priv_state->efer = env->efer;
    priv_state->cr0 = env->cr[0];
    priv_state->cr3 = env->cr[3];
    priv_state->cr4 = env->cr[4];
    priv_state->dr7 = env->dr[7];

    hyperv_get_seg(&env->segs[R_CS], &rhs);
    memcpy(&priv_state->cs, &rhs, sizeof(priv_state->cs));
    hyperv_get_seg(&env->segs[R_DS], &rhs);
    memcpy(&priv_state->ds, &rhs, sizeof(priv_state->ds));
    hyperv_get_seg(&env->segs[R_ES], &rhs);
    memcpy(&priv_state->es, &rhs, sizeof(priv_state->es));
    hyperv_get_seg(&env->segs[R_FS], &rhs);
    memcpy(&priv_state->fs, &rhs, sizeof(priv_state->fs));
    hyperv_get_seg(&env->segs[R_GS], &rhs);
    memcpy(&priv_state->gs, &rhs, sizeof(priv_state->gs));
    hyperv_get_seg(&env->segs[R_SS], &rhs);
    memcpy(&priv_state->ss, &rhs, sizeof(priv_state->ss));
    hyperv_get_seg(&env->tr, &rhs);
    memcpy(&priv_state->tr, &rhs, sizeof(priv_state->tr));
    hyperv_get_seg(&env->ldt, &rhs);
    memcpy(&priv_state->ldtr, &rhs, sizeof(priv_state->ldtr));

    priv_state->idtr.limit = env->idt.limit;
    priv_state->idtr.base = env->idt.base;
    priv_state->gdtr.limit = env->gdt.limit;
    priv_state->gdtr.base = env->gdt.base;

    priv_state->exception_nr = env->exception_nr;
    priv_state->interrupt_injected = env->interrupt_injected;
    priv_state->soft_interrupt = env->soft_interrupt;
    priv_state->exception_pending = env->exception_pending;
    priv_state->exception_injected = env->exception_injected;
    priv_state->has_error_code = env->has_error_code;
    priv_state->exception_has_payload = env->exception_has_payload;
    priv_state->exception_payload = env->exception_payload;
    priv_state->triple_fault_pending = env->triple_fault_pending;
    priv_state->ins_len = env->ins_len;
    priv_state->sipi_vector = env->sipi_vector;
}

static void hyperv_restore_priv_vtl_state(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    VpVsmState *vpvsm = get_vp_vsm(cs);
    struct kvm_hv_vcpu_per_vtl_state *priv_state = &vpvsm->priv_state;
	struct hv_init_vp_context ctx;
    uint64_t val;

	env->kernelgsbase = priv_state->msr_kernel_gsbase;
	env->gsbase = priv_state->msr_gsbase;
	env->fsbase = priv_state->msr_fsbase;
	env->tsc_aux = priv_state->msr_tsc_aux;
	env->sysenter_cs = priv_state->msr_sysenter_cs;
	env->sysenter_esp = priv_state->msr_sysenter_esp;
	env->sysenter_eip = priv_state->msr_sysenter_eip;
	env->star = priv_state->msr_star;
	env->lstar = priv_state->msr_lstar;
	env->cstar = priv_state->msr_cstar;
	env->fmask = priv_state->msr_sfmask;
    env->msr_hv_synic_control = priv_state->msr_hv_synic_control;
    env->msr_hv_synic_evt_page = priv_state->msr_hv_synic_evt_page;
    env->msr_hv_synic_msg_page = priv_state->msr_hv_synic_msg_page;
    for (int i = 0; i < HV_SINT_COUNT; i++)
        env->msr_hv_synic_sint[i] = priv_state->msr_hv_synic_sint[i];
    for (int i = 0; i < HV_STIMER_COUNT; i++)
        env->msr_hv_stimer_config[i] = priv_state->msr_hv_stimer_config[i];
    for (int i = 0; i < HV_STIMER_COUNT; i++)
        env->msr_hv_stimer_count[i] = priv_state->msr_hv_stimer_count[i];
    env->msr_hv_guest_os_id = priv_state->msr_hv_guest_os_id;
    env->msr_hv_hypercall = priv_state->msr_hv_hypercall;
    env->msr_hv_tsc = priv_state->msr_hv_tsc;
    env->msr_hv_vapic = priv_state->msr_hv_vp_assist;

    env->exception_nr = priv_state->exception_nr;
    env->interrupt_injected = priv_state->interrupt_injected;
    env->soft_interrupt = priv_state->soft_interrupt;
    env->exception_pending = priv_state->exception_pending;
    env->exception_injected = priv_state->exception_injected;
    env->has_error_code = priv_state->has_error_code;
    env->exception_has_payload = priv_state->exception_has_payload;
    env->exception_payload = priv_state->exception_payload;
    env->triple_fault_pending = priv_state->triple_fault_pending;
    env->ins_len = priv_state->ins_len;
    env->sipi_vector = priv_state->sipi_vector;

	memset(&ctx, 0, sizeof(struct hv_init_vp_context));

	ctx.rip = priv_state->rip;
	ctx.rsp = priv_state->rsp;
	ctx.rflags = priv_state->rflags;
	ctx.efer = priv_state->efer;
	ctx.cr0 = priv_state->cr0;
	ctx.cr3 = priv_state->cr3;
	ctx.cr4 = priv_state->cr4;
	ctx.msr_cr_pat = priv_state->msr_cr_pat;

	memcpy(&ctx.cs, &priv_state->cs, sizeof(priv_state->cs));
	memcpy(&ctx.ds, &priv_state->ds, sizeof(priv_state->ds));
	memcpy(&ctx.es, &priv_state->es, sizeof(priv_state->es));
	memcpy(&ctx.fs, &priv_state->fs, sizeof(priv_state->fs));
	memcpy(&ctx.gs, &priv_state->gs, sizeof(priv_state->gs));
	memcpy(&ctx.ss, &priv_state->ss, sizeof(priv_state->ss));
	memcpy(&ctx.tr, &priv_state->tr, sizeof(priv_state->tr));
	memcpy(&ctx.ldtr, &priv_state->ldtr, sizeof(priv_state->ldtr));
	memcpy(&ctx.idtr, &priv_state->idtr, sizeof(priv_state->idtr));
	memcpy(&ctx.gdtr, &priv_state->gdtr, sizeof(priv_state->gdtr));

    ctx.idtr.limit = priv_state->idtr.limit;
    ctx.idtr.base = priv_state->idtr.base;
    ctx.gdtr.limit = priv_state->gdtr.limit;
    ctx.gdtr.base = priv_state->gdtr.base;

    /* Force BSP bit in vCPU 0 */
    //TODO Fix this on non-UP
    val = cpu_get_apic_base(cpu->apic_state);
    val |= MSR_IA32_APICBASE_BSP;
    cpu_set_apic_base(cpu->apic_state, val);

    hyperv_set_vtl_cpu_state(env, &ctx);
}

static void hv_read_vtl_control(CPUState *cs, struct hv_vp_vtl_control *vtl_control)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    if (!vpvsm->vp_assist) {
        printf("BUG calling %s with null vp_assist pointer\n", __func__);
        return;
    }

    memcpy(vtl_control,
           vpvsm->vp_assist + offsetof(struct hv_vp_assist_page, vtl_control),
           sizeof(*vtl_control));
}

static void hv_write_vtl_control(CPUState *cs, struct hv_vp_vtl_control *vtl_control)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    if (!vpvsm->vp_assist) {
        printf("BUG calling %s with null vp_assist pointer\n", __func__);
        return;
    }

    memcpy(vpvsm->vp_assist + offsetof(struct hv_vp_assist_page, vtl_control),
           vtl_control, sizeof(*vtl_control));
}

static bool hyperv_hv_assist_page_enabled(CPUState *cs)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);

    if (!vpvsm)
        return false;

    return !!(vpvsm->vp_assist);
}

enum hv_vtl_entry_reason {
	HV_VTL_ENTRY_RESERVED = 0,
	HV_VTL_ENTRY_VTL_CALL = 1,
	HV_VTL_ENTRY_INTERRUPT = 2,
};

static void set_vtl_entry_reason(CPUState *prev_cs, CPUState *next_cs,
                                 enum hv_vtl_entry_reason reason)
{
    X86CPU *cpu = X86_CPU(prev_cs);
    CPUX86State *prev_env = &cpu->env;
    struct hv_vp_vtl_control vtl_control;

    if (!hyperv_hv_assist_page_enabled(next_cs))
        return;

    vtl_control = (struct hv_vp_vtl_control) {
            .vtl_entry_reason = reason,
            .vtl_ret_x64rax = prev_env->regs[R_EAX],
            .vtl_ret_x64rcx = prev_env->regs[R_ECX],
    };

    hv_write_vtl_control(next_cs, &vtl_control);
}

static void restore_regs_from_vtl_control(CPUState *prev_cs, CPUState *next_cs)
{
    struct hv_vp_vtl_control vtl_control;
    X86CPU *cpu = X86_CPU(next_cs);
    CPUX86State *env = &cpu->env;

    if (!hyperv_hv_assist_page_enabled(prev_cs))
        return;

    hv_read_vtl_control(prev_cs, &vtl_control);
    env->regs[R_EAX] = vtl_control.vtl_ret_x64rax;
    env->regs[R_ECX] = vtl_control.vtl_ret_x64rcx;
}

static void vp_vsm_realize(DeviceState *dev, Error **errp)
{
    VpVsmState *vpvsm = VP_VSM(dev);
    int vtl = get_active_vtl(vpvsm->cs);

    vpvsm->vsm_vp_status.enabled_vtl_set = 1 << 0; /* VTL0 is enabled */
    vpvsm->vsm_vp_status.active_vtl = vtl;
}

static void vp_vsm_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = vp_vsm_realize;
    // TODO
    //dc->unrealize = vp_vsm_unrealize;
    dc->user_creatable = false;
}

static void hyperv_vp_vsm_add(CPUState *cs)
{
    Object *obj = object_new(TYPE_VP_VSM);
    VpVsmState *vpvsm = VP_VSM(obj);

    vpvsm->cs = cs;
    object_property_add_child(OBJECT(cs), "vp-vsm", obj);
    object_unref(obj);
    qdev_realize(DEVICE(obj), NULL, &error_abort);
}

static const TypeInfo vp_vsm_type_info = {
    .name = TYPE_VP_VSM,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(VpVsmState),
    .class_init = vp_vsm_class_init,
};

static void vp_vsm_register_types(void)
{
    type_register_static(&vp_vsm_type_info);
}

type_init(vp_vsm_register_types)

union hv_register_vsm_partition_status hv_vsm_partition_status = {
    .enabled_vtl_set = 1 << 0, /* VTL0 is enabled */
    .maximum_vtl = HV_NUM_VTLS - 1,
};

union hv_register_vsm_capabilities hv_vsm_partition_capabilities = {
    .dr6_shared = 0,
};

union hv_register_vsm_partition_config hv_vsm_partition_config[HV_NUM_VTLS];

uint16_t hyperv_hcall_vtl_enable_partition_vtl(CPUState *cs, uint64_t param1,
                                               uint64_t param2, bool fast)
{
    struct hv_enable_partition_vtl input;
    uint64_t *pinput64 = (uint64_t *)&input;
    /* uint8_t highest_enabled_vtl; */

    // TODO: Implement not fast args
    if (!fast)
        return HV_STATUS_INVALID_HYPERCALL_CODE;

    pinput64[0] = param1;
    pinput64[1] = param2;

    trace_hyperv_hcall_vtl_enable_partition_vtl(
        input.target_partition_id, input.target_vtl, input.flags.as_u8);

    /* Only self-targeting is supported */
    if (input.target_partition_id != HV_PARTITION_ID_SELF)
        return HV_STATUS_INVALID_PARTITION_ID;

    /* We don't declare MBEC support */
    if (input.flags.enable_mbec != 0)
        return HV_STATUS_INVALID_PARAMETER;

    /* Check that target VTL is sane */
    if (input.target_vtl > hv_vsm_partition_status.maximum_vtl)
        return HV_STATUS_INVALID_PARAMETER;

    /* TODO Is target VTL already enabled? */
    if (hv_vsm_partition_status.enabled_vtl_set & (1ul << input.target_vtl))
        return HV_STATUS_INVALID_PARAMETER;

    /*
    * Requestor VP should be running on VTL higher or equal to the new one or
    * at the highest VTL enabled for partition overall if the new one is higher
    * than that
    */
    /* highest_enabled_vtl = fls(hv_vsm_partition_status.enabled_vtl_set) - 1; */
    /* if (get_active_vtl(vcpu) < input.target_vtl && get_active_vtl(vcpu) !=
    * highest_enabled_vtl) */
    /* return HV_STATUS_INVALID_PARAMETER; */

    /*
     * TODO: Double-check the number of vCPUs is correct? Maybe can be done
     * dynically? hv-vsm-num-vtls=2 -> updates ms->smp.max_cpus?
     */

    hv_vsm_partition_status.enabled_vtl_set |= (1ul << input.target_vtl);
    return HV_STATUS_SUCCESS;
}

static CPUState* hyperv_init_vtl_vcpu(CPUState *cpu, int32_t vp_index, unsigned int vtl)
{
    X86MachineState *x86ms = X86_MACHINE(qdev_get_machine());
    CPUState *new_cpu;

    qemu_mutex_lock_iothread();
    //TODO Only works on UP
    x86_cpu_new(x86ms, x86_apic_id_set_group(vp_index, vtl), &error_warn);
    qemu_mutex_unlock_iothread();
    new_cpu = hyperv_vsm_vcpu(vp_index, vtl);
    new_cpu->poll_callback = hyperv_poll_callback;
    return new_cpu;
}

uint16_t hyperv_hcall_vtl_enable_vp_vtl(CPUState *cs, uint64_t param, bool fast)
{
    struct hv_enable_vp_vtl *input;
    uint64_t len = sizeof(*input);
    CPUState *target_vcpu, *vtl_cpu;
    APICCommonState *apic_state;
    APICCommonClass *apic_class;
    int ret = 0;

    /* Neither continuations not fast calls are possible for this call */
    if (fast)
        return HV_STATUS_INVALID_HYPERCALL_INPUT;

    input = cpu_physical_memory_map(param, &len, 0);
    if (len < sizeof(*input)) {
        ret = HV_STATUS_INVALID_PARAMETER;
        goto unmap;
    }

    trace_hyperv_hcall_vtl_enable_vp_vtl(input->partition_id, input->vp_index,
                                         input->target_vtl.as_uint8);

    /* Only self-targeting is supported */
    if (input->partition_id != HV_PARTITION_ID_SELF) {
        ret = HV_STATUS_INVALID_PARTITION_ID;
        goto unmap;
    }

    /* Handle VP index argument */
    //TODO this only works for UP
    if (input->vp_index != HV_VP_INDEX_SELF && input->vp_index) {
        ret = HV_STATUS_INVALID_VP_INDEX;
        goto unmap;
    }

    if (input->vp_index != HV_VP_INDEX_SELF && input->vp_index != cs->cpu_index) {
        target_vcpu = hyperv_vsm_vcpu(input->vp_index, get_active_vtl(cs));
        if (!target_vcpu) {
            ret = HV_STATUS_INVALID_VP_INDEX;
            goto unmap;
        }
    } else {
        target_vcpu = cs;
    }

    /* Check that target VTL is sane */
    if (input->target_vtl.target_vtl > hv_vsm_partition_status.maximum_vtl) {
        ret = HV_STATUS_INVALID_PARAMETER;
        goto unmap;
    }

    /* Is target VTL already enabled for partition? */
    if ((hv_vsm_partition_status.enabled_vtl_set & (1ul << input->target_vtl.target_vtl)) == 0) {
        ret = HV_STATUS_INVALID_PARAMETER;
        goto unmap;
    }

    if (!get_vp_vsm(target_vcpu))
        hyperv_vp_vsm_add(target_vcpu);

    /* Is target VTL already enabled for target vcpu? */
    if (get_vp_vsm(target_vcpu)->vsm_vp_status.enabled_vtl_set & (1ul << input->target_vtl.target_vtl)) {
      ret = HV_STATUS_INVALID_PARAMETER;
      goto unmap;
    }

    /*
     * Requestor VP should be running on vtl higher or equal to the new one or
     * it needs to be running on a highest VTL any VP has enabled
     * TODO: find alternative to fls()... I'm lazy
     */
    /* highest_vp_enabled_vtl = fls(hv->vtl_enabled_for_vps) - 1; */
    /* if (get_active_vtl(requestor_vcpu) < input.target_vtl.target_vtl && */
        /* get_active_vtl(requestor_vcpu) != highest_vp_enabled_vtl) */
        /* return HV_STATUS_INVALID_PARAMETER; */

    vtl_cpu = hyperv_init_vtl_vcpu(target_vcpu, target_vcpu->cpu_index,
                                   input->target_vtl.target_vtl);
    if (!vtl_cpu) {
        printf("%s:%d Failed to init vtl vcpu\n", __func__, __LINE__);
        ret = HV_STATUS_INVALID_PARAMETER;
        goto unmap;
    }
    hyperv_vp_vsm_add(vtl_cpu);
    hyperv_set_vtl_cpu_state(&X86_CPU(vtl_cpu)->env, &input->vp_context);

    /*
     * Windows Server 2019 guest expects VTL1+ apics to be sw-enabled by the fact
     * that they never try to write anything to SPIV before attempting to send IPIs.
     * So enable a new apic for them. If they ever change their mind, they will set
     * their own SPIV value
     */
    apic_state = APIC_COMMON(X86_CPU(vtl_cpu)->apic_state);
    apic_class = APIC_COMMON_GET_CLASS(apic_state);
    apic_state->spurious_vec = 0x1ff;
    qemu_mutex_lock_iothread();
    apic_class->reset(apic_state);
    qemu_mutex_unlock_iothread();

    /* TODO For VTL2+ We need to always keep track of enabled_vtl_set in the
     * VTL0 VpVsmState */
    get_vp_vsm(target_vcpu)->vsm_vp_status.enabled_vtl_set |= 1 << input->target_vtl.target_vtl;

unmap:
    cpu_physical_memory_unmap(input, len, 0, 0);
    return ret;
}

void hyperv_setup_vp_assist(CPUState *cs, uint64_t data)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    hwaddr gpa = data & HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;
    hwaddr len = 1 << HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT;
    bool enable = !!(data & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE);

    trace_hyperv_setup_vp_assist(hyperv_vp_index(cs), get_active_vtl(cs), enable, gpa);

    if (!vpvsm)
        return;

    if (vpvsm->vp_assist)
        cpu_physical_memory_unmap(vpvsm->vp_assist, len, 0, 0);

    if (!enable)
        return;

    vpvsm->vp_assist = cpu_physical_memory_map(gpa, &len, 0);
    if (!vpvsm->vp_assist) {
        printf("Failed to map VP assit page");
        return;
    }
}

#define VTL_INTERRUPT_PENDING   BIT(0)
#define VTL_CALL_PENDING        BIT(1)

static unsigned int vtl_event_state;
static bool vtl_event_handled;

static void do_vtl1_entry(CPUState *vtl1, run_on_cpu_data arg)
{
    CPUX86State *vtl1_env = &X86_CPU(vtl1)->env;
    CPUState *vtl0 = hyperv_get_prev_vtl(vtl1);
    CPUX86State *vtl0_env = &X86_CPU(vtl0)->env;

    hyperv_save_priv_vtl_state(vtl1);
    memcpy(vtl1_env, vtl0_env, sizeof(*vtl1_env));
    hyperv_restore_priv_vtl_state(vtl1);
    set_vtl_entry_reason(vtl0, vtl1, vtl_event_state & VTL_CALL_PENDING ?
                         HV_VTL_ENTRY_VTL_CALL : HV_VTL_ENTRY_INTERRUPT);
    cpu_synchronize_post_reset(vtl1);
    vtl1->stop = false;
    vtl1->stopped = false;
}

static void do_vtl0_upcall(CPUState *vtl0, run_on_cpu_data arg)
{
    CPUState *vtl1 = hyperv_get_next_vtl(vtl0);

    if (vtl_event_handled)
        return;

    cpu_synchronize_state(vtl0);
    vtl_event_handled = true;
    vtl0->stop = true;
    async_run_on_cpu(vtl1, do_vtl1_entry, RUN_ON_CPU_NULL);
}

static void do_vtl0_downcall(CPUState *vtl0, run_on_cpu_data arg)
{
    CPUX86State *vtl0_env = &X86_CPU(vtl0)->env;
    CPUState *vtl1 = hyperv_get_next_vtl(vtl0);
    CPUX86State *vtl1_env = &X86_CPU(vtl1)->env;

    hyperv_save_priv_vtl_state(vtl0);
    memcpy(vtl0_env, vtl1_env, sizeof(*vtl1_env));
    hyperv_restore_priv_vtl_state(vtl0);
    restore_regs_from_vtl_control(vtl1, vtl0);
    cpu_synchronize_post_reset(vtl0);
    vtl_event_handled = false;
    vtl_event_state = 0;
    vtl0->stop = false;
    vtl0->stopped = false;
}

int hyperv_hcall_vtl_call(CPUState *vtl0)
{
    CPUState *vtl1 = hyperv_get_next_vtl(vtl0);

    trace_hyperv_hcall_vtl_call(get_active_vtl(vtl0),
                                get_active_vtl(vtl1));

    /* vtl1 wasn't initialized? */
    if (!vtl1)
        return -1;

    /* We only support vtl0<->vtl1 */
    if (get_active_vtl(vtl0) > 1)
        return -1;

    vtl0->stop = true;
    qatomic_or(&vtl_event_state, VTL_CALL_PENDING);
    async_run_on_cpu(vtl0, do_vtl0_upcall, RUN_ON_CPU_NULL);

    return EXCP_HALTED;
}

int hyperv_hcall_vtl_return(CPUState *vtl1)
{
    CPUState *vtl0 = hyperv_get_prev_vtl(vtl1);

    trace_hyperv_hcall_vtl_return(get_active_vtl(vtl1),
                                  get_active_vtl(vtl0), 0);
    vtl1->stop = true;
    vtl1->poll = true;
    cpu_synchronize_state(vtl1);
    async_run_on_cpu(vtl0, do_vtl0_downcall, RUN_ON_CPU_NULL);

    return EXCP_HALTED;
}

void hyperv_poll_callback(CPUState *vtl1, short int events)
{
    CPUState *vtl0 = hyperv_get_prev_vtl(vtl1);

    if (!(events & POLLIN))
        return;

    vtl0->stop = true;
    vtl1->poll = false;
    qatomic_or(&vtl_event_state, VTL_INTERRUPT_PENDING);
    async_run_on_cpu(vtl0, do_vtl0_upcall, RUN_ON_CPU_NULL);

    trace_hyperv_hcall_vtl_interrupt(get_active_vtl(vtl0),
                                     get_active_vtl(vtl1));

}

static bool get_vsm_vp_secure_vtl_config(CPUState *cs, uint32_t reg, uint64_t *pdata)
{
    int reg_vtl = reg - HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0;
    int target_vtl = get_active_vtl(cs);

    /* Register VTL level should be 1 below the VTL we are requesting it for (and
    * VTL0 is never correct) */
    if (target_vtl == 0 || (reg_vtl >= target_vtl))
        return false;

    *pdata = get_vp_vsm(cs)->vsm_vtl_config[reg_vtl].as_u64;

    return true;
}

static bool set_vsm_vp_secure_vtl_config(CPUState *cs, uint32_t reg, uint64_t data)
{
    union hv_register_vsm_vp_secure_vtl_config new_val = {.as_u64 = data};
    int reg_vtl = reg - HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0;
    int target_vtl = get_active_vtl(cs);

    /* Register VTL level should be 1 below the VTL we are requesting it for (and
    * VTL0 is never correct) */
    if (target_vtl == 0 || (reg_vtl >= target_vtl))
        return false;

    /* Can't enable MBEC for VTL which does not support it */
    if (new_val.mbec_enabled && !(hv_vsm_partition_capabilities.mbec_vtl_mask & 1))
        printf("Hyper-V: MBEC capability not implemented, ignoring\n");

    get_vp_vsm(cs)->vsm_vtl_config[reg_vtl] = new_val;
    return true;
}

static void set_vsm_partition_config(uint8_t vtl, uint64_t data)
{
	union hv_register_vsm_partition_config new_val = { .as_u64 = data };

	/* enable_vtl_protection bit and default protection mask are write-once after first enabled */
	if (hv_vsm_partition_config[vtl].enable_vtl_protection) {
		new_val.enable_vtl_protection = hv_vsm_partition_config[vtl].enable_vtl_protection;
		new_val.default_vtl_protection_mask = hv_vsm_partition_config[vtl].default_vtl_protection_mask;
	}

	/* We are not advertising StartVirtualProcessor partition priviledge,
	 * so requesting those intercepts is ignored (but warned about) */
	if (new_val.intercept_vp_startup || new_val.deny_lower_vtl_startup)
		printf("VSM: guest trying to intercept VP startup when it is not advertised");

	hv_vsm_partition_config[vtl] = new_val;
}

static uint64_t get_vp_register(uint32_t name, struct hv_vp_register_val *val,
                                CPUState *target_vcpu)
{
    VpVsmState *vpvsm = get_vp_vsm(target_vcpu);
    struct hv_x64_segment_register rhs;
    struct hv_x64_table_register tr;
    CPUX86State *env;
    X86CPU *cpu;

    val->low = val->high = 0;
    cpu = X86_CPU(target_vcpu);
    env = &cpu->env;

    switch (name) {
    case HV_X64_REGISTER_RSP:
        val->low = env->regs[R_ESP];
        break;
    case HV_X64_REGISTER_RIP:
        val->low = env->eip;
        break;
    case HV_X64_REGISTER_RFLAGS:
        val->low = env->eflags;
        break;
    case HV_X64_REGISTER_CR0:
        val->low = env->cr[0];
        break;
    case HV_X64_REGISTER_CR3:
        val->low = env->cr[3];
        break;
    case HV_X64_REGISTER_CR4:
        val->low = env->cr[4];
        break;
    case HV_X64_REGISTER_CR8:
        val->low = cpu_get_apic_tpr(cpu->apic_state);
        break;
    case HV_X64_REGISTER_DR7:
        val->low = env->dr[7];
        break;
    case HV_X64_REGISTER_LDTR:
        hyperv_get_seg(&env->ldt, &rhs);
        memcpy(val, &rhs, sizeof(rhs));
        break;
    case HV_X64_REGISTER_TR:
        hyperv_get_seg(&env->tr, &rhs);
        memcpy(val, &rhs, sizeof(rhs));
        break;
    case HV_X64_REGISTER_IDTR:
        tr.limit = env->idt.limit;
        tr.base = env->idt.base;
        memcpy(val, &tr, sizeof(tr));
        break;
    case HV_X64_REGISTER_GDTR:
        tr.limit = env->gdt.limit;
        tr.base = env->gdt.base;
        memcpy(val, &tr, sizeof(tr));
        break;
    case HV_X64_REGISTER_EFER:
        val->low = env->efer;
        break;
    case HV_X64_REGISTER_SYSENTER_CS:
        val->low = env->sysenter_cs;
        break;
    case HV_X64_REGISTER_SYSENTER_EIP:
        val->low = env->sysenter_eip;
        break;
    case HV_X64_REGISTER_SYSENTER_ESP:
        val->low = env->sysenter_esp;
        break;
    case HV_X64_REGISTER_STAR:
        val->low = env->star;
        break;
#ifdef TARGET_X86_64
    case HV_X64_REGISTER_LSTAR:
        val->low = env->lstar;
        break;
    case HV_X64_REGISTER_CSTAR:
        val->low = env->cstar;
        break;
    case HV_X64_REGISTER_SFMASK:
        val->low = env->fmask;
        break;
#endif
    case HV_X64_REGISTER_TSC_AUX:
        val->low = env->tsc_aux;
        break;
    case HV_X64_REGISTER_APIC_BASE:
        val->low = cpu_get_apic_base(X86_CPU(target_vcpu)->apic_state);
        break;
    case HV_REGISTER_VSM_CAPABILITIES:
        val->low = hv_vsm_partition_capabilities.as_u64;
        break;
    case HV_REGISTER_VSM_PARTITION_STATUS:
        val->low = hv_vsm_partition_status.as_u64;
        break;
    case HV_REGISTER_VSM_VP_STATUS:
        val->low = vpvsm->vsm_vp_status.as_u64;
        break;
    case HV_REGISTER_VSM_PARTITION_CONFIG:
        /*
		 * This is the only partition wide per-VTL register. Relies on atomicity
		 * of 64 bits on x86 to avoid taking a partition-wide VTL lock.
         * TODO: think about the locking
         */
        val->low = hv_vsm_partition_config[get_active_vtl(target_vcpu)].as_u64;
        break;
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL1:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL2:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL3:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL4:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL5:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL6:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL7:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL8:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL9:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL10:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL11:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL12:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL13:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14:
        if (!get_vsm_vp_secure_vtl_config(target_vcpu, name, &val->low))
            return HV_STATUS_INVALID_PARAMETER;
        break;
    case HV_REGISTER_VP_ASSIST_PAGE:
        val->low = env->msr_hv_vapic;
        break;
    case HV_REGISTER_VSM_CODE_PAGE_OFFSETS:
        val->low = env->vsm_code_page_offsets;
        break;
    default:
        printf("%s: unknown VP register 0x%x\n", __func__, name);
        return HV_STATUS_INVALID_PARAMETER;
    };

    trace_hyperv_get_vp_register(name, val->low, val->high);
    return HV_STATUS_SUCCESS;
}

static uint64_t set_vp_register(uint32_t name, struct hv_vp_register_val *val,
                                CPUState *target_vcpu, bool *dirty)
{
    struct hv_x64_segment_register rhs;
    struct hv_x64_table_register tr;
    CPUX86State *env;
    X86CPU *cpu;

    cpu = X86_CPU(target_vcpu);
    env = &cpu->env;

    /* printf("name %x, val %llx, cpuid %d\n", name, val->low, target_vcpu->cpu_index); */
    trace_hyperv_set_vp_register(name, val->low, val->high);

    switch (name) {
    case HV_X64_REGISTER_RSP:
        env->regs[REG_RSP] = val->low;
        break;
    case HV_X64_REGISTER_RIP:
        env->eip = val->low;
        break;
    case HV_X64_REGISTER_RFLAGS:
        env->eflags = val->low;
        break;
    case HV_X64_REGISTER_CR0:
        env->cr[0] = val->low;
        break;
    case HV_X64_REGISTER_CR3:
        env->cr[3] = val->low;
        break;
    case HV_X64_REGISTER_CR4:
        env->cr[4] = val->low;
        break;
    case HV_X64_REGISTER_CR8:
        cpu_set_apic_tpr(cpu->apic_state, val->low);
        break;
    case HV_X64_REGISTER_DR7:
        env->dr[7] = val->low;
        break;
    case HV_X64_REGISTER_LDTR:
        memcpy(&rhs, val, sizeof(*val));
        hyperv_set_seg(&env->ldt, &rhs);
        break;
    case HV_X64_REGISTER_TR:
        memcpy(&rhs, val, sizeof(*val));
        hyperv_set_seg(&env->tr, &rhs);
        break;
    case HV_X64_REGISTER_IDTR:
        memcpy(&tr, val, sizeof(*val));
        env->idt.base = tr.base;
        env->idt.limit = tr.limit;
        break;
    case HV_X64_REGISTER_GDTR:
        memcpy(&tr, val, sizeof(*val));
        env->gdt.base = tr.base;
        env->gdt.limit = tr.limit;
        break;
    case HV_X64_REGISTER_EFER:
        env->efer = val->low;
        break;
    case HV_X64_REGISTER_SYSENTER_CS:
        env->sysenter_cs = val->low;
        break;
    case HV_X64_REGISTER_SYSENTER_EIP:
        env->sysenter_eip = val->low;
        break;
    case HV_X64_REGISTER_SYSENTER_ESP:
        env->sysenter_esp = val->low;
        break;
    case HV_X64_REGISTER_STAR:
        env->star = val->low;
        break;
    case HV_X64_REGISTER_LSTAR:
        env->lstar = val->low;
        break;
    case HV_X64_REGISTER_CSTAR:
        env->cstar = val->low;
        break;
    case HV_X64_REGISTER_SFMASK:
        env->fmask = val->low;
        break;
    case HV_X64_REGISTER_TSC_AUX:
        env->tsc_aux = val->low;
        break;
    case HV_REGISTER_VSM_PARTITION_CONFIG:
        set_vsm_partition_config(get_active_vtl(target_vcpu), val->low);
        break;
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL1:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL2:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL3:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL4:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL5:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL6:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL7:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL8:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL9:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL10:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL11:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL12:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL13:
    case HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL14:
        if (!set_vsm_vp_secure_vtl_config(target_vcpu, name, val->low))
            return HV_STATUS_INVALID_PARAMETER;
        break;
    case HV_X64_REGISTER_PENDING_EVENT0: {
        union hv_x64_pending_exception_event event = {
            .as_u64[0] = val->low,
            .as_u64[1] = val->high,
        };

        if (!event.event_pending)
            break;

        if (event.event_type == HV_X64_PENDING_EVENT_EXCEPTION)
            kvm_queue_exception(env, event.vector, event.deliver_error_code,
                                event.error_code, false, 0);
        else
            printf("%s, Unknown event type %d\n", __func__, event.event_type);

        break;
    }
    case HV_REGISTER_VP_ASSIST_PAGE:
        env->msr_hv_vapic = val->low;
        hyperv_setup_vp_assist(target_vcpu, val->low);
        break;
    case HV_REGISTER_VSM_VINA:
    case HV_X64_REGISTER_CR_INTERCEPT_CONTROL:
    case HV_X64_REGISTER_CR_INTERCEPT_CR0_MASK:
    case HV_X64_REGISTER_CR_INTERCEPT_CR4_MASK:
    case HV_X64_REGISTER_CR_INTERCEPT_IA32_MISC_ENABLE_MASK:
        printf("%s: faking register 0x%x\n", __func__, name);
        return HV_STATUS_SUCCESS;
    default:
        printf("%s: unknown VP register 0x%x\n", __func__, name);
        return HV_STATUS_INVALID_PARAMETER;
    };

    *dirty = true;
    return HV_STATUS_SUCCESS;
}

/* This is not a spec limit, but rather something we use to limit stack memory usage */
//TODO get rid of this
#define KVM_HV_VP_REGISTER_LIST_SIZE 16u

uint64_t hyperv_hcall_get_set_vp_register(CPUState *cs, struct kvm_hyperv_exit *exit,
                                          bool set)
{
    uint16_t rep_cnt = (exit->u.hcall.input >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (exit->u.hcall.input >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    struct hv_vp_register_val vals[KVM_HV_VP_REGISTER_LIST_SIZE];
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    uint32_t names[KVM_HV_VP_REGISTER_LIST_SIZE];
    struct hv_get_set_vp_registers input;
    __u64 *xmm = &exit->u.hcall.xmm[0];
    uint16_t xmm_index = 0;
    CPUState *target_vcpu;
    bool dirty = false;
    uint16_t nregs;
    uint8_t vtl;
    int status;

    nregs = rep_cnt - rep_idx;
    nregs = nregs > KVM_HV_VP_REGISTER_LIST_SIZE ? KVM_HV_VP_REGISTER_LIST_SIZE : nregs;

    if (fast) {

        input.partition_id = exit->u.hcall.ingpa;
        input.vp_index = exit->u.hcall.outgpa & 0xFFFFFFFF;
        input.input_vtl.as_uint8 = (exit->u.hcall.outgpa >> 32) & 0xFF;

        /* We always return everything for fast calls, so no continuations should be
         * possible */
        if (rep_idx != 0)
            return HV_STATUS_INVALID_HYPERCALL_INPUT;

        /* We can never fit more than 4 registers in 6 XMM input regs even if
         * rep_idx is 0 */
        if (nregs > 4)
            return HV_STATUS_INVALID_HYPERCALL_INPUT;

        for (int i = 0; i < nregs; i += 4, xmm_index += 2) {
            names[i] = xmm[xmm_index];
            names[i + 1] = xmm[xmm_index] >> 32;
            names[i + 2] = xmm[xmm_index + 1];
            names[i + 3] = xmm[xmm_index + 1] >> 32;
        }

        if (set) {
            /* Register values follow names */
            for (int i = 0; i < nregs; i++, xmm_index += 2) {
                vals[i].low = xmm[xmm_index];
                vals[i].high = xmm[xmm_index + 1];
            }
        }
    } else {
        uint64_t ingpa = exit->u.hcall.ingpa;

        cpu_physical_memory_read(ingpa, &input, sizeof(input));

        ingpa += sizeof(input) + rep_idx * sizeof(*names);
        cpu_physical_memory_read(ingpa, names, nregs * sizeof(*names));

        if (set) {
            /* According to TLFS, values start aligned on 16-byte boundary after names
            */
            ingpa = ROUND_UP(ingpa + nregs * sizeof(*names), 16) +
                  rep_idx * sizeof(*vals);
            cpu_physical_memory_read(ingpa, vals, nregs * sizeof(*vals));
        }
    }

    /* Handle partition ID (the only supported id is self) */
    if (input.partition_id != HV_PARTITION_ID_SELF) {
        return HV_STATUS_INVALID_PARTITION_ID;
    }

    /* Handle target VTL we should use */
    if (input.input_vtl.use_target_vtl) {
        vtl = input.input_vtl.target_vtl;

        if (vtl >= HV_NUM_VTLS) {
            return HV_STATUS_INVALID_HYPERCALL_INPUT;
        }

        if (vtl > get_active_vtl(cs)) {
            return HV_STATUS_ACCESS_DENIED;
        }
    } else {
        vtl = get_active_vtl(cs);
    }

    /* Handle VP index argument */
    //TODO this is only valid for UP
    if (input.vp_index != HV_VP_INDEX_SELF && input.vp_index)
        return HV_STATUS_INVALID_VP_INDEX;

    if (input.vp_index != HV_VP_INDEX_SELF && input.vp_index != get_active_vtl(cs)) {
        target_vcpu = hyperv_vsm_vcpu(input.vp_index, vtl);
        if (!target_vcpu)
          return HV_STATUS_INVALID_VP_INDEX;
    } else {
        target_vcpu = hyperv_vsm_vcpu(hyperv_vsm_vp_index(cs), vtl);
    }

    trace_hyperv_hcall_get_set_vp_register(input.partition_id, input.vp_index,
                                           vtl, get_active_vtl(cs), nregs, set);

    //TODO Think deeper about locking here...
    qemu_mutex_lock_iothread();
    cpu_synchronize_state(target_vcpu);
    /* Handle actual registers */
    for (int i = 0; i < nregs; ++i) {
        status = set ? set_vp_register(names[i], &vals[i], target_vcpu, &dirty):
                       get_vp_register(names[i], &vals[i], target_vcpu);
        if (status != HV_STATUS_SUCCESS)
            break;
    }
    if (dirty)
        cpu_synchronize_post_reset(target_vcpu);
    qemu_mutex_unlock_iothread();

    if (status != HV_STATUS_SUCCESS)
        return status;

    /* Return results to guest */
    if (!set) {
        if (fast) {
            for (int i = 0; i < nregs; ++i, xmm_index += 2) {
                xmm[xmm_index] = vals[i].low;
                xmm[xmm_index + 1] = vals[i].high;
            }
        } else {
            uint64_t outgpa = exit->u.hcall.outgpa + rep_idx * sizeof(*vals);
            cpu_physical_memory_write(outgpa, vals, sizeof(*vals) * nregs);
        }
    }

    return (uint64_t)HV_STATUS_SUCCESS | ((uint64_t)nregs << HV_HYPERCALL_REP_COMP_OFFSET);
}

uint16_t hyperv_hcall_post_message(uint64_t param, bool fast)
{
    uint16_t ret;
    hwaddr len;
    struct hyperv_post_message_input *msg;
    MsgHandler *mh;

    if (fast) {
        return HV_STATUS_INVALID_HYPERCALL_CODE;
    }
    if (param & (__alignof__(*msg) - 1)) {
        return HV_STATUS_INVALID_ALIGNMENT;
    }

    len = sizeof(*msg);
    msg = cpu_physical_memory_map(param, &len, 0);
    if (len < sizeof(*msg)) {
        ret = HV_STATUS_INSUFFICIENT_MEMORY;
        goto unmap;
    }
    if (msg->payload_size > sizeof(msg->payload)) {
        ret = HV_STATUS_INVALID_HYPERCALL_INPUT;
        goto unmap;
    }

    ret = HV_STATUS_INVALID_CONNECTION_ID;
    WITH_RCU_READ_LOCK_GUARD() {
        QLIST_FOREACH_RCU(mh, &msg_handlers, link) {
            if (mh->conn_id == (msg->connection_id & HV_CONNECTION_ID_MASK)) {
                ret = mh->handler(msg, mh->data);
                break;
            }
        }
    }

unmap:
    cpu_physical_memory_unmap(msg, len, 0, 0);
    return ret;
}

static int set_event_flag_handler(uint32_t conn_id, EventNotifier *notifier)
{
    int ret;
    EventFlagHandler *handler;

    QEMU_LOCK_GUARD(&handlers_mutex);
    QLIST_FOREACH(handler, &event_flag_handlers, link) {
        if (handler->conn_id == conn_id) {
            if (notifier) {
                ret = -EEXIST;
            } else {
                QLIST_REMOVE_RCU(handler, link);
                g_free_rcu(handler, rcu);
                ret = 0;
            }
            return ret;
        }
    }

    if (notifier) {
        handler = g_new(EventFlagHandler, 1);
        handler->conn_id = conn_id;
        handler->notifier = notifier;
        QLIST_INSERT_HEAD_RCU(&event_flag_handlers, handler, link);
        ret = 0;
    } else {
        ret = -ENOENT;
    }

    return ret;
}

static bool process_event_flags_userspace;

int hyperv_set_event_flag_handler(uint32_t conn_id, EventNotifier *notifier)
{
    if (!process_event_flags_userspace &&
        !kvm_check_extension(kvm_state, KVM_CAP_HYPERV_EVENTFD)) {
        process_event_flags_userspace = true;

        warn_report("Hyper-V event signaling is not supported by this kernel; "
                    "using slower userspace hypercall processing");
    }

    if (!process_event_flags_userspace) {
        struct kvm_hyperv_eventfd hvevfd = {
            .conn_id = conn_id,
            .fd = notifier ? event_notifier_get_fd(notifier) : -1,
            .flags = notifier ? 0 : KVM_HYPERV_EVENTFD_DEASSIGN,
        };

        return kvm_vm_ioctl(kvm_state, KVM_HYPERV_EVENTFD, &hvevfd);
    }
    return set_event_flag_handler(conn_id, notifier);
}

uint16_t hyperv_hcall_signal_event(uint64_t param, bool fast)
{
    EventFlagHandler *handler;

    if (unlikely(!fast)) {
        hwaddr addr = param;

        if (addr & (__alignof__(addr) - 1)) {
            return HV_STATUS_INVALID_ALIGNMENT;
        }

        param = ldq_phys(&address_space_memory, addr);
    }

    /*
     * Per spec, bits 32-47 contain the extra "flag number".  However, we
     * have no use for it, and in all known usecases it is zero, so just
     * report lookup failure if it isn't.
     */
    if (param & 0xffff00000000ULL) {
        return HV_STATUS_INVALID_PORT_ID;
    }
    /* remaining bits are reserved-zero */
    if (param & ~HV_CONNECTION_ID_MASK) {
        return HV_STATUS_INVALID_HYPERCALL_INPUT;
    }

    RCU_READ_LOCK_GUARD();
    QLIST_FOREACH_RCU(handler, &event_flag_handlers, link) {
        if (handler->conn_id == param) {
            event_notifier_set(handler->notifier);
            return 0;
        }
    }
    return HV_STATUS_INVALID_CONNECTION_ID;
}

static HvSynDbgHandler hv_syndbg_handler;
static void *hv_syndbg_context;

void hyperv_set_syndbg_handler(HvSynDbgHandler handler, void *context)
{
    assert(!hv_syndbg_handler);
    hv_syndbg_handler = handler;
    hv_syndbg_context = context;
}

uint16_t hyperv_hcall_reset_dbg_session(uint64_t outgpa)
{
    uint16_t ret;
    HvSynDbgMsg msg;
    struct hyperv_reset_debug_session_output *reset_dbg_session = NULL;
    hwaddr len;

    if (!hv_syndbg_handler) {
        ret = HV_STATUS_INVALID_HYPERCALL_CODE;
        goto cleanup;
    }

    len = sizeof(*reset_dbg_session);
    reset_dbg_session = cpu_physical_memory_map(outgpa, &len, 1);
    if (!reset_dbg_session || len < sizeof(*reset_dbg_session)) {
        ret = HV_STATUS_INSUFFICIENT_MEMORY;
        goto cleanup;
    }

    msg.type = HV_SYNDBG_MSG_CONNECTION_INFO;
    ret = hv_syndbg_handler(hv_syndbg_context, &msg);
    if (ret) {
        goto cleanup;
    }

    reset_dbg_session->host_ip = msg.u.connection_info.host_ip;
    reset_dbg_session->host_port = msg.u.connection_info.host_port;
    /* The following fields are only used as validation for KDVM */
    memset(&reset_dbg_session->host_mac, 0,
           sizeof(reset_dbg_session->host_mac));
    reset_dbg_session->target_ip = msg.u.connection_info.host_ip;
    reset_dbg_session->target_port = msg.u.connection_info.host_port;
    memset(&reset_dbg_session->target_mac, 0,
           sizeof(reset_dbg_session->target_mac));
cleanup:
    if (reset_dbg_session) {
        cpu_physical_memory_unmap(reset_dbg_session,
                                  sizeof(*reset_dbg_session), 1, len);
    }

    return ret;
}

uint16_t hyperv_hcall_retreive_dbg_data(uint64_t ingpa, uint64_t outgpa,
                                        bool fast)
{
    uint16_t ret;
    struct hyperv_retrieve_debug_data_input *debug_data_in = NULL;
    struct hyperv_retrieve_debug_data_output *debug_data_out = NULL;
    hwaddr in_len, out_len;
    HvSynDbgMsg msg;

    if (fast || !hv_syndbg_handler) {
        ret = HV_STATUS_INVALID_HYPERCALL_CODE;
        goto cleanup;
    }

    in_len = sizeof(*debug_data_in);
    debug_data_in = cpu_physical_memory_map(ingpa, &in_len, 0);
    if (!debug_data_in || in_len < sizeof(*debug_data_in)) {
        ret = HV_STATUS_INSUFFICIENT_MEMORY;
        goto cleanup;
    }

    out_len = sizeof(*debug_data_out);
    debug_data_out = cpu_physical_memory_map(outgpa, &out_len, 1);
    if (!debug_data_out || out_len < sizeof(*debug_data_out)) {
        ret = HV_STATUS_INSUFFICIENT_MEMORY;
        goto cleanup;
    }

    msg.type = HV_SYNDBG_MSG_RECV;
    msg.u.recv.buf_gpa = outgpa + sizeof(*debug_data_out);
    msg.u.recv.count = TARGET_PAGE_SIZE - sizeof(*debug_data_out);
    msg.u.recv.options = debug_data_in->options;
    msg.u.recv.timeout = debug_data_in->timeout;
    msg.u.recv.is_raw = true;
    ret = hv_syndbg_handler(hv_syndbg_context, &msg);
    if (ret == HV_STATUS_NO_DATA) {
        debug_data_out->retrieved_count = 0;
        debug_data_out->remaining_count = debug_data_in->count;
        goto cleanup;
    } else if (ret != HV_STATUS_SUCCESS) {
        goto cleanup;
    }

    debug_data_out->retrieved_count = msg.u.recv.retrieved_count;
    debug_data_out->remaining_count =
        debug_data_in->count - msg.u.recv.retrieved_count;
cleanup:
    if (debug_data_out) {
        cpu_physical_memory_unmap(debug_data_out, sizeof(*debug_data_out), 1,
                                  out_len);
    }

    if (debug_data_in) {
        cpu_physical_memory_unmap(debug_data_in, sizeof(*debug_data_in), 0,
                                  in_len);
    }

    return ret;
}

uint16_t hyperv_hcall_post_dbg_data(uint64_t ingpa, uint64_t outgpa, bool fast)
{
    uint16_t ret;
    struct hyperv_post_debug_data_input *post_data_in = NULL;
    struct hyperv_post_debug_data_output *post_data_out = NULL;
    hwaddr in_len, out_len;
    HvSynDbgMsg msg;

    if (fast || !hv_syndbg_handler) {
        ret = HV_STATUS_INVALID_HYPERCALL_CODE;
        goto cleanup;
    }

    in_len = sizeof(*post_data_in);
    post_data_in = cpu_physical_memory_map(ingpa, &in_len, 0);
    if (!post_data_in || in_len < sizeof(*post_data_in)) {
        ret = HV_STATUS_INSUFFICIENT_MEMORY;
        goto cleanup;
    }

    if (post_data_in->count > TARGET_PAGE_SIZE - sizeof(*post_data_in)) {
        ret = HV_STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    out_len = sizeof(*post_data_out);
    post_data_out = cpu_physical_memory_map(outgpa, &out_len, 1);
    if (!post_data_out || out_len < sizeof(*post_data_out)) {
        ret = HV_STATUS_INSUFFICIENT_MEMORY;
        goto cleanup;
    }

    msg.type = HV_SYNDBG_MSG_SEND;
    msg.u.send.buf_gpa = ingpa + sizeof(*post_data_in);
    msg.u.send.count = post_data_in->count;
    msg.u.send.is_raw = true;
    ret = hv_syndbg_handler(hv_syndbg_context, &msg);
    if (ret != HV_STATUS_SUCCESS) {
        goto cleanup;
    }

    post_data_out->pending_count = msg.u.send.pending_count;
    ret = post_data_out->pending_count ? HV_STATUS_INSUFFICIENT_BUFFERS :
                                         HV_STATUS_SUCCESS;
cleanup:
    if (post_data_out) {
        cpu_physical_memory_unmap(post_data_out,
                                  sizeof(*post_data_out), 1, out_len);
    }

    if (post_data_in) {
        cpu_physical_memory_unmap(post_data_in,
                                  sizeof(*post_data_in), 0, in_len);
    }

    return ret;
}

uint32_t hyperv_syndbg_send(uint64_t ingpa, uint32_t count)
{
    HvSynDbgMsg msg;

    if (!hv_syndbg_handler) {
        return HV_SYNDBG_STATUS_INVALID;
    }

    msg.type = HV_SYNDBG_MSG_SEND;
    msg.u.send.buf_gpa = ingpa;
    msg.u.send.count = count;
    msg.u.send.is_raw = false;
    if (hv_syndbg_handler(hv_syndbg_context, &msg)) {
        return HV_SYNDBG_STATUS_INVALID;
    }

    return HV_SYNDBG_STATUS_SEND_SUCCESS;
}

uint32_t hyperv_syndbg_recv(uint64_t ingpa, uint32_t count)
{
    uint16_t ret;
    HvSynDbgMsg msg;

    if (!hv_syndbg_handler) {
        return HV_SYNDBG_STATUS_INVALID;
    }

    msg.type = HV_SYNDBG_MSG_RECV;
    msg.u.recv.buf_gpa = ingpa;
    msg.u.recv.count = count;
    msg.u.recv.options = 0;
    msg.u.recv.timeout = 0;
    msg.u.recv.is_raw = false;
    ret = hv_syndbg_handler(hv_syndbg_context, &msg);
    if (ret != HV_STATUS_SUCCESS) {
        return 0;
    }

    return HV_SYNDBG_STATUS_SET_SIZE(HV_SYNDBG_STATUS_RECV_SUCCESS,
                                     msg.u.recv.retrieved_count);
}

void hyperv_syndbg_set_pending_page(uint64_t ingpa)
{
    HvSynDbgMsg msg;

    if (!hv_syndbg_handler) {
        return;
    }

    msg.type = HV_SYNDBG_MSG_SET_PENDING_PAGE;
    msg.u.pending_page.buf_gpa = ingpa;
    hv_syndbg_handler(hv_syndbg_context, &msg);
}

uint64_t hyperv_syndbg_query_options(void)
{
    HvSynDbgMsg msg;

    if (!hv_syndbg_handler) {
        return 0;
    }

    msg.type = HV_SYNDBG_MSG_QUERY_OPTIONS;
    if (hv_syndbg_handler(hv_syndbg_context, &msg) != HV_STATUS_SUCCESS) {
        return 0;
    }

    return msg.u.query_options.options;
}

static bool vmbus_recommended_features_enabled;

bool hyperv_are_vmbus_recommended_features_enabled(void)
{
    return vmbus_recommended_features_enabled;
}

void hyperv_set_vmbus_recommended_features_enabled(void)
{
    vmbus_recommended_features_enabled = true;
}
