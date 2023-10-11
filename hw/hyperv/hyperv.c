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
#include "sysemu/kvm_int.h"
#include "kvm/kvm_i386.h"
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

struct hv_vsm {
    GHashTable *prots[HV_NUM_VTLS];
    KVMState *s[HV_NUM_VTLS];
    MemoryRegion *root[HV_NUM_VTLS];
    AddressSpace as[HV_NUM_VTLS];

    /* If bit N is set, then we have VTLN enabled for any number of VPs */
    uint16_t vtl_enabled_for_vps;
} hv_vsm = { .vtl_enabled_for_vps = 1 << 0, };

static int get_active_vtl(CPUState *cpu)
{
    return X86_CPU(cpu)->namespace;
}

static MemTxResult hyperv_physmem_write(CPUState *cs, hwaddr addr,
                                        const void *buf, hwaddr len)
{
    return address_space_write(cs->as, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

static MemTxResult hyperv_physmem_read(CPUState *cs, hwaddr addr,
                                       void *buf, hwaddr len)
{
    return address_space_read(cs->as, addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

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

    MemoryRegion *root = hv_vsm.root[get_active_vtl(synic->cs)] ? : get_system_memory();

    synic->sctl_enabled = sctl_enable;
    if (synic->msg_page_addr != msg_page_addr) {
        if (synic->msg_page_addr) {
            memory_region_del_subregion(root, &synic->msg_page_mr);
        }
        if (msg_page_addr) {
            memory_region_add_subregion(root, msg_page_addr, &synic->msg_page_mr);
        }
        synic->msg_page_addr = msg_page_addr;
    }
    if (synic->event_page_addr != event_page_addr) {
        if (synic->event_page_addr) {
            memory_region_del_subregion(root, &synic->event_page_mr);
        }
        if (event_page_addr) {
            memory_region_add_subregion(root, event_page_addr,
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
    uint32_t namespace;
    uint32_t vp_index;

    /* memory region names have to be globally unique */
    vp_index = hyperv_vp_index(synic->cs);
    namespace = get_active_vtl(synic->cs);
    msgp_name = g_strdup_printf("synic-%u-%u-msg-page", vp_index, namespace);
    eventp_name = g_strdup_printf("synic-%u-%u-event-page", vp_index, namespace);

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

struct VpVsmState {
    DeviceState parent_obj;

    CPUState *cs;
    uint64_t msr_hv_vapic;
    void *vp_assist;
};

#define TYPE_VP_VSM "hyperv-vp-vsm"
OBJECT_DECLARE_SIMPLE_TYPE(VpVsmState, VP_VSM)

static VpVsmState *get_vp_vsm(CPUState *cs)
{
    return VP_VSM(object_resolve_path_component(OBJECT(cs), "vp-vsm"));
}

static void hyperv_setup_vp_assist(CPUState *cs, uint64_t data)
{
    hwaddr gpa = data & HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;
    hwaddr len = 1 << HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_SHIFT;
    bool enable = !!(data & HV_X64_MSR_VP_ASSIST_PAGE_ENABLE);
    VpVsmState *vpvsm = get_vp_vsm(cs);

    trace_hyperv_setup_vp_assist_page(hyperv_vp_index(cs), get_active_vtl(cs), enable, gpa);

    if (!vpvsm)
        return;

    vpvsm->msr_hv_vapic = data;

    if (vpvsm->vp_assist)
        address_space_unmap(cs->as, vpvsm->vp_assist, len, true, len);

    if (!enable)
        return;

    vpvsm->vp_assist = address_space_map(cs->as, gpa, &len, true, MEMTXATTRS_UNSPECIFIED);
    if (!vpvsm->vp_assist) {
        printf("Failed to map VP assit page");
        return;
    }

    memset(vpvsm->vp_assist, 0, sizeof(struct hv_vp_assist_page));
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

int hyperv_init_vsm(CPUState *cs)
{
    KVMState *s = cs->kvm_state;

    //TODO Add filter for VP INDEX MSR, we don't support vp_index != apic_id.
    if (!kvm_filter_msr(s, HV_X64_MSR_APIC_ASSIST_PAGE, NULL, hyperv_vp_assist_page_wrmsr)) {
        printf("Failed to set HV_X64_MSR_APIC_ASSIST_PAGE MSR handler\n");
        return -1;
    }

    return 0;
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

static void hyperv_apic_force_enable_spiv(CPUState *cs)
{
    APICCommonState *apic_state = APIC_COMMON(X86_CPU(cs)->apic_state);
    APICCommonClass *apic_class = APIC_COMMON_GET_CLASS(apic_state);

    /*
     * Windows Server 2019 guest expects VTL1+ apics to be sw-enabled by the
     * fact that they never try to write anything to SPIV before attempting to
     * send IPIs. So enable a new apic for them. If they ever change their mind,
     * they will set their own SPIV value
     */
    apic_state->spurious_vec = 0x1ff;
    bql_lock();
    apic_class->reset(apic_state);
    bql_unlock();
}

static void hyperv_set_vtl_cpu_state(CPUState *cs, struct hv_init_vp_context *c,
                                     bool enable_spiv)
{
    CPUX86State *env = &X86_CPU(cs)->env;

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

    if (enable_spiv)
        hyperv_apic_force_enable_spiv(cs);
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

void hyperv_vp_vsm_add(CPUState *cs)
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

static void hyperv_vsm_sync_kvm_clock(KVMState *target_state, KVMState *vtl_state)
{
    struct kvm_clock_data data;
    int ret;

    ret = kvm_vm_ioctl(target_state, KVM_GET_CLOCK, &data);
    if (ret < 0) {
        fprintf(stderr, "KVM_GET_CLOCK failed: %s\n", strerror(-ret));
                abort();
    }

    ret = kvm_vm_ioctl(vtl_state, KVM_SET_CLOCK, &data);
    if (ret < 0) {
        fprintf(stderr, "KVM_SET_CLOCK failed: %s\n", strerror(-ret));
        abort();
    }
}

static void vsm_memory_listener_register(const char *name, int vtl)
{
    KVMState *s = hv_vsm.s[vtl];
    KVMMemoryListener *kml = &s->memory_listener;
    int i;

    kml->slots = g_new0(KVMSlot, s->nr_slots);
    kml->as_id = 0;

    for (i = 0; i < s->nr_slots; i++)
        kml->slots[i].slot = i;

    QSIMPLEQ_INIT(&kml->transaction_add);
    QSIMPLEQ_INIT(&kml->transaction_del);

    kml->s = s;
    kml->listener.region_add = kvm_region_add;
    kml->listener.region_del = kvm_region_del;
    kml->listener.commit = kvm_region_commit;
    kml->listener.priority = MEMORY_LISTENER_PRIORITY_ACCEL;
    kml->listener.name = name;

    memory_listener_register(&kml->listener, &hv_vsm.as[vtl]);
}

static int hyperv_kvm_init_vsm(int vtl)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    MemoryRegion *ram_below_4g, *ram_above_4g;
    X86MachineState *x86ms = X86_MACHINE(ms);
    AccelClass *ac = accel_find("kvm");
    int ret;

    hv_vsm.s[vtl] = KVM_STATE(object_new_with_class(OBJECT_CLASS(ac)));
    object_apply_compat_props(OBJECT(hv_vsm.s[vtl]));
    ret = kvm_init_companion_vm(ms, hv_vsm.s[vtl - 1], hv_vsm.s[vtl]);
    if (ret)
        return ret;

    hv_vsm.s[vtl]->as = g_new0(struct KVMAs, 1);
    hv_vsm.s[vtl]->as->ml = &hv_vsm.s[vtl]->memory_listener;
    hv_vsm.s[vtl]->as->as = &hv_vsm.as[vtl];
    hv_vsm.root[0] = get_system_memory();

    /* Outer container */
    hv_vsm.root[vtl] = g_malloc(sizeof(*hv_vsm.root[0]));

    bql_lock();
    memory_region_init(hv_vsm.root[vtl], NULL, "vsm-memory", UINT64_MAX);

    /* With one region inside */
    ram_below_4g = g_malloc(sizeof(*ram_below_4g));
    memory_region_init_alias(ram_below_4g, NULL, "ram-below-4g", ms->ram,
                             0, x86ms->below_4g_mem_size);
    memory_region_add_subregion(hv_vsm.root[vtl], 0, ram_below_4g);
    if (x86ms->above_4g_mem_size > 0) {
        ram_above_4g = g_malloc(sizeof(*ram_above_4g));
        memory_region_init_alias(ram_above_4g, NULL, "ram-above-4g",
                                 ms->ram, x86ms->below_4g_mem_size,
                                 x86ms->above_4g_mem_size);
        memory_region_add_subregion(hv_vsm.root[vtl], x86ms->above_4g_mem_start,
                                    ram_above_4g);
    }

    address_space_init(&hv_vsm.as[vtl], hv_vsm.root[vtl], "vsm-memory");
    vsm_memory_listener_register("vsm-memory", vtl);
    bql_unlock();

    hyperv_vsm_sync_kvm_clock(hv_vsm.s[vtl - 1], hv_vsm.s[vtl]);

    hv_vsm.prots[vtl - 1] = g_hash_table_new(g_direct_hash, g_direct_equal);

    return 0;
}

uint16_t hyperv_hcall_vtl_enable_partition_vtl(CPUState *cs, uint64_t param1,
                                               uint64_t param2, bool fast)
{
    union hv_enable_partition_vtl input;
    uint8_t highest_enabled_vtl;

    // TODO: Implement not fast args
    if (!fast)
        return HV_STATUS_INVALID_HYPERCALL_CODE;

    input.as_u64[0] = param1;
    input.as_u64[1] = param2;

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

    /* Is target VTL already enabled? */
    if (hv_vsm_partition_status.enabled_vtl_set & (1ul << input.target_vtl))
        return HV_STATUS_INVALID_PARAMETER;

    /*
    * Requestor VP should be running on VTL higher or equal to the new one or
    * at the highest VTL enabled for partition overall if the new one is higher
    * than that
    */
    highest_enabled_vtl = fls(hv_vsm_partition_status.enabled_vtl_set) - 1;
    if (get_active_vtl(cs) < input.target_vtl &&
        get_active_vtl(cs) != highest_enabled_vtl)
      return HV_STATUS_INVALID_PARAMETER;

    if (!get_active_vtl(cs))
        hv_vsm.s[0] = cs->kvm_state;

    /* Create new KVM VM */
    if (hyperv_kvm_init_vsm(input.target_vtl))
        return HV_STATUS_INVALID_PARAMETER;

    hv_vsm_partition_status.enabled_vtl_set |= (1ul << input.target_vtl);
    return HV_STATUS_SUCCESS;
}

static CPUState* hyperv_init_vtl_vcpu(int32_t vp_index, unsigned int vtl)
{
    X86MachineState *x86ms = X86_MACHINE(qdev_get_machine());
    CPUState *new_cpu;

    bql_lock();
    x86_cpu_new(x86ms, vtl, hv_vsm.s[vtl], vp_index, &error_warn);
    new_cpu = hyperv_vsm_vcpu(vp_index, vtl);
    new_cpu->as = hv_vsm.s[vtl]->as->as;

    /*
     * KVM's CPU init state and QEMU's might not match, so sync them...
     */
    kvm_arch_put_registers(new_cpu, KVM_PUT_RUNTIME_STATE);

    /*
     * ...but then we need to pull the SynIC state back into QEMU, otherwise
     * ours is stale. TODO rework this properly, it's the worst.
     */
    new_cpu->vcpu_dirty = false;
    cpu_synchronize_state(new_cpu);
    bql_unlock();

    return new_cpu;
}

/* Tell the previous bit that is set before specified one in a set (bit numbers start at 1) */
static uint8_t prev_bit_set(uint16_t set, uint8_t bit)
{
	uint16_t mask;
    assert(bit);

	mask = (1u << (bit - 1)) - 1; /* Select all lsbs before this one */
	return fls(set & mask);
}

static __attribute__((unused)) uint8_t prev_enabled_vtl(uint16_t set, uint8_t vtl)
{
    uint8_t prev_vtl = prev_bit_set(set, vtl + 1);
    return prev_vtl ? prev_vtl - 1 : HV_INVALID_VTL;
}

static void print_hv_init_vp_context(const struct hv_init_vp_context *ctx)
{
    printf("rip: 0x%016" PRIx64 "\n", ctx->rip);
    printf("rsp: 0x%016" PRIx64 "\n", ctx->rsp);
    printf("rflags: 0x%016" PRIx64 "\n", ctx->rflags);


    printf("cs.base: 0x%016" PRIx64 "\n", ctx->cs.base);
    printf("cs.limit: 0x%08" PRIx32 "\n", ctx->cs.limit);
    printf("cs.selector: 0x%04" PRIx16 "\n", ctx->cs.selector);
    printf("cs.attributes: 0x%04" PRIx16 "\n", ctx->cs.attributes);

    printf("ds.base: 0x%016" PRIx64 "\n", ctx->ds.base);
    printf("ds.limit: 0x%08" PRIx32 "\n", ctx->ds.limit);
    printf("ds.selector: 0x%04" PRIx16 "\n", ctx->ds.selector);
    printf("ds.attributes: 0x%04" PRIx16 "\n", ctx->ds.attributes);

    printf("es.base: 0x%016" PRIx64 "\n", ctx->es.base);
    printf("es.limit: 0x%08" PRIx32 "\n", ctx->es.limit);
    printf("es.selector: 0x%04" PRIx16 "\n", ctx->es.selector);
    printf("es.attributes: 0x%04" PRIx16 "\n", ctx->es.attributes);

    printf("fs.base: 0x%016" PRIx64 "\n", ctx->fs.base);
    printf("fs.limit: 0x%08" PRIx32 "\n", ctx->fs.limit);
    printf("fs.selector: 0x%04" PRIx16 "\n", ctx->fs.selector);
    printf("fs.attributes: 0x%04" PRIx16 "\n", ctx->fs.attributes);

    printf("gs.base: 0x%016" PRIx64 "\n", ctx->gs.base);
    printf("gs.limit: 0x%08" PRIx32 "\n", ctx->gs.limit);
    printf("gs.selector: 0x%04" PRIx16 "\n", ctx->gs.selector);
    printf("gs.attributes: 0x%04" PRIx16 "\n", ctx->gs.attributes);

    printf("ss.base: 0x%016" PRIx64 "\n", ctx->ss.base);
    printf("ss.limit: 0x%08" PRIx32 "\n", ctx->ss.limit);
    printf("ss.selector: 0x%04" PRIx16 "\n", ctx->ss.selector);
    printf("ss.attributes: 0x%04" PRIx16 "\n", ctx->ss.attributes);

    printf("tr.base: 0x%016" PRIx64 "\n", ctx->tr.base);
    printf("tr.limit: 0x%08" PRIx32 "\n", ctx->tr.limit);
    printf("tr.selector: 0x%04" PRIx16 "\n", ctx->tr.selector);
    printf("tr.attributes: 0x%04" PRIx16 "\n", ctx->tr.attributes);

    printf("ldtr.base: 0x%016" PRIx64 "\n", ctx->ldtr.base);
    printf("ldtr.limit: 0x%08" PRIx32 "\n", ctx->ldtr.limit);
    printf("ldtr.selector: 0x%04" PRIx16 "\n", ctx->ldtr.selector);
    printf("ldtr.attributes: 0x%04" PRIx16 "\n", ctx->ldtr.attributes);

    printf("idtr.limit: 0x%04" PRIx16 "\n", ctx->idtr.limit);
    printf("idtr.base: 0x%016" PRIx64 "\n", ctx->idtr.base);

    printf("gdtr.limit: 0x%04" PRIx16 "\n", ctx->gdtr.limit);
    printf("gdtr.base: 0x%016" PRIx64 "\n", ctx->gdtr.base);

    printf("efer: 0x%016" PRIx64 "\n", ctx->efer);
    printf("cr0: 0x%016" PRIx64 "\n", ctx->cr0);
    printf("cr3: 0x%016" PRIx64 "\n", ctx->cr3);
    printf("cr4: 0x%016" PRIx64 "\n", ctx->cr4);
    printf("msr_cr_pat: 0x%016" PRIx64 "\n", ctx->msr_cr_pat);
}

uint16_t hyperv_hcall_vtl_enable_vp_vtl(CPUState *cs, uint64_t param, bool fast)
{
    CPUState *target_vcpu, *vtl_cpu;
    struct hv_enable_vp_vtl input;
    int highest_vp_enabled_vtl;
    VpVsmState *vpvsm;

    /* Neither continuations not fast calls are possible for this call */
    if (fast)
        return HV_STATUS_INVALID_HYPERCALL_INPUT;

    hyperv_physmem_read(cs, param, &input, sizeof(input));

    trace_hyperv_hcall_vtl_enable_vp_vtl(input.partition_id, input.vp_index,
                                         input.target_vtl);
    printf("enable vp vtl, target partition id 0x%lx, VP index %d, target VTL %d\n",
           input.partition_id, input.vp_index, input.target_vtl);

    /* Only self-targeting is supported */
    if (input.partition_id != HV_PARTITION_ID_SELF)
        return HV_STATUS_INVALID_PARTITION_ID;

    if (input.vp_index != HV_VP_INDEX_SELF && !cpu_by_arch_id(input.vp_index, 0))
        return HV_STATUS_INVALID_VP_INDEX;

    /* Handle VP index argument */
    if (input.vp_index != HV_VP_INDEX_SELF && input.vp_index != hyperv_vp_index(cs)) {
        target_vcpu = hyperv_vsm_vcpu(input.vp_index, 0);
        if (!target_vcpu)
            return HV_STATUS_INVALID_VP_INDEX;
    } else {
        target_vcpu = cs;
    }
    vpvsm = get_vp_vsm(target_vcpu);

    /* Check that target VTL is sane */
    if (input.target_vtl > hv_vsm_partition_status.maximum_vtl)
        return HV_STATUS_INVALID_PARAMETER;

    /* Is target VTL already enabled for partition? */
    if ((hv_vsm_partition_status.enabled_vtl_set & (1ul << input.target_vtl)) == 0)
        return HV_STATUS_INVALID_PARAMETER;

    /* Is target VTL already enabled for target vcpu? */
    if (vpvsm->vsm_vp_status.enabled_vtl_set & (1ul << input.target_vtl))
      return HV_STATUS_INVALID_PARAMETER;

    /*
     * Requestor VP should be running on vtl higher or equal to the new one or
     * it needs to be running on a highest VTL any VP has enabled.
     */
    highest_vp_enabled_vtl = fls(hv_vsm.vtl_enabled_for_vps) - 1;
    if (get_active_vtl(cs) < input.target_vtl &&
        get_active_vtl(cs) != highest_vp_enabled_vtl)
      return HV_STATUS_INVALID_PARAMETER;

    vtl_cpu = hyperv_init_vtl_vcpu(input.vp_index, input.target_vtl);
    if (!vtl_cpu)
        return HV_STATUS_INVALID_PARAMETER;

    print_hv_init_vp_context(&input.vp_context);
    hyperv_set_vtl_cpu_state(vtl_cpu, &input.vp_context, true);

    /* TODO For VTL2+ We need to always keep track of enabled_vtl_set in the
     * VTL0 VpVsmState */
    vpvsm->vsm_vp_status.enabled_vtl_set |= 1 << input.target_vtl;
    hv_vsm.vtl_enabled_for_vps |= 1 << input.target_vtl;

    bql_lock();
    cpu_synchronize_post_reset(vtl_cpu);
    bql_unlock();

    return HV_STATUS_SUCCESS;
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
