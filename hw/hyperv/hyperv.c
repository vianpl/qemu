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
#include "hw/pci/msi.h"
#include "hw/i386/apic-msidef.h"
#include "qom/object.h"
#include "target/i386/kvm/hyperv-proto.h"
#include "target/i386/cpu.h"
#include "exec/cpu-all.h"
#include "sysemu/kvm_int.h"
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

struct hv_vsm {
    GHashTable *prots[HV_NUM_VTLS];
    KVMState *s[HV_NUM_VTLS];
    MemoryRegion *root[HV_NUM_VTLS];
    AddressSpace as[HV_NUM_VTLS];

    /* If bit N is set, then we have VTLN enabled for any number of VPs */
    uint16_t vtl_enabled_for_vps;
    union hv_register_vsm_code_page_offsets vsm_code_page_offsets;
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

HvSintRoute *hyperv_sint_route_new(uint32_t vp_index, uint8_t vtl, uint32_t sint,
                                   HvSintMsgCb cb, void *cb_data)
{
    HvSintRoute *sint_route = NULL;
    EventNotifier *ack_notifier = NULL;
    int r, gsi;
    CPUState *cs;
    SynICState *synic;
    bool ack_event_initialized = false;

    cs = hyperv_vsm_vcpu(vp_index, vtl);
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

    gsi = kvm_irqchip_add_hv_sint_route(cs->kvm_state, vp_index, sint);
    if (gsi < 0) {
        goto cleanup_err_sint_notifier;
    }

    r = kvm_irqchip_add_irqfd_notifier_gsi(cs->kvm_state,
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
    kvm_irqchip_release_virq(cs->kvm_state, gsi);

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
    union hv_register_vsm_vp_status vsm_vp_status;
    union hv_register_vsm_vp_secure_vtl_config vsm_vtl_config[HV_NUM_VTLS];
    uint64_t msr_hv_vapic;
    void *vp_assist;
    uint64_t msr_hv_hypercall;
    void *hypercall_page;
    struct kvm_hv_vcpu_per_vtl_state priv_state;
    HvSintRoute *intercept_route;

    unsigned int vtl_event_state;
    bool vtl_event_handled;
};

#define TYPE_VP_VSM "hyperv-vp-vsm"
OBJECT_DECLARE_SIMPLE_TYPE(VpVsmState, VP_VSM)

static VpVsmState *get_vp_vsm(CPUState *cs)
{
    return VP_VSM(object_resolve_path_component(OBJECT(cs), "vp-vsm"));
}

static CPUState *hyperv_get_next_vtl(CPUState *cs)
{
    return hyperv_vsm_vcpu(hyperv_vp_index(cs), get_active_vtl(cs) + 1);
}

static CPUState *hyperv_get_prev_vtl(CPUState *cs)
{
    return hyperv_vsm_vcpu(hyperv_vp_index(cs), get_active_vtl(cs) - 1);
}

static void hyperv_setup_hypercall_page(CPUState *cs, uint64_t data)
{
    hwaddr gpa = data & HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK;
    hwaddr len = 1 << HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_SHIFT;
    bool enable = !!(data & HV_X64_MSR_HYPERCALL_ENABLE);
    VpVsmState *vpvsm = get_vp_vsm(cs);
    uint32_t ebx = 0, ecx = 0, edx = 0;
    char vendor[CPUID_VENDOR_SZ + 1];
    uint8_t instructions[0x30];
    int i = 0;

    trace_hyperv_setup_hypercall_page(hyperv_vp_index(cs), get_active_vtl(cs), enable, gpa);

    if (!vpvsm)
        return;

    vpvsm->msr_hv_hypercall = data;

    if (vpvsm->hypercall_page) {
        memset(vpvsm->hypercall_page, 0, len);
        address_space_unmap(cs->as, vpvsm->hypercall_page, len, true, len);
    }

    if (!enable)
        return;

    vpvsm->hypercall_page = address_space_map(cs->as, gpa, &len, true, MEMTXATTRS_UNSPECIFIED);
    if (!vpvsm->hypercall_page) {
        printf("Failed to map VP assit page");
        return;
    }

    /* Intel VMCALL or AMD VMMCALL*/
    host_cpuid(0, 0, NULL, &ebx, &ecx, &edx);
    x86_cpu_vendor_words2str(vendor, ebx, edx, ecx);
    instructions[i++] = 0x0f;
    instructions[i++] = 0x01;
    if (!strcmp(vendor, "GenuineIntel"))
        instructions[i++] = 0xc1;
    else
        instructions[i++] = 0xd9;
    /* ret */
    instructions[i++] = 0xc3;

    //TODO fix this, also introduce 32bit support.
    i = 22;
    /*
     * VTL call 64-bit entry prologue:
     * 	mov %rcx, %rax
     * 	mov $0x11, %ecx
     * 	jmp 0:
     */
    hv_vsm.vsm_code_page_offsets.vtl_call_offset = i;
    instructions[i++] = 0x48;
    instructions[i++] = 0x89;
    instructions[i++] = 0xc8;
    instructions[i++] = 0xb9;
    instructions[i++] = 0x11;
    instructions[i++] = 0x00;
    instructions[i++] = 0x00;
    instructions[i++] = 0x00;
    instructions[i++] = 0xeb;
    instructions[i++] = 0xe0;
    /*
     * VTL return 64-bit entry prologue:
     * 	mov %rcx, %rax
     * 	mov $0x12, %ecx
     * 	jmp 0:
     */
    hv_vsm.vsm_code_page_offsets.vtl_return_offset = i;
    instructions[i++] = 0x48;
    instructions[i++] = 0x89;
    instructions[i++] = 0xc8;
    instructions[i++] = 0xb9;
    instructions[i++] = 0x12;
    instructions[i++] = 0x00;
    instructions[i++] = 0x00;
    instructions[i++] = 0x00;
    instructions[i++] = 0xeb;
    instructions[i++] = 0xd6;


    memcpy(vpvsm->hypercall_page, instructions, i);
}

static int hyperv_hypercall_page_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
{
    if (msr != HV_X64_MSR_HYPERCALL) {
        printf("In %s with MSR %x\n", __func__, msr);
		return 0;
    }

    hyperv_setup_hypercall_page(CPU(cpu), val);

	return 1;
}

static int hyperv_hv_x86_msr_eoi_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
{
    CPUState *cs = CPU(cpu);
    int ret;

    if (msr != HV_X64_MSR_EOI) {
        printf("In %s with MSR %x\n", __func__, msr);
		return 0;
    }

    if (get_active_vtl(cs) != 1) {
        printf("This fix should only be run on VTL1 vCPUs\n");
		return 0;
    }

    /*
     * Cleanup the high bits. They are reserved and VTL1 doesn't always
     * sanitize them.
     */

    ret = kvm_put_one_msr(cpu, HV_X64_MSR_EOI, val & 0xffffffff);
    if (ret < 0) {
        printf("Failed to set HV_X64_MSR_EOI, ret = %d\n", ret);
		return 0;
    }

	return 1;
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

static int hyperv_vp_assist_page_wrmsr(X86CPU *cpu, uint32_t msr, uint64_t val)
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

    if (!kvm_filter_msr(s, HV_X64_MSR_HYPERCALL, NULL, hyperv_hypercall_page_wrmsr)) {
        printf("Failed to set HV_X64_MSR_HYPERCALL MSR handler\n");
        return -1;
    }

    if (get_active_vtl(cs) == 1 &&
        !kvm_filter_msr(s, HV_X64_MSR_EOI, NULL, hyperv_hv_x86_msr_eoi_wrmsr)) {
        printf("Failed to set HV_X64_MSR_EOI MSR handler\n");
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
    priv_state->error_code = env->error_code;
    priv_state->nmi_pending = env->nmi_pending;
    priv_state->nmi_injected = env->nmi_injected;
    priv_state->hflags = env->hflags;
    priv_state->hflags2 = env->hflags2;
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
    env->error_code = priv_state->error_code;
    env->nmi_pending = priv_state->nmi_pending;
    env->nmi_injected = priv_state->nmi_injected;
    env->hflags = priv_state->hflags;
    env->hflags2 = priv_state->hflags2;

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
    if (!hyperv_vp_index(cs)) {
        val = cpu_get_apic_base(cpu->apic_state);
        val |= MSR_IA32_APICBASE_BSP;
        cpu_set_apic_base(cpu->apic_state, val);
    }

    hyperv_set_vtl_cpu_state(cs, &ctx, false);
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
    vpvsm->vtl_event_handled = false;
    vpvsm->intercept_route = NULL;
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

    if (!hv_vsm.prots[0])
        hv_vsm.prots[0] = g_hash_table_new(g_direct_hash, g_direct_equal);

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

#define VTL_INTERRUPT_PENDING   BIT(0)
#define VTL_CALL_PENDING        BIT(1)

static void do_vtl1_entry(CPUState *vtl1, run_on_cpu_data arg)
{
    CPUX86State *vtl1_env = &X86_CPU(vtl1)->env;
    CPUState *vtl0 = hyperv_get_prev_vtl(vtl1);
    CPUX86State *vtl0_env = &X86_CPU(vtl0)->env;
    VpVsmState *vpvsm = get_vp_vsm(vtl1);

    trace_hyperv_hcall_vtl_entry(hyperv_vp_index(vtl0), get_active_vtl(vtl0),
                                 qatomic_read(&vpvsm->vtl_event_state));

    /* Poll updated RIP */
    cpu_synchronize_state(vtl1);
    hyperv_save_priv_vtl_state(vtl1);
    memcpy(vtl1_env, vtl0_env, sizeof(*vtl1_env));
    hyperv_restore_priv_vtl_state(vtl1);
    set_vtl_entry_reason(vtl0, vtl1, qatomic_read(&vpvsm->vtl_event_state) & VTL_CALL_PENDING ?
                         HV_VTL_ENTRY_VTL_CALL : HV_VTL_ENTRY_INTERRUPT);
    vtl1_env->mp_state = KVM_MP_STATE_RUNNABLE;
    cpu_synchronize_post_reset(vtl1);
    vtl1->stop = false;
    vtl1->stopped = false;
    qatomic_set(&vpvsm->vtl_event_state, 0);
    vtl1->kvm_run->dump_state_on_run = true;
}

static void do_vtl0_upcall(CPUState *vtl0, run_on_cpu_data arg)
{
    CPUState *vtl1 = hyperv_get_next_vtl(vtl0);
    VpVsmState *vpvsm = get_vp_vsm(vtl1);

    trace_hyperv_hcall_vtl_upcall(hyperv_vp_index(vtl0), get_active_vtl(vtl0),
                                  qatomic_read(&vpvsm->vtl_event_state),
                                  vpvsm->vtl_event_handled);

    if (vpvsm->vtl_event_handled)
        return;

    cpu_synchronize_state(vtl0);
    vpvsm->vtl_event_handled = true;
    vtl0->stop = true;
    async_run_on_cpu(vtl1, do_vtl1_entry, RUN_ON_CPU_NULL);
}

static void do_vtl1_poll(CPUState *vtl1, run_on_cpu_data arg)
{
    CPUX86State *vtl1_env = &X86_CPU(vtl1)->env;

    vtl1->stop = false;
    vtl1->stopped = false;
    vtl1_env->mp_state = KVM_MP_STATE_HV_INACTIVE_VTL;
    kvm_put_mp_state(X86_CPU(vtl1));
    trace_hyperv_hcall_vtl_poll(hyperv_vp_index(vtl1), get_active_vtl(vtl1));
}

static void do_vtl0_downcall(CPUState *vtl0, run_on_cpu_data arg)
{
    CPUX86State *vtl0_env = &X86_CPU(vtl0)->env;
    CPUState *vtl1 = hyperv_get_next_vtl(vtl0);
    CPUX86State *vtl1_env = &X86_CPU(vtl1)->env;
    VpVsmState *vpvsm = get_vp_vsm(vtl1);

    trace_hyperv_hcall_vtl_downcall(hyperv_vp_index(vtl0), get_active_vtl(vtl0));

    hyperv_save_priv_vtl_state(vtl0);
    memcpy(vtl0_env, vtl1_env, sizeof(*vtl1_env));
    hyperv_restore_priv_vtl_state(vtl0);
    restore_regs_from_vtl_control(vtl1, vtl0);
    cpu_synchronize_post_reset(vtl0);
    vpvsm->vtl_event_handled = false;
    vtl0->stop = false;
    vtl0->stopped = false;
    vtl0->kvm_run->dump_state_on_run = true;
    async_run_on_cpu(vtl1, do_vtl1_poll, RUN_ON_CPU_NULL);
}

static void kvm_ioctl_set_tlb_inhibit(CPUState *vcpu, __u8 new) {
    struct kvm_hyperv_tlb_flush_inhibit set = {
        .inhibit = new,
    };

    kvm_vcpu_ioctl(vcpu, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &set);
}

int hyperv_hcall_vtl_call(CPUState *vtl0)
{
    VpVsmState *vpvsm;
    CPUState *vtl1;

    vtl1 = hyperv_get_next_vtl(vtl0);
    if (!vtl1)
        return -1;

    vpvsm = get_vp_vsm(vtl1);

    trace_hyperv_hcall_vtl_call(hyperv_vp_index(vtl0), get_active_vtl(vtl0),
                                get_active_vtl(vtl1));

    /* We only support vtl0<->vtl1 */
    if (get_active_vtl(vtl1) > 1)
        return -1;

    vtl0->stop = true;
    qatomic_or(&vpvsm->vtl_event_state, VTL_CALL_PENDING);
    async_run_on_cpu(vtl0, do_vtl0_upcall, RUN_ON_CPU_NULL);

    return EXCP_HALTED;
}

int hyperv_hcall_vtl_return(CPUState *vtl1)
{
    CPUState *vtl0 = hyperv_get_prev_vtl(vtl1);

    trace_hyperv_hcall_vtl_return(hyperv_vp_index(vtl1), get_active_vtl(vtl1),
                                  get_active_vtl(vtl0), 0);
    vtl1->stop = true;
    kvm_ioctl_set_tlb_inhibit(vtl0, false);
    cpu_synchronize_state(vtl1);
    async_run_on_cpu(vtl0, do_vtl0_downcall, RUN_ON_CPU_NULL);

    return EXCP_HALTED;
}

int hyperv_vcpu_event_callback(CPUState *vtl1)
{
    CPUX86State *vtl1_env = &X86_CPU(vtl1)->env;
    CPUState *vtl0 = hyperv_get_prev_vtl(vtl1);
    VpVsmState *vpvsm = get_vp_vsm(vtl1);

    assert(vtl1_env->mp_state == KVM_MP_STATE_HV_INACTIVE_VTL);

    vtl1->stop = true;

    /* We are already dealing with a VTL call the interrupt will be handled then */
    if (qatomic_read(&vpvsm->vtl_event_state))
        return EXCP_HALTED;

    vtl0->kvm_run->dump_state_on_run = true;
    vtl0->stop = true;

    qatomic_or(&vpvsm->vtl_event_state, VTL_INTERRUPT_PENDING);
    async_run_on_cpu(vtl0, do_vtl0_upcall, RUN_ON_CPU_NULL);

    trace_hyperv_hcall_vtl_interrupt(hyperv_vp_index(vtl1), get_active_vtl(vtl0),
                                     get_active_vtl(vtl1));
    return EXCP_HALTED;
}

void hyperv_vsm_reset(CPUState *cpu)
{
    printf("TODO!! VSM RESET\n");
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

    //TODO: ES, CS, SS, DS, FS, GS registers?
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
        val->low = vpvsm->msr_hv_vapic;
        break;
    case HV_REGISTER_VSM_CODE_PAGE_OFFSETS:
        val->low = hv_vsm.vsm_code_page_offsets.as_u64;
        break;
    default:
        printf("%s: unknown VP register 0x%x\n", __func__, name);
        return HV_STATUS_INVALID_PARAMETER;
    };

    trace_hyperv_hcall_get_vp_register(name, val->low, val->high);
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
    trace_hyperv_hcall_set_vp_register(name, val->low, val->high);

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
    MachineState *ms = MACHINE(qdev_get_machine());
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

        hyperv_physmem_read(cs, ingpa, &input, sizeof(input));

        ingpa += sizeof(input) + rep_idx * sizeof(*names);
        hyperv_physmem_read(cs, ingpa, names, nregs * sizeof(*names));

        if (set) {
            /* According to TLFS, values start aligned on 16-byte boundary after names
            */
            ingpa = ROUND_UP(ingpa + nregs * sizeof(*names), 16) +
                    rep_idx * sizeof(*vals);
            hyperv_physmem_read(cs, ingpa, vals, nregs * sizeof(*vals));
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
    if (input.vp_index != HV_VP_INDEX_SELF) {
        if (input.vp_index >= ms->smp.max_cpus)
            return HV_STATUS_INVALID_VP_INDEX;

        target_vcpu = hyperv_vsm_vcpu(input.vp_index, vtl);
        if (!target_vcpu)
            return HV_STATUS_INVALID_VP_INDEX;
    } else {
        target_vcpu = hyperv_vsm_vcpu(hyperv_vp_index(cs), vtl);
        if (!target_vcpu)
            return HV_STATUS_INVALID_PARAMETER;
    }

    trace_hyperv_hcall_get_set_vp_register(input.partition_id, input.vp_index,
                                           vtl, get_active_vtl(cs), nregs, set);

    //TODO Think deeper about locking here...
    bql_lock();
    cpu_synchronize_state(target_vcpu);
    /* Handle actual registers */
    for (int i = 0; i < nregs; ++i) {
        status = set ? set_vp_register(names[i], &vals[i], target_vcpu, &dirty):
                       get_vp_register(names[i], &vals[i], target_vcpu);
        if (status != HV_STATUS_SUCCESS)
            break;
    }
    //TODO most likely unnecessary, sync state marks vCPU dirty.
    if (dirty)
        cpu_synchronize_post_reset(target_vcpu);
    bql_unlock();

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
            hyperv_physmem_write(cs, outgpa, vals, sizeof(*vals) * nregs);
        }
    }

    return (uint64_t)HV_STATUS_SUCCESS | ((uint64_t)nregs << HV_HYPERCALL_REP_COMP_OFFSET);
}

static uint64_t hyperv_translate_va_validate_input(CPUState *cs,
                                           struct hv_xlate_va_input *in,
                                           uint8_t *target_vtl, uint8_t *flags)
{
    union hv_input_vtl in_vtl;

    if (in->partition_id != HV_PARTITION_ID_SELF)
        return HV_STATUS_INVALID_PARTITION_ID;

    in_vtl.as_uint8 = in->control_flags >> 56;
    *flags = in->control_flags & HV_XLATE_GVA_FLAGS_MASK;

    if (in_vtl.use_target_vtl) {
        *target_vtl = in_vtl.target_vtl;
        if (*target_vtl > get_active_vtl(cs))
            return HV_STATUS_INVALID_VP_STATE;
    } else {
        *target_vtl = get_active_vtl(cs);
    }

    return HV_STATUS_SUCCESS;
}

static bool hyperv_gpa_is_overlay(CPUState *cs, uint64_t gpa)
{
    VpVsmState *vpvsm = get_vp_vsm(cs);
    uint64_t hcall;

    hcall = vpvsm->msr_hv_hypercall & HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_MASK;
    if (hcall == gpa)
        return true;

    hcall = vpvsm->msr_hv_vapic & HV_X64_MSR_VP_ASSIST_PAGE_ADDRESS_MASK;
    if (hcall == gpa)
        return true;

    return false;
}

static struct kvm_translation2 kvm_gva_to_gpa(CPUState *cs, uint64_t gva, size_t *len, uint64_t control_flags)
{
    int aw = (control_flags & HV_XLATE_GVA_VAL_WRITE) ? KVM_TRANSLATE_ACCESS_WRITE : 0;
    int ae = (control_flags & HV_XLATE_GVA_VAL_EXECUTE) ? KVM_TRANSLATE_ACCESS_EXEC : 0;
    int au = (!(control_flags & HV_XLATE_GVA_PRIVILEGE_EXEMPT) && (X86_CPU(cs)->env.hflags & HF_CPL_MASK))
             ? KVM_TRANSLATE_ACCESS_USER : 0;

    int flags = control_flags & HV_XLATE_GVA_SET_PAGE_TABLE_BITS ? KVM_TRANSLATE_FLAGS_SET_ACCESSED |
                                                                   KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED |
                                                                   (aw ? KVM_TRANSLATE_FLAGS_SET_DIRTY : 0) : 0;

    struct kvm_translation2 tr = {
        .linear_address = gva,
            .flags = flags,
            .access = aw | ae | au
    };

    if (len) {
        *len = TARGET_PAGE_SIZE - (gva & ~TARGET_PAGE_MASK);
    }

    if (kvm_vcpu_ioctl(cs, KVM_TRANSLATE2, &tr)) {
        warn_report("KVM_TRANSLATE2 failed");
        tr.valid = false;
    }

    return tr;
}

uint64_t hyperv_hcall_translate_virtual_address(CPUState *cs, struct kvm_hyperv_exit *exit)
{
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    struct hv_xlate_va_output output = {};
	struct hv_xlate_va_input input;
    struct kvm_translation2 tr;
	uint8_t flags, target_vtl;
    CPUState *target_vcpu;

    if (fast) {
        input.partition_id = exit->u.hcall.ingpa;
        input.vp_index = exit->u.hcall.outgpa & 0xFFFFFFFF;
        input.control_flags = exit->u.hcall.xmm[0];
        input.gva = exit->u.hcall.xmm[1];
    } else {
        hyperv_physmem_read(cs, exit->u.hcall.ingpa, &input, sizeof(input));
    }

    uint64_t input_validity = hyperv_translate_va_validate_input(cs, &input, &target_vtl, &flags);
    if (input_validity != HV_STATUS_SUCCESS) {
        printf("Input is invalid\n");
        return input_validity;
    }

    // All VPs
    if (input.vp_index == HV_ANY_VP) {
        return HV_STATUS_INVALID_VP_INDEX;
    }

    if (input.vp_index == HV_VP_INDEX_SELF) {
        target_vcpu = hyperv_vsm_vcpu(hyperv_vp_index(cs), target_vtl);
    } else {
        target_vcpu = hyperv_vsm_vcpu(input.vp_index, target_vtl);
    }

    if (!target_vcpu) {
        printf("Invalid VP index %i\n", input.vp_index);
        return HV_STATUS_INVALID_VP_INDEX;
    }

    tr = kvm_gva_to_gpa(target_vcpu, input.gva << HV_PAGE_SHIFT, NULL, input.control_flags);

    output.gpa = tr.physical_address >> HV_PAGE_SHIFT;

    if (tr.valid) {
        output.result_code = HV_XLATE_GVA_SUCCESS;
        output.cache_type = HV_CACHE_TYPE_X64_WB;
        output.overlay_page = hyperv_gpa_is_overlay(target_vcpu, tr.physical_address);

        if (input.control_flags & HV_XLATE_GVA_TLB_FLUSH_INHIBIT) {
            CPUState *vtl0 = hyperv_get_prev_vtl(cs);
            kvm_ioctl_set_tlb_inhibit(vtl0, true);
        }
    } else {
        if (tr.error_code == KVM_TRANSLATE_FAULT_NOT_PRESENT || tr.error_code == KVM_TRANSLATE_FAULT_INVALID_GVA) {
            output.result_code = HV_XLATE_GVA_UNMAPPED;
        } else if (tr.error_code == KVM_TRANSLATE_FAULT_PRIVILEGE_VIOLATION) {
            output.result_code = HV_XLATE_GVA_PRIVILEGE_VIOLATION;
        } else if (tr.error_code == KVM_TRANSLATE_FAULT_RESERVED_BITS) {
            output.result_code = HV_XLATE_GVA_INVALID_PAGE_TABLE_FLAGS;
        } else if (tr.error_code == KVM_TRANSLATE_FAULT_INVALID_GPA) {
            output.result_code = HV_XLATE_GPA_UNMAPPED;
        } else if (!tr.set_bits_succeeded && input.control_flags & HV_XLATE_GVA_SET_PAGE_TABLE_BITS) {
            output.result_code = HV_XLATE_GPA_NO_WRITE;
        } else {
            warn_report("unknown translate error code %u", tr.error_code);
            output.result_code = HV_XLATE_GVA_PRIVILEGE_VIOLATION;
        }
    }

	trace_hyperv_hcall_translate_virtual_address(input.partition_id, input.vp_index,
                                                 target_vtl, input.control_flags,
                                                 input.gva, output.gpa,
                                                 output.overlay_page,
                                                 output.result_code);

	if (fast) {
		memcpy(&exit->u.hcall.xmm[2], &output, sizeof(output));
	} else {
		hyperv_physmem_write(cs, exit->u.hcall.outgpa, &output, sizeof(output));
	}

	return HV_STATUS_SUCCESS;

}

static uint8_t hyperv_gen_intercept_access_mask(uint64_t flags)
{
    if (flags & KVM_MEMORY_EXIT_FLAG_READ)
        return HV_INTERCEPT_ACCESS_READ;

    if (flags & KVM_MEMORY_EXIT_FLAG_WRITE)
        return HV_INTERCEPT_ACCESS_WRITE;

    if (flags & KVM_MEMORY_EXIT_FLAG_EXECUTE)
        return HV_INTERCEPT_ACCESS_EXECUTE;

    return 0;
}

static void hyperv_build_memory_intercept(CPUState *intercepted_cpu,
                                          struct hyperv_message *msg,
                                          uint64_t gpa, uint64_t flags,
                                          uint8_t exit_instruction_len)
{
    struct hyperv_memory_intercept *intercept = (struct hyperv_memory_intercept *)msg->payload;
    X86CPU *cpu = X86_CPU(intercepted_cpu);
    struct hv_x64_segment_register rhs;
    CPUX86State *env = &cpu->env;

	msg->header.message_type = HV_MESSAGE_GPA_INTERCEPT;
	msg->header.payload_size = sizeof(*intercept);

	intercept->header.vp_index = hyperv_vp_index(intercepted_cpu);
	intercept->header.instruction_length = exit_instruction_len;
	intercept->header.access_type_mask = hyperv_gen_intercept_access_mask(flags);
    hyperv_get_seg(&env->segs[R_CS], &rhs);
    memcpy(&intercept->header.cs, &rhs, sizeof(intercept->header.cs));
	intercept->header.exec_state.cr0_pe = (env->cr[0] & CR0_PE_MASK);
	intercept->header.exec_state.cr0_am = (env->cr[0] & CR0_AM_MASK);
    hyperv_get_seg(&env->segs[R_SS], &rhs);
	intercept->header.exec_state.cpl = rhs.descriptor_privilege_level;
	intercept->header.exec_state.efer_lma = !!(env->efer & MSR_EFER_LMA);
	intercept->header.exec_state.debug_active = 0;
	intercept->header.exec_state.interruption_pending = 0;
	intercept->header.rip = env->eip;
	intercept->header.rflags = env->eflags;

	/*
	 * For exec violations we don't have a way to decode an instruction that issued a fetch
	 * to a non-X page because CPU points RIP and GPA to the fetch destination in the faulted page.
	 * Instruction length though is the length of the fetch source.
	 * Seems like Hyper-V is aware of that and is not trying to access those fields.
	 */
	if (intercept->header.access_type_mask == HV_INTERCEPT_ACCESS_EXECUTE) {
		intercept->instruction_byte_count = 0;
	} else {
		intercept->instruction_byte_count = exit_instruction_len;
		if (intercept->instruction_byte_count > sizeof(intercept->instruction_bytes))
			intercept->instruction_byte_count = sizeof(intercept->instruction_bytes);

		hyperv_physmem_read(intercepted_cpu, env->eip, intercept->instruction_bytes,
                            intercept->instruction_byte_count);
	}

	intercept->memory_access_info.gva_valid = 0;
	intercept->gva = 0;
	intercept->gpa = gpa;
	intercept->cache_type = HV_X64_CACHE_TYPE_WRITEBACK;
    hyperv_get_seg(&env->segs[R_DS], &rhs);
    memcpy(&intercept->ds, &rhs, sizeof(intercept->ds));
    hyperv_get_seg(&env->segs[R_SS], &rhs);
    memcpy(&intercept->ss, &rhs, sizeof(intercept->ss));
    intercept->rax = env->regs[R_EAX];
    intercept->rbx = env->regs[R_EBX];
    intercept->rcx = env->regs[R_ECX];
    intercept->rdx = env->regs[R_EDX];
    intercept->rsp = env->regs[R_ESP];
    intercept->rbp = env->regs[R_EBP];
    intercept->rsi = env->regs[R_ESI];
    intercept->rdi = env->regs[R_EDI];
    intercept->r8 = env->regs[8];
    intercept->r9 = env->regs[9];
    intercept->r10 = env->regs[10];
    intercept->r11 = env->regs[11];
    intercept->r12 = env->regs[12];
    intercept->r13 = env->regs[13];
    intercept->r14 = env->regs[14];
    intercept->r15 = env->regs[15];
}

static inline uint64_t hyperv_memprot_flags_to_memattrs(int flags)
{
    uint64_t memattrs = KVM_MEMORY_ATTRIBUTE_NR | KVM_MEMORY_ATTRIBUTE_NW |
                        KVM_MEMORY_ATTRIBUTE_NX;

    if (flags & KVM_HV_VTL_PROTECTION_READ)
        memattrs &= ~KVM_MEMORY_ATTRIBUTE_NR;

    if (flags & KVM_HV_VTL_PROTECTION_WRITE)
        memattrs &= ~KVM_MEMORY_ATTRIBUTE_NW;

    if (flags & (KVM_HV_VTL_PROTECTION_KMX | KVM_HV_VTL_PROTECTION_UMX))
        memattrs &= ~KVM_MEMORY_ATTRIBUTE_NX;

    return memattrs;
}

static int hyperv_set_memory_attrs(uint8_t vtl, uint32_t flags, uint16_t count,
                                  uint64_t *gfn_list)
{
    struct kvm_memory_attributes attrs = { };
    GHashTable *prots = hv_vsm.prots[vtl];
    KVMState *s = hv_vsm.s[vtl];
    uint64_t start, end;
    int i, ret;

    start = gfn_list[0];
    end = start + 1;
    for (i = 1; i < count; i++) {
        if (gfn_list[i] == end) {
            end++;
            continue;
        }

        attrs.address = start << HV_PAGE_SHIFT;
        attrs.size = (end - start) * HV_PAGE_SIZE;
        attrs.attributes = hyperv_memprot_flags_to_memattrs(flags);

        ret = kvm_vm_ioctl(s, KVM_SET_MEMORY_ATTRIBUTES, &attrs);
        if (ret) {
            printf("Failed to set memprots for: addr %llx, size %llx, attrs 0x%llx, ret %d\n",
                 attrs.address, attrs.size, attrs.attributes, ret);
            return ret;
        }

        start = gfn_list[i];
        end = start + 1;
    }

    attrs.address = start << HV_PAGE_SHIFT;
    attrs.size = (end - start) * HV_PAGE_SIZE;
    attrs.attributes = hyperv_memprot_flags_to_memattrs(flags);

    ret = kvm_vm_ioctl(s, KVM_SET_MEMORY_ATTRIBUTES, &attrs);
    if (ret) {
        printf("Failed to set memprots for: addr %llx, size %llx, attrs 0x%llx\n",
             attrs.address, attrs.size, attrs.attributes);
        return ret;
    }

    for (i = 0; i < count; i++)
        g_hash_table_insert(prots, GUINT_TO_POINTER(gfn_list[i]),
                            GINT_TO_POINTER(flags));

    return 0;
}

uint64_t hyperv_hcall_vtl_protection_mask(CPUState *cs, struct kvm_hyperv_exit *exit)
{
    uint16_t rep_cnt = (exit->u.hcall.input >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (exit->u.hcall.input >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    union hv_modify_vtl_protection_mask input;
    bool rep =  !!(rep_cnt || rep_idx);
    __u64 *xmm = &exit->u.hcall.xmm[0];
    uint8_t target_vtl;
    uint64_t *gfn_list;
    uint16_t count, i;

    assert(!(rep && rep_idx >= rep_cnt));
    count = rep_cnt - rep_idx;
    if (fast) {
        input.as_u64[0] = exit->u.hcall.ingpa;
        input.as_u64[1] = exit->u.hcall.outgpa;

        /* We always return everything for fast calls, so no continuations should be possible */
        if (rep_idx != 0)
            return HV_STATUS_INVALID_HYPERCALL_INPUT;

        gfn_list = g_malloc0(count * sizeof(*gfn_list));

        for (i = 0; i < count; i++)
            gfn_list[i] = xmm[i];
    } else {
        uint64_t ingpa = exit->u.hcall.ingpa;
        hyperv_physmem_read(cs, ingpa, &input, sizeof(input));

        gfn_list = g_malloc0(count * sizeof(*gfn_list));
        ingpa += sizeof(input) + rep_idx * sizeof(*gfn_list);
        hyperv_physmem_read(cs, ingpa, gfn_list, count * sizeof(*gfn_list));
    }

    trace_hyperv_hcall_vtl_protection_mask(input.target_partition_id,
                                           input.map_flags,
                                           input.input_vtl.target_vtl, count);

    /* Handle partition ID (the only supported id is self) */
    if (input.target_partition_id != HV_PARTITION_ID_SELF)
        return HV_STATUS_INVALID_PARTITION_ID;

    /* Handle target VTL we should use */
    if (input.input_vtl.use_target_vtl) {
        target_vtl = input.input_vtl.target_vtl;

        /* VTL may only set protections for a lower VTL */
        if (target_vtl >= get_active_vtl(cs))
            return HV_STATUS_ACCESS_DENIED;
    } else {
        /*
         * VTL can only apply protections on a lower VTL, so assume that if target
         * VTL bit is not set by guest we use the previous VTL.
         */
        target_vtl = get_active_vtl(cs) - 1;
        if (target_vtl == HV_INVALID_VTL)
            return HV_STATUS_INVALID_PARAMETER;
    }

    if (target_vtl >= HV_NUM_VTLS)
        return HV_STATUS_INVALID_PARAMETER;

    if (hyperv_set_memory_attrs(target_vtl, input.map_flags, count, gfn_list))
        return HV_STATUS_INVALID_PARAMETER;

    g_free(gfn_list);
    return (uint64_t)count << HV_HYPERCALL_REP_COMP_OFFSET;
}

static void intercept_cb(void *data, int status)
{
    VpVsmState *vsm = data;

    if (!status) {
        return;
    }

    assert(status == -EAGAIN);

    while (hyperv_post_msg(vsm->intercept_route, &vsm->intercept_route->staged_msg->msg))
        sched_yield();
}

static int hyperv_deliver_memory_intercept(CPUState *cs, struct hyperv_message *msg)
{
    VpVsmState *vsm = get_vp_vsm(cs);

    if (!vsm->intercept_route)
        vsm->intercept_route = hyperv_sint_route_new(hyperv_vp_index(cs),
                                                     get_active_vtl(cs), 0,
                                                     intercept_cb, cs);
    if (!vsm->intercept_route) {
        error_report("Failed to init intercept sint route\n");
        return -1;
    }

    while (hyperv_post_msg(vsm->intercept_route, msg))
        sched_yield();

    return 0;
}

static void print_hyperv_memory_intercept(const struct hyperv_memory_intercept *intercept)
{
    printf("hyperv_intercept_header:\n");
    printf("  vp_index: %u\n", intercept->header.vp_index);
    printf("  instruction_length: %u\n", intercept->header.instruction_length);
    printf("  access_type_mask: ");
    // TODO: Review this, either the print function or the intercepts are wrong
    if (intercept->header.access_type_mask & HV_INTERCEPT_ACCESS_MASK_READ)
        printf("READ ");
    if (intercept->header.access_type_mask & HV_INTERCEPT_ACCESS_MASK_WRITE)
        printf("WRITE ");
    if (intercept->header.access_type_mask & HV_INTERCEPT_ACCESS_MASK_EXECUTE)
        printf("EXECUTE ");
    if (intercept->header.access_type_mask == HV_INTERCEPT_ACCESS_MASK_NONE)
        printf("NONE");
    printf("\n");
    printf("  exec_state.as_u16: 0x%04" PRIx16 "\n", intercept->header.exec_state.as_u16);
    printf("  exec_state.cpl: %u\n", intercept->header.exec_state.cpl);
    printf("  exec_state.cr0_pe: %u\n", intercept->header.exec_state.cr0_pe);
    printf("  exec_state.cr0_am: %u\n", intercept->header.exec_state.cr0_am);
    printf("  exec_state.efer_lma: %u\n", intercept->header.exec_state.efer_lma);
    printf("  exec_state.debug_active: %u\n", intercept->header.exec_state.debug_active);
    printf("  exec_state.interruption_pending: %u\n", intercept->header.exec_state.interruption_pending);
    printf("  cs.base: 0x%016" PRIx64 "\n", intercept->header.cs.base);
    printf("  cs.limit: 0x%08" PRIx32 "\n", intercept->header.cs.limit);
    printf("  cs.selector: 0x%04" PRIx16 "\n", intercept->header.cs.selector);
    printf("  cs.attributes: 0x%04" PRIx16 "\n", intercept->header.cs.attributes);
    printf("  rip: 0x%016" PRIx64 "\n", intercept->header.rip);
    printf("  rflags: 0x%016" PRIx64 "\n", intercept->header.rflags);

    printf("hyperv_memory_intercept:\n");
    printf("  cache_type: ");
    switch (intercept->cache_type) {
        case HV_X64_CACHE_TYPE_UNCACHED:
            printf("UNCACHED\n");
            break;
        case HV_X64_CACHE_TYPE_WRITECOMBINING:
            printf("WRITECOMBINING\n");
            break;
        case HV_X64_CACHE_TYPE_WRITETHROUGH:
            printf("WRITETHROUGH\n");
            break;
        case HV_X64_CACHE_TYPE_WRITEPROTECTED:
            printf("WRITEPROTECTED\n");
            break;
        case HV_X64_CACHE_TYPE_WRITEBACK:
            printf("WRITEBACK\n");
            break;
        default:
            printf("UNKNOWN (0x%08" PRIx32 ")\n", intercept->cache_type);
            break;
    }
    printf("  instruction_byte_count: %u\n", intercept->instruction_byte_count);
    printf("  memory_access_info.as_u8: 0x%02" PRIx8 "\n", intercept->memory_access_info.as_u8);
    printf("  memory_access_info.gva_valid: %u\n", intercept->memory_access_info.gva_valid);
    printf("  _reserved: 0x%04" PRIx16 "\n", intercept->_reserved);
    printf("  gva: 0x%016" PRIx64 "\n", intercept->gva);
    printf("  gpa: 0x%016" PRIx64 "\n", intercept->gpa);
    printf("  instruction_bytes: ");
    for (int i = 0; i < intercept->instruction_byte_count; i++) {
        printf("0x%02" PRIx8 " ", intercept->instruction_bytes[i]);
    }
    printf("\n");
    printf("  ds.base: 0x%016" PRIx64 "\n", intercept->ds.base);
    printf("  ds.limit: 0x%08" PRIx32 "\n", intercept->ds.limit);
    printf("  ds.selector: 0x%04" PRIx16 "\n", intercept->ds.selector);
    printf("  ds.attributes: 0x%04" PRIx16 "\n", intercept->ds.attributes);
    printf("  ss.base: 0x%016" PRIx64 "\n", intercept->ss.base);
    printf("  ss.limit: 0x%08" PRIx32 "\n", intercept->ss.limit);
    printf("  ss.selector: 0x%04" PRIx16 "\n", intercept->ss.selector);
    printf("  ss.attributes: 0x%04" PRIx16 "\n", intercept->ss.attributes);
    printf("  rax: 0x%016" PRIx64 "\n", intercept->rax);
    printf("  rcx: 0x%016" PRIx64 "\n", intercept->rcx);
    printf("  rdx: 0x%016" PRIx64 "\n", intercept->rdx);
    printf("  rbx: 0x%016" PRIx64 "\n", intercept->rbx);
    printf("  rsp: 0x%016" PRIx64 "\n", intercept->rsp);
    printf("  rbp: 0x%016" PRIx64 "\n", intercept->rbp);
    printf("  rsi: 0x%016" PRIx64 "\n", intercept->rsi);
    printf("  rdi: 0x%016" PRIx64 "\n", intercept->rdi);
    printf("  r8: 0x%016" PRIx64 "\n", intercept->r8);
    printf("  r9: 0x%016" PRIx64 "\n", intercept->r9);
    printf("  r10: 0x%016" PRIx64 "\n", intercept->r10);
    printf("  r11: 0x%016" PRIx64 "\n", intercept->r11);
    printf("  r12: 0x%016" PRIx64 "\n", intercept->r12);
    printf("  r13: 0x%016" PRIx64 "\n", intercept->r13);
    printf("  r14: 0x%016" PRIx64 "\n", intercept->r14);
    printf("  r15: 0x%016" PRIx64 "\n", intercept->r15);
}

int kvm_hv_handle_fault(CPUState *cs, uint64_t gpa, uint64_t size,
                        uint64_t flags, uint8_t exit_instruction_len)
{
    GHashTable *prots = hv_vsm.prots[get_active_vtl(cs)];
    uint64_t gfn = gpa >> HV_PAGE_SHIFT;
	struct hyperv_message msg = { 0 };
    uint64_t prot;

    if (!g_hash_table_contains(prots, GUINT_TO_POINTER(gfn))) {
        printf("Unexpected page fault at vcpu%d addr 0x%lx size %lx flags %lx\n",
               hyperv_vp_index(cs), gpa, size, flags);
        return -1;
    }

    prot = GPOINTER_TO_UINT(g_hash_table_lookup(prots, GUINT_TO_POINTER(gfn)));

    trace_hyperv_handle_fault(hyperv_vp_index(cs), get_active_vtl(cs), gpa,
                              size, exit_instruction_len, flags, prot);

    printf("VP index %d, vtl %d, gpa 0x%lx, size 0x%lx, insn len %d, flags "
           "0x%lx, vtl prots 0x%lx\n",
           hyperv_vp_index(cs), get_active_vtl(cs), gpa, size,
           exit_instruction_len, flags, prot);

    cs->stop = true;
    cpu_synchronize_state(cs);
    hyperv_build_memory_intercept(cs, &msg, gpa, flags, exit_instruction_len);
    hyperv_deliver_memory_intercept(hyperv_get_next_vtl(cs), &msg);
    print_hyperv_memory_intercept((struct hyperv_memory_intercept *)msg.payload);

    return EXCP_HALTED;
}

static uint64_t hyperv_get_sparse_vp_set(CPUState *cs, struct kvm_hyperv_exit *exit,
                                         bool fast, uint16_t cnt, uint64_t *data,
                                         int consumed_xmm_halves)
{
    uint64_t in_addr;
	int i;

	if (cnt > HV_MAX_SPARSE_VCPU_BANKS)
		return -EINVAL;

	if (fast) {
		/*
		 * Each XMM holds two sparse banks, but do not count halves that
		 * have already been consumed for hypercall parameters.
		 */
		if (cnt > 2 * HV_HYPERCALL_MAX_XMM_REGISTERS - consumed_xmm_halves)
			return HV_STATUS_INVALID_HYPERCALL_INPUT;

		for (i = 0; i < cnt; i++)
            data[i] = exit->u.hcall.xmm[i + consumed_xmm_halves];

		return 0;
	}

    in_addr = exit->u.hcall.ingpa + offsetof(struct hv_send_ipi_ex, vp_set.bank_contents);
	return hyperv_physmem_read(cs, in_addr, data, cnt * sizeof(*data));
}

static bool hyperv_is_vp_in_sparse_set(uint32_t vp_id, uint64_t valid_bank_mask,
                                       uint64_t sparse_banks[])
{
	int valid_bit_nr = vp_id / HV_VCPUS_PER_SPARSE_BANK;
	unsigned long sbank;

	if (!test_bit(valid_bit_nr, (unsigned long *)&valid_bank_mask))
		return false;

	/*
	 * The index into the sparse bank is the number of preceding bits in
	 * the valid mask.  Optimize for VMs with <64 vCPUs by skipping the
	 * fancy math if there can't possibly be preceding bits.
	 */
	if (valid_bit_nr)
		sbank = hweight64(valid_bank_mask & MAKE_64BIT_MASK(0, valid_bit_nr - 1));
	else
		sbank = 0;

	return test_bit(vp_id % HV_VCPUS_PER_SPARSE_BANK,
			(unsigned long *)&sparse_banks[sbank]);
}

uint64_t hyperv_hcall_send_ipi(CPUState *cs, int code, struct kvm_hyperv_exit *exit)
{
    uint16_t var_cnt = (exit->u.hcall.input & HV_HYPERCALL_VARHEAD_MASK) >>
                       HV_HYPERCALL_VARHEAD_OFFSET;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    uint64_t sparse_banks[HV_MAX_SPARSE_VCPU_BANKS];
    uint64_t ingpa = exit->u.hcall.ingpa;
    struct hv_send_ipi_ex send_ipi_ex;
    CPUClass *cc = CPU_GET_CLASS(cs);
    struct hv_send_ipi send_ipi;
    union hv_input_vtl in_vtl;
    uint64_t valid_bank_mask;
    bool all_cpus = false;
    CPUState *target_cs;
    uint32_t vector;

    if (code == HV_SEND_IPI) {
        if (fast) {
            vector = (uint32_t)ingpa;
            in_vtl.as_uint8 = (uint8_t)(ingpa >> 32);
            sparse_banks[0] = exit->u.hcall.outgpa;
        } else {
            hyperv_physmem_read(cs, ingpa, &send_ipi, sizeof(send_ipi));
            vector = send_ipi.vector;
            in_vtl.as_uint8 = send_ipi.in_vtl.as_uint8;
            sparse_banks[0] = send_ipi.cpu_mask;
        }

        valid_bank_mask = BIT_ULL(0);

        printf("VTL PV IPI from VTL%d to VTL%d, vec %d cpu_mask %lx\n",
               get_active_vtl(cs), in_vtl.target_vtl, vector, sparse_banks[0]);

        trace_hyperv_hcall_send_ipi(hyperv_vp_index(cs), vector,
                                    get_active_vtl(cs), in_vtl.target_vtl,
                                    sparse_banks[0]);
    } else {
        if (fast) {
            vector = (uint32_t)exit->u.hcall.ingpa;
            in_vtl.as_uint8 = (uint8_t)(exit->u.hcall.ingpa >> 32);
            send_ipi_ex.vp_set.format = exit->u.hcall.outgpa;
            valid_bank_mask = exit->u.hcall.xmm[0];
        } else {
            hyperv_physmem_read(cs, ingpa, &send_ipi_ex, sizeof(send_ipi_ex));
            vector = send_ipi_ex.vector;
            in_vtl.as_uint8 = send_ipi_ex.in_vtl.as_uint8;
            valid_bank_mask = send_ipi_ex.vp_set.valid_bank_mask;
        }

        all_cpus = send_ipi_ex.vp_set.format == HV_GENERIC_SET_ALL;
        if (all_cpus)
            goto check_and_send_ipi;

        if (hyperv_get_sparse_vp_set(cs, exit, fast, var_cnt, sparse_banks, 1))
            return HV_STATUS_INVALID_HYPERCALL_INPUT;

        printf("VTL PV IPI EX from VTL%d to VTL%d, vec %d format %lx, mask %lx, allcpus %d, bank0 %lx, bank1 %lx\n",
               get_active_vtl(cs), in_vtl.target_vtl, vector,
               send_ipi_ex.vp_set.format, valid_bank_mask, all_cpus,
               sparse_banks[0], sparse_banks[1]);
        trace_hyperv_hcall_send_ipi_ex( hyperv_vp_index(cs), vector,
                get_active_vtl(cs), in_vtl.target_vtl, all_cpus, valid_bank_mask,
                sparse_banks[0], sparse_banks[1]);
    }

check_and_send_ipi:
    if ((vector < HV_IPI_LOW_VECTOR) || (vector > HV_IPI_HIGH_VECTOR))
        return HV_STATUS_INVALID_HYPERCALL_INPUT;

    CPU_FOREACH(target_cs) {
        if (get_active_vtl(target_cs) != in_vtl.target_vtl)
            continue;

        if (!all_cpus && !hyperv_is_vp_in_sparse_set(hyperv_vp_index(target_cs),
                                                     valid_bank_mask, sparse_banks))
            continue;

        printf("IPI sent to CPU %d VTL %d\n", hyperv_vp_index(target_cs), in_vtl.target_vtl);
        MSIMessage msg = {
            .address = APIC_DEFAULT_ADDRESS |
                       (cc->get_arch_id(target_cs) << MSI_ADDR_DEST_ID_SHIFT),
            .data = vector,
        };
        kvm_irqchip_send_msi(target_cs->kvm_state, msg);
    }

    return HV_STATUS_SUCCESS;
}

uint64_t hyperv_hcall_get_vp_index_from_apic_id(CPUState *cs, struct kvm_hyperv_exit *exit)
{
    uint16_t rep_cnt = (exit->u.hcall.input >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    uint16_t rep_idx = (exit->u.hcall.input >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    struct hv_get_vp_index_from_apic_id_input input;
    CPUState *target_vcpu;
    uint64_t apic_id;
    uint64_t vp_index;
    uint16_t count;

    count = rep_cnt - rep_idx;
    count = !!count;

    if (fast) {
        input.partition_id = exit->u.hcall.ingpa;
        input.target_vtl = exit->u.hcall.outgpa & 0xFF;
        apic_id = exit->u.hcall.xmm[0];
    } else {
        hyperv_physmem_read(cs, exit->u.hcall.ingpa, &input, sizeof(input));
        hyperv_physmem_read(cs, exit->u.hcall.ingpa + sizeof(input), &apic_id, sizeof(apic_id));
    }

    /* Only self-targeting is supported */
    if (input.partition_id != HV_PARTITION_ID_SELF)
        return HV_STATUS_INVALID_PARTITION_ID;

    apic_id &= 0xFFFFFFFF;
    target_vcpu = hyperv_vsm_vcpu(apic_id, input.target_vtl);
    if (!target_vcpu)
        return HV_STATUS_INVALID_PARAMETER;

    vp_index = hyperv_vp_index(target_vcpu);
    trace_hyperv_hvcall_get_vp_index_from_apic_id(input.partition_id,
                                                  input.target_vtl, apic_id, vp_index);

    printf("apic_id vp id: partition_id %lx, vtl %u, apic_id 0x%lx, VP index %lu\n", input.partition_id, input.target_vtl, apic_id, vp_index);

    if (fast) {
        exit->u.hcall.xmm[2] = vp_index;
    } else {
        hyperv_physmem_write(cs, exit->u.hcall.outgpa, &vp_index, sizeof(vp_index));
    }

    return ((uint64_t)count << HV_HYPERCALL_REP_COMP_OFFSET) | HV_STATUS_SUCCESS;
}

static void __do_cpu_init(CPUState *cs, run_on_cpu_data arg)
{
    do_cpu_init(X86_CPU(cs));
}

uint64_t kvm_hv_start_virtual_processor(CPUState *cs, struct kvm_hyperv_exit *exit)
{
    uint16_t rep_idx = (exit->u.hcall.input >> HV_HYPERCALL_REP_START_OFFSET) & 0xfff;
    uint16_t rep_cnt = (exit->u.hcall.input >> HV_HYPERCALL_REP_COMP_OFFSET) & 0xfff;
    bool fast = exit->u.hcall.input & HV_HYPERCALL_FAST;
    uint8_t current_vtl = get_active_vtl(cs);
    struct hv_enable_vp_vtl input;
    uint8_t start_vtl;
    VpVsmState *vpvsm;
    CPUState *vcpu;

    /* HvStartVirtualProcessor cannot be fast or rep */
    if (fast || !!(rep_cnt || rep_idx))
        return HV_STATUS_INVALID_HYPERCALL_INPUT;

    hyperv_physmem_read(cs, exit->u.hcall.ingpa, &input, sizeof(input));

    trace_hyperv_hcall_start_virtual_processor(input.partition_id, input.vp_index,
                                               input.target_vtl, current_vtl);
    printf("vp init: partition_id 0x%lx, VP index %u, target vtl %u, active vtl %u\n",
           input.partition_id, input.vp_index, input.target_vtl, current_vtl);

    /* Only self-targeting is supported */
    if (input.partition_id != HV_PARTITION_ID_SELF)
        return HV_STATUS_INVALID_PARTITION_ID;

    /* AP must not be in any initialized or runnable states */
    for (int i = input.target_vtl - 1; i >= 0; i--) {
        vcpu = hyperv_vsm_vcpu(input.vp_index, i);
        if (!vcpu || !cpu_is_stopped(vcpu) || cpu_is_bsp(X86_CPU(vcpu)))
            return HV_STATUS_INVALID_VP_STATE;

        /* Is target VTL already enabled for target vcpu? */
        vpvsm = get_vp_vsm(vcpu);
        if (input.target_vtl > 0 &&
            vpvsm->vsm_vp_status.enabled_vtl_set & (1ul << input.target_vtl)) {
            return HV_STATUS_INVALID_PARAMETER;
        }
    }

    /* Check that target VTL is sane and can enable target vcpu in target vtl */
    if (input.target_vtl > hv_vsm_partition_status.maximum_vtl ||
        input.target_vtl > current_vtl) {
          printf("Current vcpu in VTL%d cannot enable target vcpu in VTL%d\n",
                 input.target_vtl, current_vtl);
          return HV_STATUS_INVALID_PARAMETER;
    }

    vpvsm = get_vp_vsm(hyperv_vsm_vcpu(input.vp_index, 0));
    if (!(vpvsm->vsm_vp_status.enabled_vtl_set & (1 << input.target_vtl)))
        return HV_STATUS_INVALID_PARAMETER;

    vcpu = hyperv_vsm_vcpu(input.vp_index, input.target_vtl);
    if (!vcpu)
        return HV_STATUS_INVALID_PARAMETER;

    bql_lock();
    kvm_cpu_synchronize_state(vcpu);
    vcpu->stop = true;
    run_on_cpu(vcpu, __do_cpu_init, RUN_ON_CPU_NULL);
    bql_unlock();

    input.vp_context.efer |= (1 << 10); // EFER_LMA
    print_hv_init_vp_context(&input.vp_context);
    hyperv_set_vtl_cpu_state(vcpu, &input.vp_context, true);

    bql_lock();
    cpu_synchronize_post_reset(vcpu);
    bql_unlock();

    start_vtl = fls(vpvsm->vsm_vp_status.enabled_vtl_set) - 1;
    hyperv_vsm_vcpu(input.vp_index, start_vtl)->kvm_run->dump_state_on_run = true;
    cpu_resume(hyperv_vsm_vcpu(input.vp_index, start_vtl));

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
