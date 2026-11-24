#define _GNU_SOURCE
#include "device_common.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/gen_stats.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* ==========================================================================
 * RTNetlink Topology Manager & Live Listener
 * Tracks RTM_NEWLINK/DELLINK, RTM_NEWQDISC/DELQDISC (incl. TCA_DUMP_INVISIBLE
 * for HTB default pfifo/bfifo leaves & TCA_STATS2), and RTM_NEWTCLASS/DELTCLASS
 * (incl. HTB prio/quantum/rate64/ceil64 & TCA_STATS2) with monotonic dev_gen
 * and queue_gen, plus full resync on ENOBUFS or NLM_F_DUMP_INTR.
 * ========================================================================== */

#ifndef ARPHRD_RAWIP
#define ARPHRD_RAWIP 519
#endif
#ifndef ARPHRD_NONE
#define ARPHRD_NONE 65534
#endif
#ifndef TCA_DUMP_INVISIBLE
#define TCA_DUMP_INVISIBLE 10
#endif
#ifndef TCA_HTB_PARMS
#define TCA_HTB_PARMS 1
#endif
#ifndef TCA_HTB_RATE64
#define TCA_HTB_RATE64 7
#endif
#ifndef TCA_HTB_CEIL64
#define TCA_HTB_CEIL64 8
#endif
#ifndef TCA_STATS_BASIC
#define TCA_STATS_BASIC 1
#endif
#ifndef TCA_STATS_QUEUE
#define TCA_STATS_QUEUE 3
#endif
#ifndef TCA_STATS_PKT64
#define TCA_STATS_PKT64 9
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK 0x3FFFU
#endif

static uint16_t arphrd_to_linktype(uint16_t arphrd) {
    switch (arphrd) {
    case ARPHRD_NONE:
    case ARPHRD_RAWIP:
    case ARPHRD_TUNNEL:
    case ARPHRD_TUNNEL6:
    case ARPHRD_SIT:
    case ARPHRD_IPGRE:
    case ARPHRD_PPP:
        return PKT_LINKTYPE_RAW_IP; /* 101 */
    case ARPHRD_ETHER:
    case ARPHRD_LOOPBACK:
    default:
        return PKT_LINKTYPE_ETHERNET; /* 1 */
    }
}

static uint32_t get_self_netns_inum(void) {
    struct stat st;
    if (stat("/proc/self/ns/net", &st) == 0)
        return (uint32_t)st.st_ino;
    return 0;
}

static int save_epoch_snapshot(struct topo_mgr *tm) {
    if (tm->num_epochs >= DEV_MAX_TOPO_EPOCHS)
        return 0;

    uint32_t nd = 0, nq = 0, nc = 0;
    for (uint32_t i = 0; i < tm->num_devs; i++)
        if (tm->devs[i].present) nd++;
    for (uint32_t i = 0; i < tm->num_qdiscs; i++)
        if (tm->qdiscs[i].present) nq++;
    for (uint32_t i = 0; i < tm->num_classes; i++)
        if (tm->classes[i].present) nc++;

    struct topo_dev_entry   *dcopy = nd ? calloc(nd, sizeof(*dcopy)) : NULL;
    struct topo_qdisc_entry *qcopy = nq ? calloc(nq, sizeof(*qcopy)) : NULL;
    struct topo_class_entry *ccopy = nc ? calloc(nc, sizeof(*ccopy)) : NULL;
    if ((nd && !dcopy) || (nq && !qcopy) || (nc && !ccopy)) {
        free(dcopy);
        free(qcopy);
        free(ccopy);
        return -1;
    }

    uint32_t di = 0, qi = 0, ci = 0;
    for (uint32_t i = 0; i < tm->num_devs; i++)
        if (tm->devs[i].present) dcopy[di++] = tm->devs[i];
    for (uint32_t i = 0; i < tm->num_qdiscs; i++)
        if (tm->qdiscs[i].present) qcopy[qi++] = tm->qdiscs[i];
    for (uint32_t i = 0; i < tm->num_classes; i++)
        if (tm->classes[i].present) ccopy[ci++] = tm->classes[i];

    struct topo_epoch_snap *ep = &tm->epochs[tm->num_epochs++];
    ep->epoch_id    = ++tm->cur_epoch_id;
    ep->ts_ns       = now_boottime_ns();
    ep->netns_inum  = tm->netns_inum;
    ep->num_devs    = nd;
    ep->num_qdiscs  = nq;
    ep->num_classes = nc;
    ep->devs        = dcopy;
    ep->qdiscs      = qcopy;
    ep->classes     = ccopy;
    return 0;
}

static uint32_t ensure_dev_gen(struct topo_mgr *tm, uint32_t ifindex) {
    for (uint32_t i = 0; i < tm->num_devs; i++) {
        if (tm->devs[i].present && tm->devs[i].ifindex == ifindex)
            return tm->devs[i].dev_gen;
    }
    return 0;
}

static void parse_tc_stats_attrs(const struct rtattr *stats2_rta,
                                 const struct rtattr *legacy_stats_rta,
                                 uint64_t *bytes_out, uint32_t *packets_out,
                                 uint32_t *drops_out, uint32_t *overlimits_out) {
    *bytes_out = 0;
    *packets_out = 0;
    *drops_out = 0;
    *overlimits_out = 0;

    if (stats2_rta) {
        int slen = (int)RTA_PAYLOAD(stats2_rta);
        bool got_pkt64 = false;
        for (const struct rtattr *sr = (const struct rtattr *)RTA_DATA(stats2_rta);
             RTA_OK(sr, slen);
             sr = RTA_NEXT(sr, slen)) {
            uint16_t stype = sr->rta_type & NLA_TYPE_MASK;
            size_t pay = RTA_PAYLOAD(sr);
            const uint8_t *d = (const uint8_t *)RTA_DATA(sr);
            if (stype == TCA_STATS_BASIC && pay >= 12U) {
                memcpy(bytes_out, d, 8);
                if (!got_pkt64)
                    memcpy(packets_out, d + 8, 4);
            } else if (stype == TCA_STATS_PKT64 && pay >= 8U) {
                uint64_t p64 = 0;
                memcpy(&p64, d, 8);
                *packets_out = (p64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (uint32_t)p64;
                got_pkt64 = true;
            } else if (stype == TCA_STATS_QUEUE && pay >= 20U) {
                /* struct gnet_stats_queue: qlen@0, backlog@4, drops@8, requeues@12, overlimits@16 */
                memcpy(drops_out, d + 8, 4);
                memcpy(overlimits_out, d + 16, 4);
            }
        }
        return;
    }

    if (legacy_stats_rta && RTA_PAYLOAD(legacy_stats_rta) >= 20U) {
        const uint8_t *d = (const uint8_t *)RTA_DATA(legacy_stats_rta);
        memcpy(bytes_out, d, 8);
        memcpy(packets_out, d + 8, 4);
        memcpy(drops_out, d + 12, 4);
        memcpy(overlimits_out, d + 16, 4);
    }
}

static void parse_htb_class_options(const struct rtattr *opt_rta,
                                    uint32_t *prio_out, uint32_t *quantum_out,
                                    uint64_t *rate_bps_out, uint64_t *ceil_bps_out) {
    uint64_t rate64 = 0, ceil64 = 0;
    uint32_t rate32 = 0, ceil32 = 0;

    int olen = (int)RTA_PAYLOAD(opt_rta);
    for (const struct rtattr *or = (const struct rtattr *)RTA_DATA(opt_rta);
         RTA_OK(or, olen);
         or = RTA_NEXT(or, olen)) {
        uint16_t otype = or->rta_type & NLA_TYPE_MASK;
        size_t pay = RTA_PAYLOAD(or);
        const uint8_t *d = (const uint8_t *)RTA_DATA(or);
        if (otype == TCA_HTB_PARMS && pay >= sizeof(struct tc_htb_opt)) {
            struct tc_htb_opt hopt;
            memcpy(&hopt, d, sizeof(hopt));
            *prio_out    = hopt.prio;
            *quantum_out = hopt.quantum;
            rate32       = hopt.rate.rate;
            ceil32       = hopt.ceil.rate;
        } else if (otype == TCA_HTB_RATE64 && pay >= 8U) {
            memcpy(&rate64, d, 8);
        } else if (otype == TCA_HTB_CEIL64 && pay >= 8U) {
            memcpy(&ceil64, d, 8);
        }
    }

    *rate_bps_out = (rate64 > 0 ? rate64 : (uint64_t)rate32) * 8ULL;
    *ceil_bps_out = (ceil64 > 0 ? ceil64 : (uint64_t)ceil32) * 8ULL;
}

static bool handle_link_msg(struct topo_mgr *tm, const struct nlmsghdr *nlh, bool *seen_devs) {
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
        return false;
    const struct ifinfomsg *ifi = (const struct ifinfomsg *)NLMSG_DATA(nlh);
    uint32_t ifindex = (uint32_t)ifi->ifi_index;

    char ifname[32] = "";
    int len = (int)IFLA_PAYLOAD(nlh);
    for (const struct rtattr *rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if ((rta->rta_type & NLA_TYPE_MASK) == IFLA_IFNAME) {
            size_t slen = RTA_PAYLOAD(rta);
            if (slen >= sizeof(ifname)) slen = sizeof(ifname) - 1;
            memcpy(ifname, RTA_DATA(rta), slen);
            ifname[slen] = '\0';
        }
    }

    if (nlh->nlmsg_type == RTM_DELLINK) {
        bool changed = false;
        for (uint32_t i = 0; i < tm->num_devs; i++) {
            if (tm->devs[i].present && tm->devs[i].ifindex == ifindex) {
                tm->devs[i].present = false;
                changed = true;
            }
        }
        for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
            if (tm->qdiscs[i].present && tm->qdiscs[i].ifindex == ifindex) {
                tm->qdiscs[i].present = false;
                changed = true;
            }
        }
        for (uint32_t i = 0; i < tm->num_classes; i++) {
            if (tm->classes[i].present && tm->classes[i].ifindex == ifindex) {
                tm->classes[i].present = false;
                changed = true;
            }
        }
        return changed;
    }

    uint16_t arphrd = (uint16_t)ifi->ifi_type;
    uint16_t linktype = arphrd_to_linktype(arphrd);

    for (uint32_t i = 0; i < tm->num_devs; i++) {
        if (tm->devs[i].present && tm->devs[i].ifindex == ifindex) {
            if (seen_devs) seen_devs[i] = true;
            if (strcmp(tm->devs[i].name, ifname) == 0 && tm->devs[i].linktype == linktype) {
                tm->devs[i].flags = ifi->ifi_flags;
                return false;
            }
            tm->devs[i].dev_gen = ++tm->next_dev_gen;
            tm->devs[i].arphrd = arphrd;
            tm->devs[i].linktype = linktype;
            tm->devs[i].flags = ifi->ifi_flags;
            snprintf(tm->devs[i].name, sizeof(tm->devs[i].name), "%s", ifname);
            return true;
        }
    }

    uint32_t slot = tm->num_devs;
    for (uint32_t i = 0; i < tm->num_devs; i++) {
        if (!tm->devs[i].present) {
            slot = i;
            break;
        }
    }
    if (slot >= DEV_MAX_TOPO_DEVICES) return false;
    if (slot == tm->num_devs) tm->num_devs++;

    tm->devs[slot].ifindex  = ifindex;
    tm->devs[slot].dev_gen  = ++tm->next_dev_gen;
    tm->devs[slot].arphrd   = arphrd;
    tm->devs[slot].linktype = linktype;
    tm->devs[slot].flags    = ifi->ifi_flags;
    tm->devs[slot].present  = true;
    snprintf(tm->devs[slot].name, sizeof(tm->devs[slot].name), "%s", ifname);
    if (seen_devs) seen_devs[slot] = true;
    return true;
}

static bool handle_qdisc_msg(struct topo_mgr *tm, const struct nlmsghdr *nlh, bool *seen_qdiscs) {
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct tcmsg)))
        return false;
    const struct tcmsg *tcm = (const struct tcmsg *)NLMSG_DATA(nlh);
    uint32_t ifindex = (uint32_t)tcm->tcm_ifindex;
    uint32_t handle  = tcm->tcm_handle;
    uint32_t parent  = tcm->tcm_parent;

    char kind[32] = "";
    const struct rtattr *stats2_rta = NULL;
    const struct rtattr *legacy_stats_rta = NULL;

    int len = (int)TCA_PAYLOAD(nlh);
    for (const struct rtattr *rta = TCA_RTA(tcm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        uint16_t rtype = rta->rta_type & NLA_TYPE_MASK;
        if (rtype == TCA_KIND) {
            size_t slen = RTA_PAYLOAD(rta);
            if (slen >= sizeof(kind)) slen = sizeof(kind) - 1;
            memcpy(kind, RTA_DATA(rta), slen);
            kind[slen] = '\0';
        } else if (rtype == TCA_STATS2) {
            stats2_rta = rta;
        } else if (rtype == TCA_STATS) {
            legacy_stats_rta = rta;
        }
    }

    if (nlh->nlmsg_type == RTM_DELQDISC) {
        bool changed = false;
        for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
            if (tm->qdiscs[i].present &&
                tm->qdiscs[i].ifindex == ifindex &&
                tm->qdiscs[i].handle == handle &&
                tm->qdiscs[i].parent == parent) {
                tm->qdiscs[i].present = false;
                changed = true;
            }
        }
        return changed;
    }

    uint64_t bytes = 0;
    uint32_t packets = 0, drops = 0, overlimits = 0;
    parse_tc_stats_attrs(stats2_rta, legacy_stats_rta, &bytes, &packets, &drops, &overlimits);

    uint32_t dev_gen = ensure_dev_gen(tm, ifindex);
    for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
        if (tm->qdiscs[i].present &&
            tm->qdiscs[i].ifindex == ifindex &&
            tm->qdiscs[i].handle == handle &&
            tm->qdiscs[i].parent == parent) {
            if (seen_qdiscs) seen_qdiscs[i] = true;
            tm->qdiscs[i].bytes      = bytes;
            tm->qdiscs[i].packets    = packets;
            tm->qdiscs[i].drops      = drops;
            tm->qdiscs[i].overlimits = overlimits;

            if (tm->qdiscs[i].dev_gen == dev_gen &&
                (strcmp(tm->qdiscs[i].kind, kind) == 0 || tm->qdiscs[i].kind[0] == '\0')) {
                if (tm->qdiscs[i].kind[0] == '\0' && kind[0] != '\0') {
                    snprintf(tm->qdiscs[i].kind, sizeof(tm->qdiscs[i].kind), "%s", kind);
                    return true;
                }
                return false;
            }
            tm->qdiscs[i].dev_gen   = dev_gen;
            tm->qdiscs[i].queue_gen = ++tm->next_queue_gen;
            snprintf(tm->qdiscs[i].kind, sizeof(tm->qdiscs[i].kind), "%s", kind);
            return true;
        }
    }

    uint32_t slot = tm->num_qdiscs;
    for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
        if (!tm->qdiscs[i].present) {
            slot = i;
            break;
        }
    }
    if (slot >= DEV_MAX_TOPO_QDISCS) return false;
    if (slot == tm->num_qdiscs) tm->num_qdiscs++;

    tm->qdiscs[slot].ifindex    = ifindex;
    tm->qdiscs[slot].dev_gen    = dev_gen;
    tm->qdiscs[slot].queue_gen  = ++tm->next_queue_gen;
    tm->qdiscs[slot].handle     = handle;
    tm->qdiscs[slot].parent     = parent;
    tm->qdiscs[slot].bytes      = bytes;
    tm->qdiscs[slot].packets    = packets;
    tm->qdiscs[slot].drops      = drops;
    tm->qdiscs[slot].overlimits = overlimits;
    tm->qdiscs[slot].present    = true;
    snprintf(tm->qdiscs[slot].kind, sizeof(tm->qdiscs[slot].kind), "%s", kind);
    if (seen_qdiscs) seen_qdiscs[slot] = true;
    return true;
}

static bool handle_tclass_msg(struct topo_mgr *tm, const struct nlmsghdr *nlh, bool *seen_classes) {
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct tcmsg)))
        return false;
    const struct tcmsg *tcm = (const struct tcmsg *)NLMSG_DATA(nlh);
    uint32_t ifindex = (uint32_t)tcm->tcm_ifindex;
    uint32_t handle  = tcm->tcm_handle;
    uint32_t parent  = tcm->tcm_parent;
    uint32_t leaf    = tcm->tcm_info;

    char kind[32] = "";
    const struct rtattr *opt_rta = NULL;
    const struct rtattr *stats2_rta = NULL;
    const struct rtattr *legacy_stats_rta = NULL;

    int len = (int)TCA_PAYLOAD(nlh);
    for (const struct rtattr *rta = TCA_RTA(tcm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        uint16_t rtype = rta->rta_type & NLA_TYPE_MASK;
        if (rtype == TCA_KIND) {
            size_t slen = RTA_PAYLOAD(rta);
            if (slen >= sizeof(kind)) slen = sizeof(kind) - 1;
            memcpy(kind, RTA_DATA(rta), slen);
            kind[slen] = '\0';
        } else if (rtype == TCA_OPTIONS) {
            opt_rta = rta;
        } else if (rtype == TCA_STATS2) {
            stats2_rta = rta;
        } else if (rtype == TCA_STATS) {
            legacy_stats_rta = rta;
        }
    }

    if (nlh->nlmsg_type == RTM_DELTCLASS) {
        bool changed = false;
        for (uint32_t i = 0; i < tm->num_classes; i++) {
            if (tm->classes[i].present &&
                tm->classes[i].ifindex == ifindex &&
                tm->classes[i].handle == handle) {
                tm->classes[i].present = false;
                changed = true;
            }
        }
        return changed;
    }

    uint32_t prio = 0, quantum = 0;
    uint64_t rate_bps = 0, ceil_bps = 0;
    if (opt_rta && strcmp(kind, "htb") == 0) {
        parse_htb_class_options(opt_rta, &prio, &quantum, &rate_bps, &ceil_bps);
    }

    uint64_t bytes = 0;
    uint32_t packets = 0, drops = 0, overlimits = 0;
    parse_tc_stats_attrs(stats2_rta, legacy_stats_rta, &bytes, &packets, &drops, &overlimits);

    uint32_t dev_gen = ensure_dev_gen(tm, ifindex);
    for (uint32_t i = 0; i < tm->num_classes; i++) {
        if (tm->classes[i].present &&
            tm->classes[i].ifindex == ifindex &&
            tm->classes[i].handle == handle) {
            if (seen_classes) seen_classes[i] = true;
            bool meta_changed = (tm->classes[i].dev_gen != dev_gen ||
                                 tm->classes[i].parent != parent ||
                                 tm->classes[i].leaf != leaf ||
                                 tm->classes[i].prio != prio ||
                                 tm->classes[i].rate_bps != rate_bps ||
                                 tm->classes[i].ceil_bps != ceil_bps ||
                                 strcmp(tm->classes[i].kind, kind) != 0);
            tm->classes[i].dev_gen    = dev_gen;
            tm->classes[i].parent     = parent;
            tm->classes[i].leaf       = leaf;
            tm->classes[i].prio       = prio;
            tm->classes[i].quantum    = quantum;
            tm->classes[i].rate_bps   = rate_bps;
            tm->classes[i].ceil_bps   = ceil_bps;
            tm->classes[i].bytes      = bytes;
            tm->classes[i].packets    = packets;
            tm->classes[i].drops      = drops;
            tm->classes[i].overlimits = overlimits;
            snprintf(tm->classes[i].kind, sizeof(tm->classes[i].kind), "%s", kind);
            return meta_changed;
        }
    }

    uint32_t slot = tm->num_classes;
    for (uint32_t i = 0; i < tm->num_classes; i++) {
        if (!tm->classes[i].present) {
            slot = i;
            break;
        }
    }
    if (slot >= DEV_MAX_TOPO_CLASSES) return false;
    if (slot == tm->num_classes) tm->num_classes++;

    tm->classes[slot].ifindex    = ifindex;
    tm->classes[slot].dev_gen    = dev_gen;
    tm->classes[slot].handle     = handle;
    tm->classes[slot].parent     = parent;
    tm->classes[slot].leaf       = leaf;
    tm->classes[slot].prio       = prio;
    tm->classes[slot].quantum    = quantum;
    tm->classes[slot].rate_bps   = rate_bps;
    tm->classes[slot].ceil_bps   = ceil_bps;
    tm->classes[slot].bytes      = bytes;
    tm->classes[slot].packets    = packets;
    tm->classes[slot].drops      = drops;
    tm->classes[slot].overlimits = overlimits;
    tm->classes[slot].present    = true;
    snprintf(tm->classes[slot].kind, sizeof(tm->classes[slot].kind), "%s", kind);
    if (seen_classes) seen_classes[slot] = true;
    return true;
}

static int send_rtm_dump_ex(int fd, uint16_t nlmsg_type, uint32_t seq,
                            int ifindex, bool dump_invisible) {
    struct {
        struct nlmsghdr nlh;
        union {
            struct ifinfomsg ifi;
            struct {
                struct tcmsg  tcm;
                struct rtattr inv;
            } tc;
        } u;
    } req;
    memset(&req, 0, sizeof(req));

    if (nlmsg_type == RTM_GETQDISC || nlmsg_type == RTM_GETTCLASS) {
        req.u.tc.tcm.tcm_family  = AF_UNSPEC;
        req.u.tc.tcm.tcm_ifindex = ifindex;
        if (dump_invisible && nlmsg_type == RTM_GETQDISC) {
            req.u.tc.inv.rta_len  = RTA_LENGTH(0); /* NLA_FLAG has 0-byte payload */
            req.u.tc.inv.rta_type = TCA_DUMP_INVISIBLE;
            req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)) + RTA_SPACE(0);
        } else {
            req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
        }
    } else {
        req.u.ifi.ifi_family = AF_UNSPEC;
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    }

    req.nlh.nlmsg_type  = nlmsg_type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = seq;

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        return -1;
    }
    return 0;
}

static int recv_dump_until_done(struct topo_mgr *tm, int dump_fd, uint32_t expected_seq,
                                bool *seen_devs, bool *seen_qdiscs, bool *seen_classes,
                                bool *intr_out) {
    uint8_t buf[32768];
    for (;;) {
        ssize_t n = recv(dump_fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                *intr_out = true;
                return -1;
            }
            return -1;
        }
        if (n == 0) break;

        int rem = (int)n;
        for (const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
             NLMSG_OK(nlh, rem);
             nlh = NLMSG_NEXT(nlh, rem)) {
            if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
                *intr_out = true;
            if (nlh->nlmsg_seq != expected_seq && nlh->nlmsg_seq != 0)
                continue;
            if (nlh->nlmsg_type == NLMSG_DONE)
                return 0;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nlh);
                if (nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)) && err->error == 0)
                    return 0;
                return -2;
            }
            if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK)
                (void)handle_link_msg(tm, nlh, seen_devs);
            else if (nlh->nlmsg_type == RTM_NEWQDISC || nlh->nlmsg_type == RTM_DELQDISC)
                (void)handle_qdisc_msg(tm, nlh, seen_qdiscs);
            else if (nlh->nlmsg_type == RTM_NEWTCLASS || nlh->nlmsg_type == RTM_DELTCLASS)
                (void)handle_tclass_msg(tm, nlh, seen_classes);
        }
    }
    return 0;
}

static bool dev_has_any_present_qdisc(const struct topo_mgr *tm, uint32_t ifindex) {
    for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
        if (tm->qdiscs[i].present && tm->qdiscs[i].ifindex == ifindex)
            return true;
    }
    return false;
}

static int sync_tc_qdiscs_and_classes(struct topo_mgr *tm, int dfd, bool *intr_io) {
    bool seen_qdiscs[DEV_MAX_TOPO_QDISCS] = {false};
    bool seen_classes[DEV_MAX_TOPO_CLASSES] = {false};

    /* 1. Try RTM_GETQDISC with TCA_DUMP_INVISIBLE first so HTB default pfifo 0:
     *    leaves are captured; fall back to plain RTM_GETQDISC if unsupported. */
    int qrc = -1;
    if (send_rtm_dump_ex(dfd, RTM_GETQDISC, 2, 0, true) == 0) {
        qrc = recv_dump_until_done(tm, dfd, 2, NULL, seen_qdiscs, NULL, intr_io);
    }
    if (qrc < 0) {
        memset(seen_qdiscs, 0, sizeof(seen_qdiscs));
        if (send_rtm_dump_ex(dfd, RTM_GETQDISC, 3, 0, false) < 0 ||
            recv_dump_until_done(tm, dfd, 3, NULL, seen_qdiscs, NULL, intr_io) < 0) {
            return -1;
        }
    }

    for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
        if (tm->qdiscs[i].present && !seen_qdiscs[i])
            tm->qdiscs[i].present = false;
    }

    /* 2. RTM_GETTCLASS requires tcm_ifindex > 0 in Linux tc_dump_tclass */
    uint32_t seq = 100;
    for (uint32_t i = 0; i < tm->num_devs; i++) {
        if (!tm->devs[i].present || tm->devs[i].ifindex == 0)
            continue;
        if (!dev_has_any_present_qdisc(tm, tm->devs[i].ifindex))
            continue;
        seq++;
        if (send_rtm_dump_ex(dfd, RTM_GETTCLASS, seq, (int)tm->devs[i].ifindex, false) == 0) {
            int crc = recv_dump_until_done(tm, dfd, seq, NULL, NULL, seen_classes, intr_io);
            if (crc == -1)
                return -1; /* I/O or ENOBUFS error (ignore -2 NLMSG_ERROR for classless qdiscs) */
        }
    }

    for (uint32_t i = 0; i < tm->num_classes; i++) {
        if (tm->classes[i].present && !seen_classes[i])
            tm->classes[i].present = false;
    }
    return 0;
}

static int topo_sync_tc_only(struct topo_mgr *tm) {
    int dfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (dfd < 0) return -1;
    int rcvbuf = 1024 * 1024;
    (void)setsockopt(dfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    bool intr = false;
    int rc = sync_tc_qdiscs_and_classes(tm, dfd, &intr);
    close(dfd);
    return (rc == 0 && !intr) ? 0 : -1;
}

static int topo_full_sync(struct topo_mgr *tm) {
    for (int attempt = 0; attempt < 3; attempt++) {
        int dfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (dfd < 0) return -1;
        int rcvbuf = 1024 * 1024;
        (void)setsockopt(dfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        bool seen_devs[DEV_MAX_TOPO_DEVICES] = {false};
        bool intr = false;

        if (send_rtm_dump_ex(dfd, RTM_GETLINK, 1, 0, false) < 0 ||
            recv_dump_until_done(tm, dfd, 1, seen_devs, NULL, NULL, &intr) < 0) {
            close(dfd);
            tm->desync_count++;
            continue;
        }
        for (uint32_t i = 0; i < tm->num_devs; i++)
            if (tm->devs[i].present && !seen_devs[i]) tm->devs[i].present = false;

        if (sync_tc_qdiscs_and_classes(tm, dfd, &intr) < 0) {
            close(dfd);
            tm->desync_count++;
            continue;
        }
        close(dfd);

        if (intr) {
            tm->desync_count++;
            continue;
        }
        return 0;
    }
    return -1;
}

int topo_mgr_init(struct topo_mgr *tm, char *err_buf, size_t err_cap) {
    memset(tm, 0, sizeof(*tm));
    tm->nl_fd = -1;
    tm->netns_inum = get_self_netns_inum();

    /* 1. Subscribe to live multicast notifications BEFORE initial dump (§2.5) */
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "rtnetlink socket failed: %s", strerror(errno));
        return -1;
    }
    int rcvbuf = 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK | RTMGRP_TC;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "rtnetlink bind failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    tm->nl_fd = fd;

    /* 2. Dump links + qdiscs + classes */
    if (topo_full_sync(tm) < 0) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "rtnetlink initial topology dump failed");
        topo_mgr_destroy(tm);
        return -1;
    }

    /* 3. Drain any race notifications that arrived during initial sync, then snapshot epoch #1 */
    bool dummy_chg = false, dummy_desync = false;
    (void)topo_mgr_poll(tm, &dummy_chg, &dummy_desync);
    if (tm->num_epochs == 0)
        (void)save_epoch_snapshot(tm);
    return 0;
}

void topo_mgr_destroy(struct topo_mgr *tm) {
    if (!tm) return;
    if (tm->nl_fd >= 0) {
        close(tm->nl_fd);
        tm->nl_fd = -1;
    }
    for (uint32_t i = 0; i < tm->num_epochs; i++) {
        free(tm->epochs[i].devs);
        free(tm->epochs[i].qdiscs);
        free(tm->epochs[i].classes);
    }
    tm->num_epochs = 0;
}

int topo_mgr_poll(struct topo_mgr *tm, bool *changed_out, bool *desync_out) {
    if (changed_out) *changed_out = false;
    if (desync_out) *desync_out = false;
    if (!tm || tm->nl_fd < 0) return -1;

    bool changed = false;
    bool saw_tc_event = false;
    bool need_resync = false;
    uint8_t buf[16384];

    for (;;) {
        ssize_t n = recv(tm->nl_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == ENOBUFS) {
                need_resync = true;
                tm->desync_count++;
                break;
            }
            return -1;
        }
        if (n == 0) break;

        int rem = (int)n;
        for (const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
             NLMSG_OK(nlh, rem);
             nlh = NLMSG_NEXT(nlh, rem)) {
            if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
                need_resync = true;
                tm->desync_count++;
            }
            if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
                if (handle_link_msg(tm, nlh, NULL)) changed = true;
            } else if (nlh->nlmsg_type == RTM_NEWQDISC || nlh->nlmsg_type == RTM_DELQDISC) {
                if (handle_qdisc_msg(tm, nlh, NULL)) changed = true;
                saw_tc_event = true;
            } else if (nlh->nlmsg_type == RTM_NEWTCLASS || nlh->nlmsg_type == RTM_DELTCLASS) {
                if (handle_tclass_msg(tm, nlh, NULL)) changed = true;
                saw_tc_event = true;
            }
        }
    }

    if (need_resync) {
        if (desync_out) *desync_out = true;
        (void)topo_full_sync(tm);
        changed = true;
    } else if (saw_tc_event) {
        /* Refresh invisible HTB default leaf qdiscs & parent class leaf handles */
        (void)topo_sync_tc_only(tm);
        changed = true;
    }

    if (changed && tm->cur_epoch_id > 0) {
        (void)save_epoch_snapshot(tm);
        if (changed_out) *changed_out = true;
    }
    return 0;
}

const struct topo_dev_entry *topo_find_dev_by_name(const struct topo_mgr *tm, const char *ifname) {
    if (!tm || !ifname) return NULL;
    for (uint32_t i = 0; i < tm->num_devs; i++) {
        if (tm->devs[i].present && strcmp(tm->devs[i].name, ifname) == 0)
            return &tm->devs[i];
    }
    return NULL;
}

const struct topo_dev_entry *topo_find_dev_by_ifindex(const struct topo_mgr *tm, uint32_t ifindex) {
    if (!tm || ifindex == 0) return NULL;
    for (uint32_t i = 0; i < tm->num_devs; i++) {
        if (tm->devs[i].present && tm->devs[i].ifindex == ifindex)
            return &tm->devs[i];
    }
    return NULL;
}

uint64_t topo_lookup_queue_gen(const struct topo_mgr *tm, uint32_t ifindex,
                               uint32_t handle, uint32_t parent) {
    if (!tm || ifindex == 0) return 0;

    /* 1. Exact (ifindex, handle, parent) match */
    for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
        if (tm->qdiscs[i].present &&
            tm->qdiscs[i].ifindex == ifindex &&
            tm->qdiscs[i].handle == handle &&
            tm->qdiscs[i].parent == parent) {
            return tm->qdiscs[i].queue_gen;
        }
    }

    /* 2. Unique handle match when handle != 0 */
    if (handle != 0) {
        uint64_t found = 0;
        int matches = 0;
        for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
            if (tm->qdiscs[i].present &&
                tm->qdiscs[i].ifindex == ifindex &&
                tm->qdiscs[i].handle == handle) {
                found = tm->qdiscs[i].queue_gen;
                matches++;
            }
        }
        if (matches == 1) return found;
    }
    return 0;
}

uint64_t topo_ensure_queue_gen(struct topo_mgr *tm, uint32_t ifindex,
                               uint32_t handle, uint32_t parent,
                               const char *fallback_kind) {
    uint64_t qgen = topo_lookup_queue_gen(tm, ifindex, handle, parent);
    if (qgen != 0 || !tm || ifindex == 0 || (handle == 0 && parent == 0))
        return qgen;

    uint32_t slot = tm->num_qdiscs;
    for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
        if (!tm->qdiscs[i].present) {
            slot = i;
            break;
        }
    }
    if (slot >= DEV_MAX_TOPO_QDISCS)
        return ++tm->next_queue_gen;
    if (slot == tm->num_qdiscs)
        tm->num_qdiscs++;

    uint32_t dev_gen = ensure_dev_gen(tm, ifindex);
    tm->qdiscs[slot].ifindex    = ifindex;
    tm->qdiscs[slot].dev_gen    = dev_gen;
    tm->qdiscs[slot].queue_gen  = ++tm->next_queue_gen;
    tm->qdiscs[slot].handle     = handle;
    tm->qdiscs[slot].parent     = parent;
    tm->qdiscs[slot].bytes      = 0;
    tm->qdiscs[slot].packets    = 0;
    tm->qdiscs[slot].drops      = 0;
    tm->qdiscs[slot].overlimits = 0;
    tm->qdiscs[slot].present    = true;
    snprintf(tm->qdiscs[slot].kind, sizeof(tm->qdiscs[slot].kind), "%s",
             fallback_kind ? fallback_kind : "");
    uint64_t new_qgen = tm->qdiscs[slot].queue_gen;
    (void)save_epoch_snapshot(tm);
    return new_qgen;
}

bool topo_dev_has_qdisc_kind(const struct topo_mgr *tm, uint32_t ifindex, const char *kind) {
    if (!tm || !kind) return false;
    for (uint32_t i = 0; i < tm->num_qdiscs; i++) {
        if (!tm->qdiscs[i].present) continue;
        if (ifindex != 0 && tm->qdiscs[i].ifindex != ifindex) continue;
        if (strcmp(tm->qdiscs[i].kind, kind) == 0)
            return true;
    }
    return false;
}
