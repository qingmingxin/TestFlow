
#ifndef SXQ_RDMA_H
#define SXQ_RDMA_H

#include <ifaddrs.h>
#include <cstdint>
#include "rdma_api.h"
#include <unistd.h>
#include <inttypes.h>
struct cm_con_data_t
{
    uint64_t addr;   /* Buffer address */
    uint32_t rkey;   /* Remote key */
    uint32_t qp_num; /* QP number */
    uint16_t lid;    /* LID of the IB port */
    uint8_t gid[16]; /* gid */
} __attribute__((packed));
#define SRV_MSG "Server's message "
#define RDMAMSGR "RDMA read operation "
#define RDMAMSGW "RDMA write operation sxq"

struct SXQ_IBV_OPEN_DEVICE_RSP
{
    uint32_t async_fd;
    uint32_t num_comp_vectors;
};

struct SXQ_IBV_QUERY_PORT_REQ
{
    int port_num;
};

struct SXQ_IBV_QUERY_PORT_RSP
{
    struct ibv_port_attr port_attr;
};

struct SXQ_IBV_ALLOC_PD_RSP
{
    uint32_t pd_handle;
};
struct SXQ_IBV_REG_MR_REQ
{
    uint32_t pd_handle;
    uint32_t size;
    uint32_t access;
    char shm_name[100];
};
struct SXQ_IBV_REG_MR_RSP
{
    uint32_t mr_handle;
    uint32_t rkey;
    uint32_t lkey;
    char shm_name[100];
};
struct SXQ_IBV_CREATE_CQ_REQ
{
    uint32_t cqe_num;
};
struct SXQ_IBV_CREATE_CQ_RSP
{
    uint32_t cq_handle;
};
struct SXQ_IBV_CREATE_QP_REQ
{
    uint32_t pd_handle;
    enum ibv_qp_type qp_type;
    int sq_sig_all;
    uint32_t send_cq_handle;
    uint32_t recv_cq_handle;
    uint32_t srq_handle;
    struct ibv_qp_cap cap;
};
struct SXQ_IBV_CREATE_QP_RSP
{
    uint32_t qp_handle;
    uint32_t qp_num;
};

struct SXQ_IBV_QUERY_GID_REQ
{
    int port_num;
    int gid_index;
};

struct SXQ_IBV_QUERY_GID_RSP
{
    union ibv_gid gid;
};

struct SXQ_IBV_QUERY_QP_REQ
{
    uint32_t qp_handle;
};

struct SXQ_IBV_QUERY_QP_RSP
{
    uint32_t qp_attr_mask;
    struct ibv_qp_attr qp_attr;
    struct ibv_qp_init_attr qp_init_attr;
};

struct SXQ_IBV_MODIFY_QP_REQ
{
    uint32_t handle;
    struct ibv_qp_attr attr;
    int attr_mask;
};

struct SXQ_IBV_MODIFY_QP_RSP
{
    int ret;
};

struct SXQ_IBV_POST_RECV_REQ
{
    uint32_t wr_size;
    char *wr;
};

struct SXQ_IBV_POST_RECV_BODY
{
    uint32_t qp_handle;
    uint32_t wr_count;
    uint32_t sge_count;
    char wr[];
};

struct SXQ_IBV_POST_RECV_RSP
{
    int ret_errno;
    uint32_t bad_wr;
};

struct SXQ_IBV_POST_SEND_REQ
{
    uint32_t wr_size;
    char *wr;
};
struct SXQ_IBV_POST_SEND_BODY
{
    uint32_t qp_handle;
    uint32_t sr_count;
    uint32_t sge_count;
    char wr[];
};
struct SXQ_IBV_POST_SEND_RSP
{
    int ret_errno;
    uint32_t bad_wr;
};

struct SXQ_IBV_POLL_CQ_REQ
{
    uint32_t cq_handle;
    uint32_t num_entries;
};

struct SXQ_IBV_POLL_CQ_RSP
{
    int ret_errno; // which is also the count of following wc.
    struct ibv_wc wc;
};

static int modify_qp_to_init(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = 1;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to INIT\n");
    }
    return rc;
}
static int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1;
    if (3 >= 0)
    {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = 3;
        attr.ah_attr.grh.traffic_class = 0;
    }

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
    }
    return rc;
}
static int modify_qp_to_rts(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTS\n");
    }
    return rc;
}

#define MAX_POLL_CQ_TIMEOUT 2000
static int sxq_poll_completion(struct ib_data *ibv_data)
{
    struct ibv_wc wc;
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    int poll_result;
    int rc = 0;
    /* poll the completion for a while before giving up of doing it .. */
    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    do
    {
        poll_result = ibv_poll_cq(ibv_data->ib_cq, 1, &wc);
        gettimeofday(&cur_time, NULL);
        cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    } while ((poll_result == 0) && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));

    if (poll_result < 0)
    {
        /* poll CQ failed */
        fprintf(stderr, "poll CQ failed\n");
        rc = 1;
    }
    else if (poll_result == 0)
    {
        /* the CQ is empty */
        fprintf(stderr, "completion wasn't found in the CQ after timeout\n");
        rc = 1;
    }
    else
    {
        /* CQE found */
        fprintf(stdout, "completion was found in CQ with status 0x%x\n", wc.status);
        /* check the completion status (here we don't care about the completion opcode */
        if (wc.status != IBV_WC_SUCCESS)
        {
            fprintf(stderr, "got bad completion with status: 0x%x, vendor syndrome: 0x%x\n",
                    wc.status, wc.vendor_err);
            rc = 1;
        }
    }
    return rc;
}
static int post_send(struct ib_data *res, enum ibv_wr_opcode opcode, struct cm_con_data_t *remote)
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;
    int rc;

    /* prepare the scatter/gather entry */
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res->ib_buffer;
    sge.length = 64;
    sge.lkey = res->ib_mr->lkey;

    /* prepare the send work request */
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = opcode;
    sr.send_flags = IBV_SEND_SIGNALED;
    if (opcode != IBV_WR_SEND)
    {
        sr.wr.rdma.remote_addr = remote->addr;
        sr.wr.rdma.rkey = remote->rkey;
    }

    /* there is a Receive Request in the responder side, so we won't get any into RNR flow */
    rc = ibv_post_send(res->ib_qp, &sr, &bad_wr);
    if (rc)
    {
        fprintf(stderr, "failed to post SR\n");
    }
    else
    {
        switch (opcode)
        {
        case IBV_WR_SEND:
            fprintf(stdout, "Send Request was posted\n");
            break;
        case IBV_WR_RDMA_READ:
            fprintf(stdout, "RDMA Read Request was posted\n");
            break;
        case IBV_WR_RDMA_WRITE:
            fprintf(stdout, "RDMA Write Request was posted\n");
            break;
        default:
            fprintf(stdout, "Unknown Request was posted\n");
            break;
        }
    }
    return rc;
}

/******************************************************************************
 * Function: ibv_query_port_custom
 *
 * Input:
 * ibv_data: pointer to ib_data from ffr
 * port_num: port num
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description:
 * Query port num.
 ******************************************************************************/
int ibv_query_port_custom(struct ib_data *ibv_data, int port_num)
{
    if (ibv_query_port(ibv_data->ib_context, port_num, &ibv_data->ib_port_attr))
    {
        return 1;
    }
    return 0;
}

/******************************************************************************
 * Function: ibv_alloc_pd_custom
 *
 * Input:
 * ibv_data : pointer to ib_data from ffr
 * pd       : pointer to an ibv_pd structure where the allocated protection domain
 *            will be stored. It must be allocated by the caller before invoking
 *            this function.
 * Returns: 0 on success, 1 on failure
 *
 * Description:
 * Alloc pd on FFR.
 ******************************************************************************/
int ibv_alloc_pd_custom(struct ib_data *ibv_data, struct ibv_pd *pd)
{
    pd = ibv_alloc_pd(ibv_data->ib_context);
    if (!pd)
        return 1;
    return 0;
}

/******************************************************************************
 * Function: ibv_create_cq_custom
 *
 * Input:
 * ibv_data : pointer to ib_data from ffr
 * cq       : pointer to an ibv_cq structure where the allocated complete queue
 * channel  : pointer to an ibv_comp_channel structure where the completion channel
 * cqe      : number of CQEs
 * comp_vector : completion vector
 *
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description:
 * Create complete queue on FFR.
 ******************************************************************************/
int ibv_create_cq_custom(struct ib_data *ibv_data, struct ibv_cq *cq, ibv_comp_channel *channel, int cqe, int comp_vector)
{
    cq = ibv_create_cq(ibv_data->ib_context, cqe, NULL, channel, comp_vector);
    if (!cq)
    {
        return 1;
    }
    return 0;
}

/******************************************************************************
 * Function: ibv_reg_mr_custom
 *
 * Input:
 * pd       : pointer to an ibv_pd structure
 * mr       : pointer to an ibv_mr structure where the registered memory region
 * addr     : pointer to the memory region to be registered
 * length   : length of the memory region to be registered
 * mr_flags : flags to be used for registration
 *
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description:
 * Register memory region on FFR.
 ******************************************************************************/
int ibv_reg_mr_custom(struct ibv_pd *pd, struct ibv_mr *mr, void *addr, size_t length, int mr_flags)
{
    mr = ibv_reg_mr(pd, addr, length, mr_flags);
    if (!mr)
    {
        return 1;
    }
    return 0;
}
/******************************************************************************
 * Function: ibv_create_qp_custom
 *
 * Input:
 * pd       : pointer to an ibv_pd structure
 * qp       : pointer to an ibv_qp structure where the allocated queue pair
 * qp_init_attr : pointer to an ibv_qp_init_attr structure that contains the
 *
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description:
 * Create queue pair on FFR.
 ******************************************************************************/
int ibv_create_qp_custom(struct ibv_pd *pd, struct ibv_qp *qp, struct ibv_qp_init_attr *qp_init_attr)
{
    qp = ibv_create_qp(pd, qp_init_attr);
    if (!qp)
    {
        return 1;
    }
    return 0;
}

void rdma_with_client1(struct ib_data *ibv_data)
{
    fprintf(stdout, "start rdma_with_client1\n");
    int num_devices;
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;
    size_t size;
    char *dev_name;
    int i;
    int mr_flags = 0;
    int cq_size = 0;
    int rc = 0;
    ibv_data->ib_context = NULL;
    dev_list = ibv_get_device_list(&num_devices);
    fprintf(stdout, "found %d device(s)\n", num_devices);

    /* search for the specific device we want to work with */
    for (i = 0; i < num_devices; i++)
    {
        dev_name = strdup(ibv_get_device_name(dev_list[i]));
        fprintf(stdout, "device not specified, using first one found: %s\n", dev_name);
        /* find the specific device */
        if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name))
        {
            ib_dev = dev_list[i];
            break;
        }
    }

    /* get device handle */
    ibv_data->ib_context = ibv_open_device(ib_dev);

    /* We are now done with device list, free it */
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;

    /* query port properties */
    if (ibv_query_port(ibv_data->ib_context, 1, &ibv_data->ib_port_attr))
    {
        fprintf(stderr, "ibv_query_port on port %u failed\n", 1);
        rc = 1;
    }
    fprintf(stdout, "start ibv_alloc_pd\n");
    ibv_data->ib_pd = ibv_alloc_pd(ibv_data->ib_context);
    cq_size = 1;
    fprintf(stdout, "start ibv_create_cq\n");
    ibv_data->ib_cq = ibv_create_cq(ibv_data->ib_context, cq_size, NULL, NULL, 0);
    size = 64;
    ibv_data->ib_buffer = (char *)malloc(size);
    memset(ibv_data->ib_buffer, 0, size);
    mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    fprintf(stdout, "start ibv_reg_mr\n");
    ibv_data->ib_mr = ibv_reg_mr(ibv_data->ib_pd, ibv_data->ib_buffer, size, mr_flags);
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = ibv_data->ib_cq;
    qp_init_attr.recv_cq = ibv_data->ib_cq;
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = 1;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    fprintf(stdout, "start ibv_create_qp\n");
    ibv_data->ib_qp = ibv_create_qp(ibv_data->ib_pd, &qp_init_attr);
}
int rdma_with_client2(struct ib_data *ibv_data, struct cm_con_data_t *remote_con_data)
{
    fprintf(stdout, "start rdma_with_client2\n");
    fprintf(stdout, "start modify_qp_to_init\n");
    if (ibv_data->ib_qp == NULL)
    {
        fprintf(stdout, "ibv_data->ib_qp is null\n");
    }
    struct ibv_qp_attr qp_attr;
    struct ibv_qp_init_attr qp_init_attr;
    int qp_attr_mask = 0;
    if (ibv_query_qp(ibv_data->ib_qp, &qp_attr, qp_attr_mask, &qp_init_attr) == 0)
    {
        printf("QP State: %d\n", qp_attr.qp_state);
    }
    else
    {
        fprintf(stderr, "Failed to query QP\n");
    }
    modify_qp_to_init(ibv_data->ib_qp);

    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;
    int rc;

    /* prepare the scatter/gather entry */
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)ibv_data->ib_buffer;
    sge.length = MSG_SIZE;
    sge.lkey = ibv_data->ib_mr->lkey;

    /* prepare the receive work request */
    memset(&rr, 0, sizeof(rr));
    rr.next = NULL;
    rr.wr_id = 0;
    rr.sg_list = &sge;
    rr.num_sge = 1;

    /* post the Receive Request to the RQ */
    fprintf(stdout, "start ibv_post_recv\n");

    rc = ibv_post_recv(ibv_data->ib_qp, &rr, &bad_wr);

    fprintf(stdout, "start modify_qp_to_rtr\n");

    rc = modify_qp_to_rtr(ibv_data->ib_qp, remote_con_data->qp_num, remote_con_data->lid, remote_con_data->gid);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        return 1;
    }

    /* modify the QP to RTS */
    fprintf(stdout, "start modify_qp_to_rts\n");
    rc = modify_qp_to_rts(ibv_data->ib_qp);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTS\n");
        return 1;
    }
    return 0;
}

int rdma_with_client3(struct ib_data *ibv_data)
{
    if (sxq_poll_completion(ibv_data))
    {
        fprintf(stderr, "poll completion failed\n");
        return 1;
    }
    return 0;
}
int rdma_with_client4(struct ib_data *ibv_data, struct cm_con_data_t *remote)
{
    if (post_send(ibv_data, IBV_WR_RDMA_READ, remote))
    {
        fprintf(stderr, "failed to post SR 2\n");
        return 1;
    }
    if (sxq_poll_completion(ibv_data))
    {
        fprintf(stderr, "poll completion failed 2\n");
        return 1;
    }
    fprintf(stdout, "read buffer from server: '%s'\n", ibv_data->ib_buffer);
    strcpy(ibv_data->ib_buffer, RDMAMSGW);
    fprintf(stdout, "Now replacing it with: '%s'\n", ibv_data->ib_buffer);
    if (post_send(ibv_data, IBV_WR_RDMA_WRITE, remote))
    {
        fprintf(stderr, "failed to post SR 3\n");
        return 1;
    }
    if (sxq_poll_completion(ibv_data))
    {
        fprintf(stderr, "poll completion failed 3\n");
        return 1;
    }
    return 0;
}
#endif /* FFROUTER_H */