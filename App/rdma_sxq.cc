/*
 * BUILD COMMAND:
 * gcc -Wall -O0 -g -o RDMA_RC_example RDMA_RC_example.c -libverbs
 *server：
 *./RDMA_RC_example  -d mlx5_0 -i 1 -g 3
 *client：
 *./RDMA_RC_example 192.169.31.53 -d mlx5_0 -i 1 -g 3
 */
/******************************************************************************
 *
 * RDMA Aware Networks Programming Example
 *
 * This code demonstrates how to perform the following operations using
 * the * VPI Verbs API:
 * Send
 * Receive
 * RDMA Read
 * RDMA Write
 *
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/un.h> // For sockaddr_un
#include "byrouter.h"
#include <iostream>
#include <chrono> //用来测试延迟的

/* poll CQ timeout in millisec (2 seconds) */
#define MAX_POLL_CQ_TIMEOUT 2000
#define SRV_MSG "Server's message "
#define RDMAMSGR "RDMA read operation "
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE 64
#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return bswap_64(x);
}
static inline uint64_t ntohll(uint64_t x)
{
    return bswap_64(x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return x;
}
static inline uint64_t ntohll(uint64_t x)
{
    return x;
}
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

/* structure of test parameters */
struct config_t
{
    const char *dev_name; /* IB device name */
    char *server_name;    /* server host name */
    uint32_t tcp_port;    /* server TCP port */
    int ib_port;          /* local IB port to work with */
    int gid_idx;          /* gid index to use */
};

/* structure to exchange data which is needed to connect the QPs */

/* structure of system resources */
struct resources
{
    struct ibv_device_attr device_attr; /* Device attributes */
    struct ibv_port_attr port_attr;     /* IB port attributes */
    struct cm_con_data_t remote_props;  /* values to connect to remote side */
    struct ibv_context *ib_ctx;         /* device handle */

    struct ibv_pd *pd; /* PD handle */
    struct ibv_cq *cq; /* CQ handle */
    struct ibv_qp *qp; /* QP handle */
    struct ibv_mr *mr; /* MR handle for buf */
    char *buf;         /* memory buffer pointer, used for RDMA and send ops */
    int sock;          /* TCP socket file descriptor */

    int ffr_sock;
    uint32_t pd_handle;
    uint32_t cq_handle;
    uint32_t mr_handle;
    uint32_t qp_handle;
};

struct config_t config =
    {
        NULL,  /* dev_name */
        NULL,  /* server_name */
        19875, /* tcp_port */
        1,     /* ib_port */
        //-1     /* gid_idx 源码此处初始值应该是bug,会导致connect_qp（）中的if (config.gid_idx >= 0)无法满足*/
        0 /* gid_idx */
};
/******************************************************************************
Socket operations:
For simplicity, the example program uses TCP sockets to exchange control
information. If a TCP/IP stack/connection is not available, connection manager
(CM) may be used to pass this information. Use of CM is beyond the scope of
this example
******************************************************************************/
/******************************************************************************
 * Function: sock_connect
 * Input:
 * servername: URL of server to connect to (NULL for server mode)
 * port: port of service
 *
 * Output:none
 *
 * Returns: socket (fd) on success, negative error code on failure
 *
 * Description:
 * Connect a socket. If servername is specified a client connection will be
 * initiated to the indicated server and port. Otherwise listen on the
 * indicated port for an incoming connection.
 *
 ******************************************************************************/
static int sock_connect(const char *servername, int port)
{
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;
    int tmp;
    struct addrinfo hints =
        {
            .ai_flags = AI_PASSIVE,
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM};

    if (sprintf(service, "%d", port) < 0)
    {
        goto sock_connect_exit;
    }

    /* Resolve DNS address, use sockfd as temp storage */
    sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);
    if (sockfd < 0)
    {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(sockfd), servername, port);
        goto sock_connect_exit;
    }

    /* Search through results and find the one we want */
    for (iterator = resolved_addr; iterator; iterator = iterator->ai_next)
    {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
        if (sockfd >= 0)
        {
            if (servername)
            {
                /* Client mode. Initiate connection to remote */
                if ((tmp = connect(sockfd, iterator->ai_addr, iterator->ai_addrlen)))
                {
                    fprintf(stdout, "failed connect \n");
                    close(sockfd);
                    sockfd = -1;
                }
            }
            else
            {
                /* Server mode. Set up listening socket an accept a connection */
                listenfd = sockfd;
                sockfd = -1;
                if (bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))
                {
                    goto sock_connect_exit;
                }
                listen(listenfd, 1);
                sockfd = accept(listenfd, NULL, 0);
            }
        }
    }

sock_connect_exit:
    if (listenfd)
    {
        close(listenfd);
    }

    if (resolved_addr)
    {
        freeaddrinfo(resolved_addr);
    }

    if (sockfd < 0)
    {
        if (servername)
        {
            fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        }
        else
        {
            perror("server accept");
            fprintf(stderr, "accept() failed\n");
        }
    }

    return sockfd;
}

/******************************************************************************
 * Function: sock_sync_data
 * Input:
 * sock: socket to transfer data on
 * xfer_size: size of data to transfer
 * local_data: pointer to data to be sent to remote
 *
 * Output: remote_data pointer to buffer to receive remote data
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Description:
 * Sync data across a socket. The indicated local data will be sent to the
 * remote. It will then wait for the remote to send its data back. It is
 * assumed that the two sides are in sync and call this function in the proper
 * order. Chaos will ensue if they are not. :)
 *
 * Also note this is a blocking function and will wait for the full data to be
 * received from the remote.
 *
 ******************************************************************************/
int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;
    rc = write(sock, local_data, xfer_size);

    if (rc < xfer_size)
    {
        fprintf(stderr, "Failed writing data during sock_sync_data\n");
    }
    else
    {
        rc = 0;
    }

    while (!rc && total_read_bytes < xfer_size)
    {
        read_bytes = read(sock, remote_data, xfer_size);
        if (read_bytes > 0)
        {
            total_read_bytes += read_bytes;
        }
        else
        {
            rc = read_bytes;
        }
    }
    return rc;
}
/******************************************************************************
End of socket operations
******************************************************************************/

/******************************************************************************
 * Function: resources_init
 *
 * Input:
 * res: pointer to resources structure
 *
 * Output: res is initialized
 *
 * Returns: none
 *
 * Description: res is initialized to default values
 ******************************************************************************/
static void resources_init(struct resources *res)
{
    memset(res, 0, sizeof *res);
    res->sock = -1;
}

/******************************************************************************
 * Function: print_config
 *
 * Input: none
 *
 * Output: none
 *
 * Returns: none
 *
 * Description: Print out config information
 ******************************************************************************/
static void print_config(void)
{
    fprintf(stdout, " ------------------------------------------------\n");
    fprintf(stdout, " Device name : \"%s\"\n", config.dev_name);
    fprintf(stdout, " IB port : %u\n", config.ib_port);
    if (config.server_name)
    {
        fprintf(stdout, " IP : %s\n", config.server_name);
    }
    fprintf(stdout, " TCP port : %u\n", config.tcp_port);
    if (config.gid_idx >= 0)
    {
        fprintf(stdout, " GID index : %u\n", config.gid_idx);
    }
    fprintf(stdout, " ------------------------------------------------\n\n");
}

/******************************************************************************
 * Function: usage
 *
 * Input:
 * argv0: command line arguments
 *
 * Output: none
 *
 * Returns: none
 *
 * Description: print a description of command line syntax
 ******************************************************************************/
static void usage(const char *argv0)
{
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, " %s start a server and wait for connection\n", argv0);
    fprintf(stdout, " %s <host> connect to server at <host>\n", argv0);
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, " -p, --port <port> listen on/connect to port <port> (default 18515)\n");
    fprintf(stdout, " -d, --ib-dev <dev> use IB device <dev> (default first device found)\n");
    fprintf(stdout, " -i, --ib-port <port> use port <port> of IB device (default 1)\n");
    fprintf(stdout, " -g, --gid_idx <git index> gid index to be used in GRH (default not used)\n");
}

/******************************************************************************
 * Function: main
 *
 * Input:
 * argc: number of items in argv
 * argv: command line parameters
 *
 * Output: none
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description: Main program code
 ******************************************************************************/
int main(int argc, char *argv[])
{
    struct resources res;
    int rc = 1;
    int async_fd = -1;
    int num_comp_vectors = 0;
    char temp_char;
    char *shm_ptr = NULL;

    /* parse the command line parameters */
    while (1)
    {
        int c;
        /* Designated Initializer */
        static struct option long_options[] =
            {
                {.name = "port", .has_arg = 1, .val = 'p'},
                {.name = "ib-dev", .has_arg = 1, .val = 'd'},
                {.name = "ib-port", .has_arg = 1, .val = 'i'},
                {.name = "gid-idx", .has_arg = 1, .val = 'g'},
                {.name = NULL, .has_arg = 0, .val = '\0'}};

        c = getopt_long(argc, argv, "p:d:i:g:", long_options, NULL);
        if (c == -1)
        {
            break;
        }
        switch (c)
        {
        case 'p':
            config.tcp_port = strtoul(optarg, NULL, 0);
            break;
        case 'd':
            config.dev_name = strdup(optarg);
            break;
        case 'i':
            config.ib_port = strtoul(optarg, NULL, 0);
            if (config.ib_port < 0)
            {
                usage(argv[0]);
                return 1;
            }
            break;
        case 'g':
            config.gid_idx = strtoul(optarg, NULL, 0);
            if (config.gid_idx < 0)
            {
                usage(argv[0]);
                return 1;
            }
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* parse the last parameter (if exists) as the server name */
    /*
     * server_name is null means this node is a server,
     * otherwise this node is a client which need to connect to
     * the specific server
     */
    if (optind == argc - 1)
    {
        config.server_name = argv[optind];
    }
    else if (optind < argc)
    {
        usage(argv[0]);
        return 1;
    }

    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    print_config();
    initLogFile();
    resources_init(&res);
    LOG_DEBUG("prepare to connect to FFR");
    res.ffr_sock = ffr_sock_init();
    if (res.ffr_sock < 0)
    {
        LOG_ERROR("failed to connect to ffr");
        return -1;
    }
    LOG_DEBUG("connected to FFR");
    LOG_DEBUG("prepare to connect to RDMA Server...");
    res.sock = sock_connect(config.server_name, config.tcp_port);
    LOG_DEBUG("connected to RDMA Server");
    auto start = std::chrono::high_resolution_clock::now();

    // ===================== ibv_open_device =====================
    if (custom_ibv_open_device(&res.ffr_sock, &async_fd, &num_comp_vectors))
    {
        fprintf(stderr, "failed to open device context\n");
        return -1;
    }
    auto end_ibv_open_device = std::chrono::high_resolution_clock::now();
    auto duration_ibv_open_device = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_open_device - start).count();
    LOG_DEBUG("Open device cost:" << duration_ibv_open_device << "ns");
    // ===================== ibv_query_port =====================
    auto start_ibv_query_port = std::chrono::high_resolution_clock::now();
    if (custom_ibv_query_port(&res.ffr_sock, 1, &res.port_attr))
    {
        fprintf(stderr, "failed to query port attributes\n");
        return -1;
    }
    auto end_ibv_query_port = std::chrono::high_resolution_clock::now();
    auto duration_ibv_query_port = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_query_port - start_ibv_query_port).count();
    LOG_DEBUG("Query port cost:" << duration_ibv_query_port << "ns");
    // ===================== ibv_alloc_pd =====================
    auto start_ibv_alloc_pd = std::chrono::high_resolution_clock::now();
    if (custom_ibv_alloc_pd(&res.ffr_sock, &res.pd_handle))
    {
        fprintf(stderr, "failed to allocate protection domain\n");
        return -1;
    }
    auto end_ibv_alloc_pd = std::chrono::high_resolution_clock::now();
    auto duration_ibv_alloc_pd = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_alloc_pd - start_ibv_alloc_pd).count();
    LOG_DEBUG("Allocate pd cost:" << duration_ibv_alloc_pd << "ns");

    //  ===================== ibv_create_cq =====================
    auto start_ibv_create_cq = std::chrono::high_resolution_clock::now();
    if (custom_ibv_create_cq(&res.ffr_sock, 1, &res.cq_handle, -1, 0))
    {
        fprintf(stderr, "failed to create completion queue\n");
        return -1;
    }
    auto end_ibv_create_cq = std::chrono::high_resolution_clock::now();
    auto duration_ibv_create_cq = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_create_cq - start_ibv_create_cq).count();
    LOG_DEBUG("Create cq cost:" << duration_ibv_create_cq << "ns");
    int mr_flags = 0;
    mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    int rkey = 0;
    int lkey = 0;
    // ===================== ibv_reg_mr =====================
    auto start_ibv_reg_mr = std::chrono::high_resolution_clock::now();
    if (custom_ibv_reg_mr(&res.ffr_sock, 64, res.pd_handle, mr_flags, &res.mr_handle, &rkey, &lkey, (void **)&shm_ptr))
    {
        fprintf(stderr, "failed to register memory region\n");
        return -1;
    }
    auto end_ibv_reg_mr = std::chrono::high_resolution_clock::now();
    auto duration_ibv_reg_mr = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_reg_mr - start_ibv_reg_mr).count();
    LOG_DEBUG("Reg mr cost:" << duration_ibv_reg_mr << "ns");
    // buffer_addr = (char *)res.buf;
    int sq_sig_all = 1;
    ibv_qp_type qp_type = IBV_QPT_RC;
    int send_cq_handle = res.cq_handle;
    int recv_cq_handle = res.cq_handle;
    struct ibv_qp_cap cap;
    cap.max_send_wr = 1;
    cap.max_recv_wr = 1;
    cap.max_send_sge = 1;
    cap.max_recv_sge = 1;
    int qp_num = 0;
    // ===================== ibv_create_qp =====================
    auto start_ibv_create_qp = std::chrono::high_resolution_clock::now();
    rc = custom_ibv_create_qp(&res.ffr_sock, res.pd_handle, qp_type, send_cq_handle, recv_cq_handle, &cap, sq_sig_all, &res.qp_handle, &qp_num);
    if (rc)
    {
        fprintf(stderr, "failed to create queue pair\n");
        return -1;
    }
    auto end_ibv_create_qp = std::chrono::high_resolution_clock::now();
    auto duration_ibv_create_qp = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_create_qp - start_ibv_create_qp).count();
    LOG_DEBUG("Create qp cost:" << duration_ibv_create_qp << "ns");
    union ibv_gid gid;
    // ===================== ibv_query_gid =====================
    rc = custom_ibv_query_gid(&res.ffr_sock, 1, 3, &gid);
    if (rc)
    {
        fprintf(stderr, "failed to query gid\n");
        return -1;
    }

    fprintf(stdout, "Local address = 0x%" PRIx64 "\n", (uintptr_t)shm_ptr);
    local_con_data.addr = htonll((uint64_t)(uintptr_t)shm_ptr);
    local_con_data.rkey = htonl(rkey);
    local_con_data.qp_num = htonl(qp_num);
    local_con_data.lid = htons(res.port_attr.lid);
    memcpy(local_con_data.gid, &gid, 16);

    // ===================== sock_sync_data =====================
    if (sock_sync_data(res.sock, sizeof(struct cm_con_data_t), (char *)&local_con_data, (char *)&tmp_con_data) < 0)
    {
        fprintf(stderr, "failed to exchange connection data between sides\n");
        rc = 1;
    }
    fprintf(stdout, "resv from rdma server remote info\n");

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    fprintf(stdout, "Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
    fprintf(stdout, "Remote rkey = 0x%x\n", remote_con_data.rkey);
    fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
    fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
    uint8_t *p = remote_con_data.gid;
    fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

    fprintf(stdout, "prepare to request ffr to write remote data\n");
    fprintf(stdout, "Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);

    LOG_DEBUG("Prepare to modify qp to INIT");
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    int attr_mask;
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = 1;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    attr_mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    int mqp_res = 0;
    auto start_ibv_modify_qp_1 = std::chrono::high_resolution_clock::now();
    // ===================== ibv_modify_qp =====================
    if (custom_ibv_modify_qp(&res.ffr_sock, res.qp_handle, &attr, attr_mask, &mqp_res))
    {
        fprintf(stderr, "failed to modify qp\n");
        return 1;
    }
    auto end_ibv_modify_qp_1 = std::chrono::high_resolution_clock::now();
    auto duration_ibv_modify_qp_1 = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_modify_qp_1 - start_ibv_modify_qp_1).count();
    LOG_DEBUG("Modify qp to INIT cost:" << duration_ibv_modify_qp_1 << "ns");
    LOG_DEBUG("Modify qp to INIT success.");

    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;

    memset(&sge, 0, sizeof(sge));
    sge.addr = (uint64_t)(uintptr_t)shm_ptr;
    sge.length = MSG_SIZE;
    sge.lkey = lkey;
    LOG_DEBUG("lkey:" << lkey);

    /* prepare the receive work request */
    memset(&rr, 0, sizeof(rr));
    rr.next = NULL;
    rr.wr_id = 0;
    rr.sg_list = &sge;
    rr.num_sge = 1;
    memset(&bad_wr, 0, sizeof(bad_wr));
    auto start_ibv_post_recv = std::chrono::high_resolution_clock::now();
    // ===================== ibv_post_recv =====================
    if (custom_ibv_post_recv(&res.ffr_sock, res.qp_handle, &rr, &bad_wr))
    {
        fprintf(stderr, "failed to post SR\n");
        return 1;
    }
    auto end_ibv_post_recv = std::chrono::high_resolution_clock::now();
    auto duration_ibv_post_recv = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_post_recv - start_ibv_post_recv).count();
    LOG_DEBUG("Post recv cost:" << duration_ibv_post_recv << "ns");
    LOG_DEBUG("Prepare to modify qp to RTR");
    int flags;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_con_data.qp_num;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = remote_con_data.lid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1;
    if (config.gid_idx >= 0)
    {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, remote_con_data.gid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = 3;
        attr.ah_attr.grh.traffic_class = 0;
    }

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    auto start_ibv_modify_qp_2 = std::chrono::high_resolution_clock::now();
    // ===================== ibv_modify_qp =====================
    if (custom_ibv_modify_qp(&res.ffr_sock, res.qp_handle, &attr, flags, &rc))
    {
        fprintf(stderr, "failed to modify qp\n");
        return 1;
    }
    auto end_ibv_modify_qp_2 = std::chrono::high_resolution_clock::now();
    auto duration_ibv_modify_qp_2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_modify_qp_2 - start_ibv_modify_qp_2).count();
    LOG_DEBUG("Modify qp to RTR cost:" << duration_ibv_modify_qp_2 << "ns");
    LOG_DEBUG("Modify qp to RTR success.");
    LOG_DEBUG("Prepare to modify qp to RTS");
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    auto start_ibv_modify_qp_3 = std::chrono::high_resolution_clock::now();
    // ===================== ibv_modify_qp =====================
    if (custom_ibv_modify_qp(&res.ffr_sock, res.qp_handle, &attr, flags, &rc))
    {
        fprintf(stderr, "failed to modify qp\n");
        return 1;
    }
    auto end_ibv_modify_qp_3 = std::chrono::high_resolution_clock::now();
    auto duration_ibv_modify_qp_3 = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_modify_qp_3 - start_ibv_modify_qp_3).count();
    LOG_DEBUG("Modify qp to RTS cost:" << duration_ibv_modify_qp_3 << "ns");
    LOG_DEBUG("Modify qp to RTS success.");

    // ===================== sock_sync_data =====================
    if (sock_sync_data(res.sock, 1, "Q", &temp_char)) /* just send a dummy char back and forth */
    {
        fprintf(stderr, "sync error after QPs are were moved to RTS\n");
        rc = 1;
    }
    LOG_DEBUG("prepare to request ffr to poll completion");
    struct ibv_wc wc;
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    int poll_result;
    /* poll the completion for a while before giving up of doing it .. */
    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    // ===================== ibv_poll_cq =====================
    do
    {
        auto start_ibv_poll_cq_1 = std::chrono::high_resolution_clock::now();
        poll_result = custom_ibv_poll_cq(&res.ffr_sock, res.cq_handle, 1, &wc);
        auto end_ibv_poll_cq_1 = std::chrono::high_resolution_clock::now();
        auto duration_ibv_poll_cq_1 = std::chrono::duration_cast<std::chrono::nanoseconds>(end_ibv_poll_cq_1 - start_ibv_poll_cq_1).count();
        LOG_DEBUG("Poll completion cost:" << duration_ibv_poll_cq_1 << "ns");
        LOG_DEBUG("Poll completion poll_result:" << poll_result << "ns");
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
    LOG_DEBUG("Poll completion success.");
    // ===================== sock_sync_data =====================
    if (sock_sync_data(res.sock, 1, "R", &temp_char)) /* just send a dummy char back and forth */
    {
        fprintf(stderr, "sync error before RDMA ops\n");
        rc = 1;
    }
    LOG_DEBUG("prepare for to  IBV_WR_RDMA_READ");

    struct ibv_send_wr sr;
    struct ibv_sge send_sge;
    struct ibv_send_wr *bad_sr = NULL;
    memset(&send_sge, 0, sizeof(send_sge));
    send_sge.addr = (uint64_t)(uintptr_t)shm_ptr;
    send_sge.length = MSG_SIZE;
    send_sge.lkey = lkey;

    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &send_sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_RDMA_READ;
    sr.send_flags = IBV_SEND_SIGNALED;
    sr.wr.rdma.remote_addr = remote_con_data.addr;
    sr.wr.rdma.rkey = remote_con_data.rkey;
    LOG_DEBUG("sr.wr.rdma.rkey:" << sr.wr.rdma.rkey);
    // ===================== ibv_post_send =====================
    if (custom_ibv_post_send(&res.ffr_sock, res.qp_handle, &sr, &bad_sr))
    {
        fprintf(stderr, "failed to post SR\n");
        return 1;
    }
    LOG_DEBUG("Success for to  IBV_WR_RDMA_READ");

    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    // ===================== ibv_poll_cq =====================
    do
    {
        poll_result = custom_ibv_poll_cq(&res.ffr_sock, res.cq_handle, 1, &wc);
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
    LOG_DEBUG("Poll completion success.");
    LOG_DEBUG("read remote memory" << shm_ptr);

    LOG_DEBUG("prepare for to  IBV_WR_RDMA_WRITE");
    strncpy(shm_ptr, "use shared memory 4", MSG_SIZE);
    // msync(shm_ptr, MSG_SIZE, MS_SYNC);
    // memmove(buffer_addr, (void *)"use shared memory", MSG_SIZE);
    // asm volatile("sfence" ::: "memory");
    memset(&send_sge, 0, sizeof(send_sge));
    send_sge.addr = (uint64_t)(uintptr_t)shm_ptr;
    send_sge.length = MSG_SIZE;
    send_sge.lkey = lkey;

    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &send_sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_RDMA_WRITE;
    sr.send_flags = IBV_SEND_SIGNALED;
    sr.wr.rdma.remote_addr = remote_con_data.addr;
    sr.wr.rdma.rkey = remote_con_data.rkey;
    // ===================== ibv_post_send =====================
    if (custom_ibv_post_send(&res.ffr_sock, res.qp_handle, &sr, &bad_sr))
    {
        fprintf(stderr, "failed to post SR\n");
        return 1;
    }
    LOG_DEBUG("Success for to  IBV_WR_RDMA_WRITE");

    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    // ===================== ibv_poll_cq =====================
    do
    {
        poll_result = custom_ibv_poll_cq(&res.ffr_sock, res.cq_handle, 1, &wc);
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

    /* Sync so server will know that client is done mucking with its memory */
    // ===================== sock_sync_data =====================
    if (sock_sync_data(res.sock, 1, "W", &temp_char)) /* just send a dummy char back and forth */
    {
        fprintf(stderr, "sync error after RDMA ops\n");
        rc = 1;
    }

    auto end = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    LOG_DEBUG("All step duration: " << duration << "ns");
    int ret = 0;
    custom_ibv_destroy_qp(&res.ffr_sock, 1, &ret);
    custom_ibv_destory_cq(&res.ffr_sock, 1, &ret);
    custom_ibv_dereg_mr(&res.ffr_sock, 1, &ret);
    custom_ibv_dealloc_pd(&res.ffr_sock, 1, &ret);
    custom_ibv_c
    closeLogFile();
}