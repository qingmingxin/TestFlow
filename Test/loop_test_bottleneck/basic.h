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
#include <iostream>
#include <thread>
#include "log.h"
#include <chrono> //用来测试延迟的

#define LOOPTIME 10
// #define LOOPTIME 100
// #define LOOPTIME 1000

#define LOOPSEND 0
constexpr int tcp_ports[] = {25283, 19750, 36919, 4859, 42339, 43619, 31746, 33255, 44100, 21642, 38877, 57937, 46331, 4402, 40960, 10639, 2423, 30215, 22222, 12918, 58919, 26029, 48329, 62354, 20480, 19135, 49659, 57887, 57132, 26955, 20162, 50560, 54771, 41165, 3467, 49427, 33662, 21430, 32192, 47468, 24993, 15362, 64088, 23435, 28467, 18854, 59618, 1882, 20588, 25666, 5867, 22339, 54808, 56194, 55532, 1947, 24809, 20468, 15001, 5426, 44417, 12081, 8480, 40290, 3610, 38113, 64269, 4833, 58575, 43847, 32715, 65115, 21240, 41572, 39162, 35528, 62776, 25536, 52830, 47263, 11039, 11607, 46938, 4776, 46093, 58815, 32905, 19325, 39971, 3126, 33150, 44343, 18439, 51509, 41248, 1207, 3371, 57110, 40488, 63446, 5543, 17977, 45408, 35184, 24208, 25445, 26802, 32190, 14204, 15424, 36590, 36918, 16911, 48642, 19496, 22689, 21577, 12062, 19116, 6813, 59687, 18782, 4730, 45267, 32193, 47890, 25018, 57879, 27324, 18102, 57797, 14703, 27886, 25896, 9067, 12956, 63074, 19250, 11426, 30759, 21864, 57379, 15678, 28290, 2936, 12402, 20145, 27905, 15570, 12250, 56629, 25540, 16139, 3591, 4885, 24060, 9394, 26673, 15588, 46457, 40714, 38809, 52850, 36332, 5153, 59137, 18899, 61253, 43815, 40152, 32100, 2115, 63881, 28725, 38037, 52494, 13954, 1902, 8793, 2940, 12632, 40695, 2153, 35793, 48230, 26718, 16805, 63965, 27490, 64091, 23437, 47761, 44297, 2163, 33248, 24167, 51328, 13066, 14819, 11863, 63886, 20555, 41338, 8897, 52318, 60240, 32555, 44040, 5799, 12955, 48194, 41015, 48698, 3569, 37497, 56849, 27409, 2700, 56375, 52764, 11558, 25281, 33143, 37073, 15993, 59099, 27614, 51762, 59602, 64486, 63125, 48507, 49379, 33980, 32995, 49714, 20787, 10255, 25528, 63700, 19144, 47897, 38474, 57001, 31674, 34556, 1748, 38534, 1691, 38800, 63084, 44176, 51302, 62882, 57885, 33314, 64407, 23685, 47080, 19735, 16160, 15833, 42642, 54966, 34616, 29304, 64711, 60415, 43917, 34264, 56380, 28477, 41541, 65294, 48003, 15817, 52006, 5762, 4179, 37124, 22567, 36933, 57068, 21614, 49134, 49033, 14237, 51105, 34551, 50350, 32737, 51062, 51952, 21049, 50356, 58379, 55594, 17983, 16054, 7414, 14748, 31167, 35632, 27382, 11134, 33944, 51054, 23629, 42755, 17979, 6911, 21128, 57192, 20089, 63901, 9320, 27321, 42562, 64803, 6917, 30527, 31207, 33829, 61540, 25236, 48616, 58993, 32333, 2070, 64935, 3563, 12071, 7705, 60599, 56378, 56466, 10988, 57637, 1425, 49470, 14961, 19071, 25691, 23242, 23051, 24117, 20930, 39185, 54487, 31890, 6497, 26652, 62764, 29560, 37617, 25948, 36294, 44928, 23222, 64853, 34474, 40034, 20088, 55715, 64498, 13181, 55772, 58959, 52147, 27074, 4659, 3363, 16808, 31766, 32046, 29738, 6198, 43303, 25914, 63858, 58119, 26353, 7958, 57296, 7851, 51636, 24523, 25844, 29956, 19738, 24757, 22094, 50022, 27561, 62411, 12427, 35475, 19063, 57508, 18281, 38852, 16788, 12455, 40208, 34338, 50705, 17956, 60641, 65164, 49484, 46384, 38363, 8516, 42066, 56534, 3296, 51692, 33254, 28992, 63073, 34329, 7432, 12133, 35295, 55054, 8761, 43710, 4325, 36376, 29547, 7748, 45368, 17210, 39610, 64420, 58229, 48583, 34535, 38225, 8244, 56660, 34555, 12403, 60937, 8841, 17103, 21446, 46846, 51460, 8892, 26416, 64985, 19905, 62400, 58106, 4915, 27609, 7993, 52239, 23254, 24430, 40820, 60988, 44570, 21912, 53258, 50447, 54910, 12340, 42421, 28070, 22015, 65520, 57027, 63345, 27337, 51806, 61040, 10099, 9718, 41280, 45235, 62901, 38252, 59012, 6370, 23512, 51702, 34063, 19418, 22999, 46078, 49701, 18512, 9264, 40322, 17229, 34360, 32732, 27492, 9096, 15626, 62378, 39427, 64856, 27049, 5244, 1684, 28233, 11782, 47952, 19988, 25556, 63970, 1852, 13153, 42903, 7094, 62086, 10137, 3835, 32323, 41441, 31431, 18053, 10698, 32204, 13602, 17129, 39557, 5621, 32627, 29485, 27496, 2900, 33807, 3491, 27241, 16215, 13567, 1534, 28557, 8130, 52526, 65228, 11285, 1763, 40705, 38963, 42078, 10256, 42661, 6359, 49860, 16301, 55400, 59633, 3475, 64355, 17481, 32111, 50036, 64053, 49202, 38616, 58719, 62374, 38446, 22417, 38765, 31849, 45458, 54184, 50202, 39750, 14294, 21566, 40514, 27888, 36430, 7599, 25210, 16423, 14827, 12383, 26345, 48631, 27728, 63818, 4459, 42072, 16906, 48565, 27823, 57231, 52467, 39595, 60730, 15782, 52364, 63983, 54234, 21843, 12909, 20696, 8347, 16839, 41930, 6452, 18593, 62592, 59404, 58518, 38989, 14805, 57694, 42635, 38218, 23755, 14878, 1908, 33424, 49428, 57247, 33883, 17448, 32934, 45947, 9427, 30716, 20326, 50845, 51170, 20051, 38878, 14236, 54534, 37560, 13810, 2562, 52342, 48614, 52303, 28221, 46814, 12319, 33088, 1088, 51425, 1695, 41360, 49978, 52835, 44547, 59024, 59471, 32097, 40426, 25595, 7484, 6697, 42540, 58352, 20731, 1645, 17648, 29795, 38489, 22668, 64553, 39732, 26013, 41704, 29398, 15858, 56767, 51431, 11465, 65495, 62591, 51326, 8323, 38735, 45871, 42152, 46680, 57352, 44010, 8153, 18808, 14071, 17365, 28081, 42077, 32189, 6696, 16351, 11688, 2108, 24250, 47356, 15386, 33035, 2461, 8239, 57134, 47145, 26332, 16560, 36503, 10160, 14037, 11193, 62905, 38123, 4422, 37089, 27393, 55479, 11989, 51620, 5495, 20738, 42365, 61607, 19450, 47600, 53288, 50335, 42451, 18186, 7824, 30009, 19235, 45014, 6550, 28173, 63116, 40110, 35390, 20444, 1702, 51065, 31582, 15173, 48742, 46758, 26655, 14194, 17836, 58982, 43101, 3807, 20685, 10954, 13939, 25507, 22552, 4828, 41261, 43539, 1769, 24539, 29829, 12549, 49252, 30739, 10898, 47547, 37461, 60382, 5927, 3732, 24093, 56784, 16962, 59907, 38551, 45774, 14610, 60739, 28396, 7242, 34455, 49600, 32863, 10133, 35769, 25426, 13018, 22693, 2436, 60705, 22822, 53410, 37647, 49129, 64688, 31593, 10652, 27709, 53775, 38764, 21467, 62772, 13065, 6651, 51496, 55230, 35944, 23318, 31160, 1486, 55970, 11849, 45092, 27388, 43931, 20659, 41274, 44705, 18338, 49378, 27447, 29925, 61423, 17209, 28266, 2958, 44131, 57057, 51621, 32811, 61811, 20132, 37090, 33885, 56583, 17559, 60812, 48020, 12625, 37640, 55903, 31497, 10849, 57799, 29571, 38508, 42181, 61795, 27051, 41139, 59195, 19495, 2365, 52794, 61887, 31966, 42938, 54768, 46120, 33997, 60517, 40216, 23626, 28502, 35675, 6393, 20040, 46205, 10601, 61712, 11425, 36195, 28136, 61121, 28113, 61339, 13129, 50222, 41180, 9936, 38187, 16893, 4632, 21158, 49925, 43417, 52450, 16914, 8120, 16930, 5271, 39287, 37533, 6992, 20798, 23894, 53433, 53573, 49360, 26923, 28606, 6900, 27650, 22721, 12386, 64472, 23614, 17165, 56663, 54547, 40972, 8928, 25799, 25258, 37069, 36247, 8896, 54129, 44829, 33855, 61020, 6278, 54321, 59720, 47924, 20317, 57631, 46466, 59644, 58867, 48888, 50453, 34800, 23027, 15968, 15961, 39136, 59824, 12036, 22643, 39583, 6633, 57263, 25560, 30318, 55837, 65116, 49873, 9675, 16674, 57000, 5430, 21449, 28225, 39025, 25760, 10477, 33155, 49419, 36586, 9505, 10857, 13620, 56179, 16313, 2164, 38853, 15991, 7983, 57823, 58183, 30809, 24446, 40443, 47411, 60645, 20783, 45027, 48007, 57007, 7210, 12077, 25905, 54044, 13529, 11029, 25004, 5639, 42212, 44174, 12673, 2904, 30040, 50186, 61129, 20192, 6134};
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
struct cm_con_data_t
{
    uint64_t addr;   /* Buffer address */
    uint32_t rkey;   /* Remote key */
    uint32_t qp_num; /* QP number */
    uint16_t lid;    /* LID of the IB port */
    uint8_t gid[16]; /* gid */
} __attribute__((packed));

/* structure of system resources */
struct resources
{
    struct ibv_device_attr device_attr; /* Device attributes */
    struct ibv_port_attr port_attr;     /* IB port attributes */
    struct cm_con_data_t remote_props;  /* values to connect to remote side */
    struct ibv_context *ib_ctx;         /* device handle */
    struct ibv_pd *pd;                  /* PD handle */
    struct ibv_cq *cq;                  /* CQ handle */
    struct ibv_qp *qp;                  /* QP handle */
    struct ibv_mr *mr;                  /* MR handle for buf */
    char *buf;                          /* memory buffer pointer, used for RDMA and send ops */
    int sock;                           /* TCP socket file descriptor */
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

/* poll_completion */
/******************************************************************************
 * Function: poll_completion
 *
 * Input:
 * res: pointer to resources structure
 *
 * Output: none
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description:
 * Poll the completion queue for a single event. This function will continue to
 * poll the queue until MAX_POLL_CQ_TIMEOUT milliseconds have passed.
 *
 ******************************************************************************/
static int poll_completion(struct resources *res)
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
        poll_result = ibv_poll_cq(res->cq, 1, &wc);
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

/******************************************************************************
 * Function: post_send
 *
 * Input:
 * res: pointer to resources structure
 * opcode: IBV_WR_SEND, IBV_WR_RDMA_READ or IBV_WR_RDMA_WRITE
 *
 * Output: none
 *
 * Returns: 0 on success, error code on failure
 *
 * Description: This function will create and post a send work request
 ******************************************************************************/
static int post_send(struct resources *res, enum ibv_wr_opcode opcode)
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;
    int rc;

    /* prepare the scatter/gather entry */
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res->buf;
    sge.length = MSG_SIZE;
    sge.lkey = res->mr->lkey;

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
        sr.wr.rdma.remote_addr = res->remote_props.addr;
        sr.wr.rdma.rkey = res->remote_props.rkey;
    }

    /* there is a Receive Request in the responder side, so we won't get any into RNR flow */
    rc = ibv_post_send(res->qp, &sr, &bad_wr);
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
 * Function: post_receive
 *
 * Input:
 * res: pointer to resources structure
 *
 * Output: none
 *
 * Returns: 0 on success, error code on failure
 *
 * Description: post RR to be prepared for incoming messages
 *
 ******************************************************************************/
static int post_receive(struct resources *res)
{
    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;
    int rc;

    /* prepare the scatter/gather entry */
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res->buf;
    sge.length = MSG_SIZE;
    sge.lkey = res->mr->lkey;

    /* prepare the receive work request */
    memset(&rr, 0, sizeof(rr));
    rr.next = NULL;
    rr.wr_id = 0;
    rr.sg_list = &sge;
    rr.num_sge = 1;

    /* post the Receive Request to the RQ */
    rc = ibv_post_recv(res->qp, &rr, &bad_wr);
    if (rc)
    {
        fprintf(stderr, "failed to post RR\n");
    }
    else
    {
        fprintf(stdout, "Receive Request was posted\n");
    }
    return rc;
}

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
 * Function: resources_create
 *
 * Input: res pointer to resources structure to be filled in
 *
 * Output: res filled in with resources
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description:
 * This function creates and allocates all necessary system resources. These
 * are stored in res.
 *****************************************************************************/
static int resources_create(struct resources *res)
{
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;
    size_t size;
    int i;
    int mr_flags = 0;
    int cq_size = 0;
    int num_devices;
    int rc = 0;

    /* if client side */
    if (config.server_name)
    {
        res->sock = sock_connect(config.server_name, config.tcp_port);
        if (res->sock < 0)
        {
            fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n",
                    config.server_name, config.tcp_port);
            rc = -1;
            goto resources_create_exit;
        }
    }
    else
    {
        fprintf(stdout, "waiting on port %d for TCP connection\n", config.tcp_port);
        res->sock = sock_connect(NULL, config.tcp_port);
        if (res->sock < 0)
        {
            fprintf(stderr, "failed to establish TCP connection with client on port %d\n",
                    config.tcp_port);
            rc = -1;
            goto resources_create_exit;
        }
    }
    fprintf(stdout, "TCP connection was established\n");
    fprintf(stdout, "searching for IB devices in host\n");

    /* get device names in the system */
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list)
    {
        fprintf(stderr, "failed to get IB devices list\n");
        rc = 1;
        goto resources_create_exit;
    }

    /* if there isn't any IB device in host */
    if (!num_devices)
    {
        fprintf(stderr, "found %d device(s)\n", num_devices);
        rc = 1;
        goto resources_create_exit;
    }
    fprintf(stdout, "found %d device(s)\n", num_devices);

    /* search for the specific device we want to work with */
    for (i = 0; i < num_devices; i++)
    {
        if (!config.dev_name)
        {
            config.dev_name = strdup(ibv_get_device_name(dev_list[i]));
            fprintf(stdout, "device not specified, using first one found: %s\n", config.dev_name);
        }
        /* find the specific device */
        if (!strcmp(ibv_get_device_name(dev_list[i]), config.dev_name))
        {
            ib_dev = dev_list[i];
            break;
        }
    }

    /* if the device wasn't found in host */
    if (!ib_dev)
    {
        fprintf(stderr, "IB device %s wasn't found\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }

    /* get device handle */
    res->ib_ctx = ibv_open_device(ib_dev);
    if (!res->ib_ctx)
    {
        fprintf(stderr, "failed to open device %s\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }

    /* We are now done with device list, free it */
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;

    /* query port properties */
    if (ibv_query_port(res->ib_ctx, config.ib_port, &res->port_attr))
    {
        fprintf(stderr, "ibv_query_port on port %u failed\n", config.ib_port);
        rc = 1;
        goto resources_create_exit;
    }

    /* allocate Protection Domain */
    res->pd = ibv_alloc_pd(res->ib_ctx);
    if (!res->pd)
    {
        fprintf(stderr, "ibv_alloc_pd failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    /* each side will send only one WR, so Completion Queue with 1 entry is enough */
    cq_size = 1;
    res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
    if (!res->cq)
    {
        fprintf(stderr, "failed to create CQ with %u entries\n", cq_size);
        rc = 1;
        goto resources_create_exit;
    }

    /* allocate the memory buffer that will hold the data */
    size = MSG_SIZE;
    res->buf = (char *)malloc(size);
    fprintf(stdout, "申请内存buf\n");
    if (!res->buf)
    {
        fprintf(stderr, "failed to malloc %Zu bytes to memory buffer\n", size);
        rc = 1;
        goto resources_create_exit;
    }
    memset(res->buf, 0, size);

    /* only in the server side put the message in the memory buffer */
    if (!config.server_name)
    {
        strcpy(res->buf, SRV_MSG);
        fprintf(stdout, "put the message: '%s' to buf\n", res->buf);
    }
    else
    {
        memset(res->buf, 0, size);
    }

    /* register the memory buffer */
    mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    res->mr = ibv_reg_mr(res->pd, res->buf, size, mr_flags);
    fprintf(stdout, "注册buf内存到pd\n");
    if (!res->mr)
    {
        fprintf(stderr, "ibv_reg_mr failed with mr_flags=0x%x\n", mr_flags);
        rc = 1;
        goto resources_create_exit;
    }
    fprintf(stdout, "MR was registered with addr=%p, lkey=0x%x, rkey=0x%x, flags=0x%x\n",
            res->buf, res->mr->lkey, res->mr->rkey, mr_flags);

    /* create the Queue Pair */
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = res->cq;
    qp_init_attr.recv_cq = res->cq;
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = 1;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    res->qp = ibv_create_qp(res->pd, &qp_init_attr);
    if (!res->qp)
    {
        fprintf(stderr, "failed to create QP\n");
        rc = 1;
        goto resources_create_exit;
    }
    fprintf(stdout, "QP was created, QP number=0x%x\n", res->qp->qp_num);

resources_create_exit:
    if (rc)
    {
        /* Error encountered, cleanup */
        if (res->qp)
        {
            ibv_destroy_qp(res->qp);
            res->qp = NULL;
        }
        if (res->mr)
        {
            ibv_dereg_mr(res->mr);
            res->mr = NULL;
        }
        if (res->buf)
        {
            free(res->buf);
            res->buf = NULL;
        }
        if (res->cq)
        {
            ibv_destroy_cq(res->cq);
            res->cq = NULL;
        }
        if (res->pd)
        {
            ibv_dealloc_pd(res->pd);
            res->pd = NULL;
        }
        if (res->ib_ctx)
        {
            ibv_close_device(res->ib_ctx);
            res->ib_ctx = NULL;
        }
        if (dev_list)
        {
            ibv_free_device_list(dev_list);
            dev_list = NULL;
        }
        if (res->sock >= 0)
        {
            if (close(res->sock))
            {
                fprintf(stderr, "failed to close socket\n");
            }
            res->sock = -1;
        }
    }
    return rc;
}

/******************************************************************************
 * Function: modify_qp_to_init
 *
 * Input:
 * qp: QP to transition
 *
 * Output: none
 *
 * Returns: 0 on success, ibv_modify_qp failure code on failure
 *
 * Description: Transition a QP from the RESET to INIT state
 ******************************************************************************/
static int modify_qp_to_init(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = config.ib_port;
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

/******************************************************************************
 * Function: modify_qp_to_rtr
 *
 * Input:
 * qp: QP to transition
 * remote_qpn: remote QP number
 * dlid: destination LID
 * dgid: destination GID (mandatory for RoCEE)
 *
 * Output: none
 *
 * Returns: 0 on success, ibv_modify_qp failure code on failure
 *
 * Description:
 * Transition a QP from the INIT to RTR state, using the specified QP number
 ******************************************************************************/
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
    attr.ah_attr.port_num = config.ib_port;
    if (config.gid_idx >= 0)
    {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = config.gid_idx;
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

/******************************************************************************
 * Function: modify_qp_to_rts
 *
 * Input:
 * qp: QP to transition
 *
 * Output: none
 *
 * Returns: 0 on success, ibv_modify_qp failure code on failure
 *
 * Description: Transition a QP from the RTR to RTS state
 ******************************************************************************/
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

/******************************************************************************
 * Function: connect_qp
 *
 * Input:
 * res: pointer to resources structure
 *
 * Output: none
 *
 * Returns: 0 on success, error code on failure
 *
 * Description:
 * Connect the QP. Transition the server side to RTR, sender side to RTS
 ******************************************************************************/
static int connect_qp(struct resources *res)
{
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    int rc = 0;
    char temp_char;
    union ibv_gid my_gid;
    if (config.gid_idx >= 0)
    {
        rc = ibv_query_gid(res->ib_ctx, config.ib_port, config.gid_idx, &my_gid);
        if (rc)
        {
            fprintf(stderr, "could not get gid for port %d, index %d\n", config.ib_port, config.gid_idx);
            return rc;
        }
    }
    else
    {
        memset(&my_gid, 0, sizeof my_gid);
    }

    /* exchange using TCP sockets info required to connect QPs */
    local_con_data.addr = htonll((uintptr_t)res->buf);
    local_con_data.rkey = htonl(res->mr->rkey);
    local_con_data.qp_num = htonl(res->qp->qp_num);
    local_con_data.lid = htons(res->port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);
    fprintf(stdout, "\nLocal LID = 0x%x\n", res->port_attr.lid);
    if (sock_sync_data(res->sock, sizeof(struct cm_con_data_t), (char *)&local_con_data, (char *)&tmp_con_data) < 0)
    {
        fprintf(stderr, "failed to exchange connection data between sides\n");
        rc = 1;
        goto connect_qp_exit;
    }

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    /* save the remote side attributes, we will need it for the post SR */
    res->remote_props = remote_con_data;
    fprintf(stdout, "Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
    fprintf(stdout, "Remote rkey = 0x%x\n", remote_con_data.rkey);
    fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
    fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
    if (config.gid_idx >= 0)
    {
        uint8_t *p = remote_con_data.gid;
        fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }

    /* modify the QP to init */
    rc = modify_qp_to_init(res->qp);
    if (rc)
    {
        fprintf(stderr, "change QP state to INIT failed\n");
        goto connect_qp_exit;
    }

    /* modify the QP to RTR */
    rc = modify_qp_to_rtr(res->qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }

    /* modify the QP to RTS */
    rc = modify_qp_to_rts(res->qp);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTS\n");
        goto connect_qp_exit;
    }
    fprintf(stdout, "QP state was change to RTS\n");

connect_qp_exit:
    return rc;
}

/******************************************************************************
 * Function: resources_destroy
 *
 * Input:
 * res: pointer to resources structure
 *
 * Output: none
 *
 * Returns: 0 on success, 1 on failure
 *
 * Description: Cleanup and deallocate all resources used
 ******************************************************************************/
static int resources_destroy(struct resources *res)
{
    int rc = 0;
    if (res->qp)
    {
        if (ibv_destroy_qp(res->qp))
        {
            fprintf(stderr, "failed to destroy QP\n");
            rc = 1;
        }
    }

    if (res->mr)
    {
        if (ibv_dereg_mr(res->mr))
        {
            fprintf(stderr, "failed to deregister MR\n");
            rc = 1;
        }
    }

    if (res->buf)
    {
        free(res->buf);
    }

    if (res->cq)
    {
        if (ibv_destroy_cq(res->cq))
        {
            fprintf(stderr, "failed to destroy CQ\n");
            rc = 1;
        }
    }

    if (res->pd)
    {
        if (ibv_dealloc_pd(res->pd))
        {
            fprintf(stderr, "failed to deallocate PD\n");
            rc = 1;
        }
    }

    if (res->ib_ctx)
    {
        if (ibv_close_device(res->ib_ctx))
        {
            fprintf(stderr, "failed to close device context\n");
            rc = 1;
        }
    }

    if (res->sock >= 0)
    {
        if (close(res->sock))
        {
            fprintf(stderr, "failed to close socket\n");
            rc = 1;
        }
    }
    return rc;
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
