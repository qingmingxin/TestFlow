#include "basic.h"

int prepare(struct resources *res, int loop_time)
{
    resources_init(res);
    /* if client side */
    auto prepare_start_time = std::chrono::high_resolution_clock::now();
    if (config.server_name)
    {
        res->sock = sock_connect(config.server_name, tcp_ports[loop_time]);
        if (res->sock < 0)
        {
            fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n",
                    config.server_name, tcp_ports[loop_time]);
            return 1;
        }
    }
    else
    {
        fprintf(stdout, "waiting on port %d for TCP connection\n", tcp_ports[loop_time]);
        res->sock = sock_connect(NULL, tcp_ports[loop_time]);
        if (res->sock < 0)
        {
            fprintf(stderr, "failed to establish TCP connection with client on port %d\n",
                    tcp_ports[loop_time]);
            return 1;
        }
    }
    auto prepare_end_sock = std::chrono::high_resolution_clock::now();
    struct ibv_device **dev_list = NULL;
    struct ibv_device *ib_dev = NULL;
    int num_devices;
    dev_list = ibv_get_device_list(&num_devices);
    auto prepare_end_get_device_list = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_devices; i++)
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
    auto prepare_end_get_device_name = std::chrono::high_resolution_clock::now();
    size_t size;
    int i;
    int mr_flags = 0;
    int cq_size = 0;
    res->ib_ctx = ibv_open_device(ib_dev);
    auto prepare_end_open_device = std::chrono::high_resolution_clock::now();
    /* create resources before using them */

    if (ibv_query_port(res->ib_ctx, config.ib_port, &res->port_attr))
    {
        fprintf(stderr, "ibv_query_port on port %u failed\n", config.ib_port);
        return 1;
    }

    /* allocate Protection Domain */
    res->pd = ibv_alloc_pd(res->ib_ctx);
    if (!res->pd)
    {
        fprintf(stderr, "ibv_alloc_pd failed\n");
        return 1;
    }

    /* each side will send only one WR, so Completion Queue with 1 entry is enough */
    cq_size = 1;
    res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
    if (!res->cq)
    {
        fprintf(stderr, "failed to create CQ with %u entries\n", cq_size);
        return 1;
    }

    /* allocate the memory buffer that will hold the data */
    size = MSG_SIZE;
    res->buf = (char *)malloc(size);
    fprintf(stdout, "申请内存buf\n");
    if (!res->buf)
    {
        fprintf(stderr, "failed to malloc %Zu bytes to memory buffer\n", size);
        return 1;
    }
    memset(res->buf, 0, size);

    /* only in the server side put the message in the memory buffer */
    if (config.server_name)
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
        return 1;
    }
    fprintf(stdout, "MR was registered with addr=%p, lkey=0x%x, rkey=0x%x, flags=0x%x\n",
            res->buf, res->mr->lkey, res->mr->rkey, mr_flags);

    /* create the Queue Pair */
    struct ibv_qp_init_attr qp_init_attr;
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
        return 1;
    }
    fprintf(stdout, "QP was created, QP number=0x%x\n", res->qp->qp_num);
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    union ibv_gid my_gid;
    if (config.gid_idx >= 0)
    {
        int rc = ibv_query_gid(res->ib_ctx, config.ib_port, config.gid_idx, &my_gid);
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
        return 1;
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
    if (modify_qp_to_init(res->qp))
    {
        fprintf(stderr, "change QP state to INIT failed\n");
        return 1;
    }

    /* modify the QP to RTR */
    if (modify_qp_to_rtr(res->qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid))
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        return 1;
    }
    if (config.server_name)
    {

        /* modify the QP to RTS */
        if (modify_qp_to_rts(res->qp))
        {
            fprintf(stderr, "failed to modify QP state to RTS\n");
            return 1;
        }
        fprintf(stdout, "QP state was change to RTS\n");
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct resources res;
    int rc = 0;
    int cur_loop_time = 1;
    char temp_char;

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

    /* print the used parameters for info*/
    print_config();
    auto start_time = std::chrono::high_resolution_clock::now();
    /* init all of the resources, so cleanup will be easy */
    if (!LOOPSEND)
    {
        while (cur_loop_time <= LOOPTIME)
        {
            rc = 0;
            auto start_item = std::chrono::high_resolution_clock::now();
            if (prepare(&res, cur_loop_time - 1))
            {
                fprintf(stderr, "failed to prepare.\n");
                goto main_break;
            }
            auto end_conn = std::chrono::high_resolution_clock::now();

            if (config.server_name)
            {
                if (post_send(&res, IBV_WR_SEND))
                {
                    fprintf(stderr, "failed to post sr\n");
                    goto main_break;
                }
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
            else
            {
                if (post_receive(&res))
                {
                    fprintf(stderr, "failed to post RR\n");
                    goto main_break;
                }
            }
            /* in both sides we expect to get a completion */
            if (poll_completion(&res))
            {
                fprintf(stderr, "poll completion failed\n");
                goto main_break;
            }
            if (!config.server_name)
            {
                fprintf(stdout, "Contents of server buffer: '%s'\n", res.buf);
            }
            rc = 0;
            auto end_send = std::chrono::high_resolution_clock::now();
            if (resources_destroy(&res))
            {
                fprintf(stderr, "failed to destroy resources\n");
                rc = 1;
            }
            auto end_destory = std::chrono::high_resolution_clock::now();
            auto conn_time = std::chrono::duration_cast<std::chrono::microseconds>(end_conn - start_item).count();
            auto send_time = std::chrono::duration_cast<std::chrono::microseconds>(end_send - end_conn).count();
            auto destory_time = std::chrono::duration_cast<std::chrono::microseconds>(end_destory - end_send).count();
            fprintf(stdout, "time: '%d'\t conn_time: %lld μs \t send_time: %lld μs\tdestory_time: %lld μs\n", cur_loop_time, conn_time, send_time, destory_time);
            cur_loop_time++;
        }
    }
    else
    {
        auto start_item_1 = std::chrono::high_resolution_clock::now();
        if (prepare(&res, 0))
        {
            fprintf(stderr, "failed to prepare.\n");
            goto main_break;
        }
        auto end_conn = std::chrono::high_resolution_clock::now();
        auto conn_time = std::chrono::duration_cast<std::chrono::microseconds>(end_conn - start_item_1).count();
        fprintf(stdout, "conn_time: %lld μs \n", conn_time);
        while (cur_loop_time <= LOOPTIME)
        {
            fprintf(stdout, "test time: '%d'\n", cur_loop_time);
            auto start_item_2 = std::chrono::high_resolution_clock::now();
            if (config.server_name)
            {
                if (post_send(&res, IBV_WR_SEND))
                {
                    fprintf(stderr, "failed to post sr\n");
                    goto main_break;
                }
                std::this_thread::sleep_for(std::chrono::microseconds(10));
                // usleep(10);
            }
            else
            {
                if (post_receive(&res))
                {
                    fprintf(stderr, "failed to post RR\n");
                    goto main_break;
                }
            }
            /* in both sides we expect to get a completion */
            if (poll_completion(&res))
            {
                fprintf(stderr, "poll completion failed\n");
                goto main_break;
            }
            if (!config.server_name)
            {
                fprintf(stdout, "Contents of server buffer: '%s'\n", res.buf);
            }
            auto end_send = std::chrono::high_resolution_clock::now();
            auto send_time = std::chrono::duration_cast<std::chrono::microseconds>(end_send - start_item_2).count();
            fprintf(stdout, "time: '%d'\tsend_time: %lld μs \n", cur_loop_time, send_time);
            cur_loop_time++;
        }
        auto start_item_3 = std::chrono::high_resolution_clock::now();
        if (resources_destroy(&res))
        {
            fprintf(stderr, "failed to destroy resources\n");
            rc = 1;
        }
        auto end_destory = std::chrono::high_resolution_clock::now();
        auto des_time = std::chrono::duration_cast<std::chrono::microseconds>(end_destory - start_item_3).count();
        fprintf(stdout, "des_time: %lld μs \n", des_time);
    }
main_break:
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
    fprintf(stdout, "\n test used %lld μs\n", duration_time);
    if (config.dev_name)
    {
        free((char *)config.dev_name);
    }
    fprintf(stdout, "\n test result is %d\n", rc);
    return 0;
}