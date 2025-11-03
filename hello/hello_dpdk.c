#include <stdio.h>
#include <stdlib.h>   // ← 必须，加这里！

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_launch.h>

static int lcore_hello(__rte_unused void *arg) {
    printf("hello from lcore %u\n", rte_lcore_id());
    return 0;
}

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "EAL init failed\n");
    }

    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
    }

    lcore_hello(NULL);
    rte_eal_mp_wait_lcore();
    return 0;
}
