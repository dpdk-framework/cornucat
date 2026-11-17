#include "options.h"
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct pg_options options;
    pg_options_default(&options);
    int separator = -1;
    for (int i = 1; i < argc; ++i) if (!strcmp(argv[i], "--")) { separator = i; break; }
    int first = separator < 0 ? 1 : separator + 1;
    char error[192];
    int parsed = pg_options_parse(argc - first, argv + first, &options, error, sizeof(error));
    if (parsed == 1) { pg_usage(stdout, argv[0]); return EXIT_SUCCESS; }
    if (parsed < 0) { fprintf(stderr, "%s\n", error); pg_usage(stderr, argv[0]); return EXIT_FAILURE; }
    if (options.mode == PG_MODE_PCAP) {
        if (separator >= 0) { fprintf(stderr, "EAL arguments are only available in DPDK mode\n"); return EXIT_FAILURE; }
        return pg_write_pcap(&options) ? EXIT_FAILURE : EXIT_SUCCESS;
    }
    if (separator < 0) { fprintf(stderr, "Separate EAL and application options with --\n"); return EXIT_FAILURE; }
#ifdef PG_HAVE_DPDK
    if (options.replay_input)
        return pg_dpdk_replay_run(separator + 1, argv, &options) ? EXIT_FAILURE : EXIT_SUCCESS;
    if (options.stream_count || options.control_socket || options.ttl_min != options.ttl_max)
        return pg_dpdk_stream_run(separator + 1, argv, &options) ? EXIT_FAILURE : EXIT_SUCCESS;
    return pg_dpdk_run(separator + 1, argv, &options) ? EXIT_FAILURE : EXIT_SUCCESS;
#else
    fprintf(stderr, "This executable has no DPDK backend; on Linux build with make dpdk\n");
    return EXIT_FAILURE;
#endif
}
