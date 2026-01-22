// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 */

#include <zebra.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>

#include "filter.h"
#include "if.h"
#include "vrf.h"

#include "bfd.h"
#include "bfd_trace.h"
#include "bfdd_nb.h"
#include "bfddp_packet.h"
#include "lib/version.h"
#include "lib/command.h"


/*
 * FRR related code.
 */
DEFINE_MGROUP(BFDD, "Bidirectional Forwarding Detection Daemon");
DEFINE_MTYPE(BFDD, BFDD_CONTROL, "control socket memory");
DEFINE_MTYPE(BFDD, BFDD_NOTIFICATION, "control notification data");

/* Master of threads. */
struct event_loop *master;

/* BFDd privileges */
static zebra_capabilities_t _caps_p[] = {    ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN, ZCAP_NET_RAW, ZCAP_IPC_LOCK, ZCAP_SYS_RAWIO, ZCAP_BIND, ZCAP_SETID, ZCAP_CHROOT, ZCAP_NICE, ZCAP_PTRACE, ZCAP_DAC_OVERRIDE, ZCAP_READ_SEARCH, ZCAP_FOWNER,};

static zebra_capabilities_t _caps_i[] = {    ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN, ZCAP_NET_RAW, ZCAP_IPC_LOCK, ZCAP_SYS_RAWIO, ZCAP_BIND, ZCAP_SETID, ZCAP_CHROOT, ZCAP_NICE, ZCAP_PTRACE, ZCAP_DAC_OVERRIDE, ZCAP_READ_SEARCH, ZCAP_FOWNER,};

/* BFD daemon information. */
static struct frr_daemon_info bfdd_di;

void socket_close(int *s)
{
	if (*s <= 0)
		return;

	if (close(*s) != 0) {
		/* Trace socket close failed */
		frrtrace(3, frr_bfd, socket_error, 5, 0, errno);
		zlog_err("%s: close(%d): (%d) %s", __func__, *s, errno,
			 strerror(errno));
	}

	*s = -1;
}

static void sigusr1_handler(void)
{
	zlog_rotate();
}

static void sigterm_handler(void)
{
	bglobal.bg_shutdown = true;

	/* Signalize shutdown. */
	frr_early_fini();

	/* Stop receiving message from zebra. */
	bfdd_zclient_stop();

	/* Shutdown controller to avoid receiving anymore commands. */
	control_shutdown();

	/* Shutdown and free all protocol related memory. */
	bfd_shutdown();

	bfd_vrf_terminate();

	bfdd_zclient_terminate();

	/* Terminate and free() FRR related memory. */
	frr_fini();

	exit(0);
}

static void sighup_handler(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, bfdd_di.config_file, config_default);
}

static struct frr_signal_t bfd_signals[] = {
	{
		.signal = SIGUSR1,
		.handler = &sigusr1_handler,
	},
	{
		.signal = SIGTERM,
		.handler = &sigterm_handler,
	},
	{
		.signal = SIGINT,
		.handler = &sigterm_handler,
	},
	{
		.signal = SIGHUP,
		.handler = &sighup_handler,
	},
};

static const struct frr_yang_module_info *const bfdd_yang_modules[] = {
	&frr_filter_cli_info,
	&frr_interface_info,
	&frr_bfdd_info,
	&frr_vrf_info,
};

/* clang-format off */
FRR_DAEMON_INFO(bfdd, BFD,
	.vty_port = BFDD_VTY_PORT,
	.proghelp = "Implementation of the BFD protocol.",

	.signals = bfd_signals,
	.n_signals = array_size(bfd_signals),

	.privs = &bglobal.bfdd_privs,

	.yang_modules = bfdd_yang_modules,
	.n_yang_modules = array_size(bfdd_yang_modules),
);
/* clang-format on */

#define OPTION_CTLSOCK 1001
#define OPTION_DPLANEADDR 2000
static const struct option longopts[] = {
	{"bfdctl", required_argument, NULL, OPTION_CTLSOCK},
	{"dplaneaddr", required_argument, NULL, OPTION_DPLANEADDR},
	{0}
};


/*
 * BFD daemon related code.
 */
struct bfd_global bglobal;

const struct bfd_diag_str_list diag_list[] = {
	{.str = "control-expired", .type = BD_CONTROL_EXPIRED},
	{.str = "echo-failed", .type = BD_ECHO_FAILED},
	{.str = "neighbor-down", .type = BD_NEIGHBOR_DOWN},
	{.str = "forwarding-reset", .type = BD_FORWARDING_RESET},
	{.str = "path-down", .type = BD_PATH_DOWN},
	{.str = "concatenated-path-down", .type = BD_CONCATPATH_DOWN},
	{.str = "administratively-down", .type = BD_ADMIN_DOWN},
	{.str = "reverse-concat-path-down", .type = BD_REVCONCATPATH_DOWN},
	{.str = NULL},
};

const struct bfd_state_str_list state_list[] = {
	{.str = "admin-down", .type = PTM_BFD_ADM_DOWN},
	{.str = "down", .type = PTM_BFD_DOWN},
	{.str = "init", .type = PTM_BFD_INIT},
	{.str = "up", .type = PTM_BFD_UP},
	{.str = NULL},
};

/**
 * Check if this is a hardware platform (not VX/virtual).
 * 
 * @return true if hardware platform, false if virtual platform
 */
static bool
is_hardware_platform(void)
{
	FILE *fp;
	char result[128];
	bool is_hardware = true;

	/* Run platform-detect and check for 'vx' in output */
	fp = popen("/usr/bin/platform-detect 2>/dev/null | grep vx", "r");
	if (fp == NULL) {
		/* If platform-detect doesn't exist, assume hardware platform */
		return true;
	}

	/* If grep finds 'vx', fgets will return non-NULL (virtual platform) */
	if (fgets(result, sizeof(result), fp) != NULL) {
		/* Found 'vx' in output - this is a virtual platform */
		is_hardware = false;
		zlog_info("Virtual platform detected: %s", result);
	}

	pclose(fp);
	return is_hardware;
}

static uint16_t
parse_port(const char *str)
{
	char *nulbyte;
	long rv;

	errno = 0;
	rv = strtol(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
		fprintf(stderr, "invalid BFD data plane address port: %s\n",
			str);
		exit(0);
	}
	/* Invalid number range. */
	if ((rv <= 0 || rv >= 65535) || errno == ERANGE) {
		fprintf(stderr, "invalid BFD data plane port range: %s\n",
			str);
		exit(0);
	}
	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		fprintf(stderr, "invalid BFD data plane port: %s\n",
			str);
		exit(0);
	}

	return (uint16_t)rv;
}

static void
distributed_bfd_init(const char *arg)
{
	char *sptr, *saux;
	bool is_client = false;
	size_t slen;
	socklen_t salen;
	char addr[64];
	char type[64];
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_un sun;
	} sa;

	/* Basic parsing: find ':' to figure out type part and address part. */
	sptr = strchr(arg, ':');
	if (sptr == NULL) {
		fprintf(stderr, "invalid BFD data plane socket: %s\n", arg);
		exit(1);
	}

	/* Calculate type string length. */
	slen = (size_t)(sptr - arg);

	/* Copy the address part. */
	sptr++;
	strlcpy(addr, sptr, sizeof(addr));

	/* Copy type part. */
	strlcpy(type, arg, slen + 1);

	/* Reset address data. */
	memset(&sa, 0, sizeof(sa));

	/* Fill the address information. */
	if (strcmp(type, "unix") == 0 || strcmp(type, "unixc") == 0) {
		if (strcmp(type, "unixc") == 0)
			is_client = true;

		salen = sizeof(sa.sun);
		sa.sun.sun_family = AF_UNIX;
		strlcpy(sa.sun.sun_path, addr, sizeof(sa.sun.sun_path));
	} else if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv4c") == 0) {
		if (strcmp(type, "ipv4c") == 0)
			is_client = true;

		salen = sizeof(sa.sin);
		sa.sin.sin_family = AF_INET;

		/* Parse port if any. */
		sptr = strchr(addr, ':');
		if (sptr == NULL) {
			sa.sin.sin_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		} else {
			*sptr = 0;
			sa.sin.sin_port = htons(parse_port(sptr + 1));
		}

		if (inet_pton(AF_INET, addr, &sa.sin.sin_addr) != 1)
			errx(1, "%s: inet_pton: invalid address %s", __func__,
			     addr);
	} else if (strcmp(type, "ipv6") == 0 || strcmp(type, "ipv6c") == 0) {
		if (strcmp(type, "ipv6c") == 0)
			is_client = true;

		salen = sizeof(sa.sin6);
		sa.sin6.sin6_family = AF_INET6;

		/* Check for IPv6 enclosures '[]' */
		sptr = &addr[0];
		if (*sptr != '[')
			errx(1, "%s: invalid IPv6 address format: %s", __func__,
			     addr);

		saux = strrchr(addr, ']');
		if (saux == NULL)
			errx(1, "%s: invalid IPv6 address format: %s", __func__,
			     addr);

		/* Consume the '[]:' part. */
		slen = saux - sptr;
		memmove(addr, addr + 1, slen);
		addr[slen - 1] = 0;

		/* Parse port if any. */
		saux++;
		sptr = strrchr(saux, ':');
		if (sptr == NULL) {
			sa.sin6.sin6_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		} else {
			*sptr = 0;
			sa.sin6.sin6_port = htons(parse_port(sptr + 1));
		}

		if (inet_pton(AF_INET6, addr, &sa.sin6.sin6_addr) != 1)
			errx(1, "%s: inet_pton: invalid address %s", __func__,
			     addr);
	} else {
		fprintf(stderr, "invalid BFD data plane socket type: %s\n",
			type);
		exit(1);
	}

	/* Initialize BFD data plane listening socket. */
	bfd_dplane_init((struct sockaddr *)&sa, salen, is_client);
}

static void bg_init(void)
{
	struct zebra_privs_t bfdd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
		.user = FRR_USER,
		.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
		.vty_group = VTY_GROUP,
#endif
		.caps_p = _caps_p,
		.cap_num_p = array_size(_caps_p),
		.caps_i = _caps_i,
		.cap_num_i = array_size(_caps_i),
	};

	TAILQ_INIT(&bglobal.bg_bcslist);
	TAILQ_INIT(&bglobal.bg_obslist);

	memcpy(&bglobal.bfdd_privs, &bfdd_privs,
	       sizeof(bfdd_privs));
}

int main(int argc, char *argv[])
{
	char ctl_path[512], dplane_addr[512];
	bool ctlsockused = false;
	int opt;

	bglobal.bg_use_dplane = false;
	bool dplaneaddr_configured = false;

	/* Initialize global RAW socket to invalid */
	bglobal.bg_shop6_raw = -1;
	bglobal.bg_shop6_raw_ev = NULL;

	/* Initialize system sockets. */
	bg_init();

	frr_preinit(&bfdd_di, argc, argv);
	frr_opt_add("", longopts,
		    "      --bfdctl       Specify bfdd control socket\n"
		    "      --dplaneaddr   Specify BFD data plane address\n");

	while (true) {
		opt = frr_getopt(argc, argv, NULL);
		if (opt == EOF)
			break;

		switch (opt) {
		case OPTION_CTLSOCK:
			strlcpy(ctl_path, optarg, sizeof(ctl_path));
			ctlsockused = true;
			break;
		case OPTION_DPLANEADDR:
			strlcpy(dplane_addr, optarg, sizeof(dplane_addr));
			dplaneaddr_configured = true;
			break;

		default:
			frr_help_exit(1);
		}
	}

	if (!ctlsockused)
		snprintf(ctl_path, sizeof(ctl_path), BFDD_SOCK_NAME);

	/* Initialize FRR infrastructure. */
	master = frr_init();

	/* Initialize control socket. */
	control_init(ctl_path);

	/* Initialize BFD data structures. */
	bfd_initialize();

	bfd_vrf_init();

	/*
	 * Initialize access-list/prefix-list CLI commands.
	 * Note: We use frr_filter_cli_info instead of frr_filter_info in
	 * bfdd_yang_modules[] so that the Northbound config callbacks are
	 * ignored. Additionally, we set filter_cli_skip_processing to skip
	 * CLI processing entirely for prefix-lists.
	 * This prevents bfdd from allocating memory for prefix-list
	 * entries that it doesn't use, while still allowing the CLI commands
	 * to be parsed without "Unknown command" errors.
	 */
	filter_cli_skip_processing = true;
	access_list_init();

	/* Initialize zebra connection. */
	bfdd_zclient_init(&bglobal.bfdd_privs);

	event_add_read(master, control_accept, NULL, bglobal.bg_csock,
		       &bglobal.bg_csockev);

	/* Install commands. */
	bfdd_vty_init();

	/* read configuration file and daemonize  */
	frr_config_fork();

	/* Initialize BFD data plane listening socket. */
	if (dplaneaddr_configured) {
		/* Check if this is a hardware platform before initializing data plane */
		if (!is_hardware_platform()) {
			zlog_err("BFD data plane is only supported on hardware platforms, not on virtual/VX platforms");
			fprintf(stderr, "Error: BFD data plane (--dplaneaddr) is only supported on hardware platforms.\n");
			fprintf(stderr, "       Virtual/VX platforms detected. Data plane will not be initialized.\n");
			/* Don't exit - just skip data plane initialization */
		} else {
			distributed_bfd_init(dplane_addr);
		}
	}

	frr_run(master);
	/* NOTREACHED */

	return 0;
}
