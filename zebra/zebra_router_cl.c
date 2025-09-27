// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra Router Code.
 * Copyright (C) 2025 Nvidia, Inc.
 *    Soumya Roy
 */

#include "zebra.h"
#include <sys/stat.h> 
#include "lib/hook.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_router_cl.h"


/* Platform detection function for nos_initialize_data hook */
int zebra_platform_data_init(struct zebra_architectural_values *zav)
{
	struct stat pfile;

	zlog_info("Zebra: Initializing platform-specific data");
	
	if (stat("/usr/bin/platform-detect", &pfile) >= 0) {
		/* Platform-detect exists - check if it's VX or regular platform */
		int rc = 0;
		if ((rc = system("/usr/bin/platform-detect | grep vx")) == 0) {
			/* VX platform - no ASIC offload, use build-time default */
			zav->asic_offloaded = false;
			zlog_info("VX platform detected, using build-time default multipath: %d", zav->multipath_num);
		} else {
			/* Non-VX platform - has ASIC offload, read from system file */
			zav->asic_offloaded = true;
			FILE *ecmp_fp = fopen("/cumulus/switchd/run/route_info/ecmp_nh/max_per_route", "r");
			if (ecmp_fp != NULL) {
				char ecmp_buffer[32];
				if (fgets(ecmp_buffer, sizeof(ecmp_buffer), ecmp_fp) != NULL) {
					int max_multipath;
					int count = sscanf(ecmp_buffer, "%d", &max_multipath);
					if (count == 1 && max_multipath > 0) {
						zav->multipath_num = max_multipath;
						zlog_info("ASIC platform detected, read max multipath from system file: %d", max_multipath);
					}
				}
				fclose(ecmp_fp);
			}
		}

		if (WIFSIGNALED(rc) && WTERMSIG(rc) == SIGINT)
			raise(SIGINT);
	}

	return 0;
}

/* Initialize platform detection hooks */
void zebra_platform_init(void)
{
	hook_register(nos_initialize_data, zebra_platform_data_init);
	zlog_info("Zebra: Platform detection hook registered");
}
