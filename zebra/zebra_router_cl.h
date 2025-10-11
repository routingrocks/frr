// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra Router CL header.
 * Copyright (C) 2025 Nvidia, Inc.
 * Soumya Roy
 */
 #ifndef __ZEBRA_ROUTER_CL_H__
 #define __ZEBRA_ROUTER_CL_H__
 
 #include "zebra/zebra_router.h"
 #ifdef __cplusplus
 extern "C" {
 #endif
 
/*
 * This header file contains platform detection apis for zebra
 */
int zebra_platform_data_init(struct zebra_architectural_values *zav);
void zebra_platform_init(void);

#ifdef __cplusplus
 }
 #endif

 #endif