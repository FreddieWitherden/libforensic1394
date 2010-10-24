/*
    This file is part of libforensic1394.
    Copyright (C) 2010  Freddie Witherden <freddie@witherden.org>

    libforensic1394 is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    libforensic1394 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with libforensic1394.  If not, see
    <http://www.gnu.org/licenses/>.
*/

#ifndef FORENSIC1394_COMMON_H
#define FORENSIC1394_COMMON_H

#include "forensic1394.h"

#define FORENSIC1394_DEV_NAME_SZ 64

/// Request timeout in milliseconds
#define FORENSIC1394_TIMEOUT_MS  150

typedef enum
{
    REQUEST_TYPE_READ,
    REQUEST_TYPE_WRITE
} request_type;

typedef struct _platform_bus platform_bus;

typedef struct _platform_dev platform_dev;

struct _forensic1394_bus
{
    int sbp2_enabled;

    forensic1394_dev **dev;
    forensic1394_dev *dev_link;

    int ndev;

    void *user_data;

    forensic1394_device_callback ondestroy;

    platform_bus *pbus;
};

struct _forensic1394_dev
{
    char product_name[FORENSIC1394_DEV_NAME_SZ];
    int product_id;

    char vendor_name[FORENSIC1394_DEV_NAME_SZ];
    int vendor_id;

    int max_req;

    int is_open;

    uint16_t node_id;
    uint32_t generation;

    int64_t guid;

    uint32_t rom[FORENSIC1394_CSR_SZ];

    void *user_data;

    platform_dev *pdev;
    forensic1394_bus *bus;

    forensic1394_dev *next;
};

platform_bus *platform_bus_alloc(void);

void platform_bus_destroy(forensic1394_bus *bus);

forensic1394_result platform_enable_sbp2(forensic1394_bus *bus,
                                         const uint32_t *sbp2dir, size_t len);

forensic1394_result platform_update_device_list(forensic1394_bus *bus);

void platform_device_destroy(forensic1394_dev *dev);

forensic1394_result platform_open_device(forensic1394_dev *dev);

void platform_close_device(forensic1394_dev *dev);

forensic1394_result platform_send_requests(forensic1394_dev *dev,
                                           request_type type,
                                           const forensic1394_req *req,
                                           size_t nreq);

#endif // FORENSIC1394_COMMON_H
