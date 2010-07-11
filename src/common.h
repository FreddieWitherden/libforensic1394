/*
    This file is part of Forensic1394.
    Copyright (C) 2010  Freddie Witherden <freddie@witherden.org>

    Forensic1394 is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    Forensic1394 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with Forensic1394.  If not, see
    <http://www.gnu.org/licenses/>.
*/

#ifndef FORENSIC1394_COMMON_H
#define FORENSIC1394_COMMON_H

#include "forensic1394.h"

#define FORENSIC1394_DEV_LIST_SZ 16
#define FORENSIC1394_DEV_NAME_SZ 64

typedef struct _platform_bus platform_bus;

typedef struct _platform_dev platform_dev;

struct _forensic1394_bus
{
    int sbp2Enabled;

    forensic1394_dev **dev;
    int ndev;
    int size;

    platform_bus *pbus;
};

struct _forensic1394_dev
{
    char product_name[FORENSIC1394_DEV_NAME_SZ];
    int product_id;

    char vendor_name[FORENSIC1394_DEV_NAME_SZ];
    int vendor_id;

    int isOpen;

    uint16_t nodeid;

    uint32_t rom[256];

    platform_dev *pdev;
    forensic1394_bus *bus;
};

platform_bus *platform_bus_alloc(void);

void platform_bus_destory(forensic1394_bus *bus);

int platform_enable_sbp2(forensic1394_bus *bus);

void platform_update_device_list(forensic1394_bus *bus);

void platform_device_destroy(forensic1394_dev *dev);

int platform_open_device(forensic1394_dev *dev);

void platform_close_device(forensic1394_dev *dev);

int platform_read_device(forensic1394_dev *dev,
                         uint64_t addr,
                         size_t len,
                         void *buf);

int platform_write_device(forensic1394_dev *dev,
                          uint64_t addr,
                          size_t len,
                          void *buf);

#endif // FORENSIC1394_COMMON_H
