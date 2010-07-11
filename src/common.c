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

#include "forensic1394.h"
#include "common.h"

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void forensic1394_destroy_all_devices(forensic1394_bus *bus);

forensic1394_bus *forensic1394_alloc(void)
{
    forensic1394_bus *b = malloc(sizeof(forensic1394_bus));

    if (!b)
    {
        return NULL;
    }

    // SBP-2 needs to be enabled explicitly
    b->sbp2Enabled = 0;

    // We have no devices (yet!)
    b->dev = NULL;
    b->ndev = 0;
    b->size = 0;

    // Delegate to the platform-specific allocation routine
    b->pbus = platform_bus_alloc();

    if (!b->pbus)
    {
        free(b);
        return NULL;
    }

    return b;
}

void forensic1394_destroy(forensic1394_bus *bus)
{
    assert(bus);

    // Get rid of any devices
    forensic1394_destroy_all_devices(bus);

    // Delegate
    platform_bus_destory(bus);

    // Free the bus
    free(bus);
}

int forensic1394_enable_sbp2(forensic1394_bus *bus)
{
    assert(bus);

    // Check that it is not already enabled
    if (bus->sbp2Enabled)
    {
        return 1;
    }

    bus->sbp2Enabled = platform_enable_sbp2(bus);

    return bus->sbp2Enabled;
}

forensic1394_dev **forensic1394_get_devices(forensic1394_bus *bus,
                                            int *ndev)
{
    assert(bus);

    // Void the current device list, freeing any memory associated with it
    forensic1394_destroy_all_devices(bus);

    // Allocate some space for the initial device list
    bus->dev = malloc(sizeof(forensic1394_dev *) * FORENSIC1394_DEV_LIST_SZ);
    bus->size = FORENSIC1394_DEV_LIST_SZ;

    // Update the device list
    platform_update_device_list(bus);

    // Ensure we have space to NULL terminate
    assert(bus->ndev < bus->size);

    // NULL terminate the last item in the list
    bus->dev[bus->ndev] = NULL;

    // If ndev was passed populate it with the number of devices
    if (ndev)
    {
        *ndev = bus->ndev;
    }

    return bus->dev;
}

int forensic1394_open_device(forensic1394_dev *dev)
{
    int ret;

    assert(dev);

    // Ensure the device is not already open
    if (forensic1394_device_is_open(dev))
    {
        return 0;
    }

    // Try to open the device
    ret = platform_open_device(dev);

    // If successful mark the device as open
    if (ret)
    {
        dev->isOpen = 1;
    }

    return ret;
}

void forensic1394_close_device(forensic1394_dev *dev)
{
    assert(dev);

    // Ensure the device is open
    if (!forensic1394_device_is_open(dev))
    {
        return;
    }

    platform_close_device(dev);

    // The device is now closed
    dev->isOpen = 0;
}

int forensic1394_read_device(forensic1394_dev *dev,
                             uint64_t addr,
                             size_t len,
                             void *buf)
{
    assert(dev);

    // Mask the top 16-bits of the address
    addr &= 0x0000ffffffffffffULL;

    return platform_read_device(dev, addr, len, buf);
}

int forensic1394_write_device(forensic1394_dev *dev,
                              uint64_t addr,
                              size_t len,
                              void *buf)
{
    assert(dev);

    // Mask the top 16-bits of the address
    addr &= 0x0000ffffffffffffULL;

    return platform_write_device(dev, addr, len, buf);
}

void forensic1394_get_device_csr(forensic1394_dev *dev, uint32_t *rom)
{
    assert(dev);
    assert(rom);

    memcpy(rom, dev->rom, sizeof(dev->rom));
}

uint16_t forensic1394_get_device_nodeid(forensic1394_dev *dev)
{
    assert(dev);

    return dev->nodeid;
}

int forensic1394_device_is_open(forensic1394_dev *dev)
{
    assert(dev);

    return dev->isOpen;
}

const char *forensic1394_get_device_product_name(forensic1394_dev *dev)
{
    assert(dev);

    return dev->product_name;
}

int forensic1394_get_device_product_id(forensic1394_dev *dev)
{
    assert(dev);

    return dev->product_id;
}

const char *forensic1394_get_device_vendor_name(forensic1394_dev *dev)
{
    assert(dev);

    return dev->vendor_name;
}

int forensic1394_get_device_vendor_id(forensic1394_dev *dev)
{
    assert(dev);

    return dev->vendor_id;
}

void forensic1394_destroy_all_devices(forensic1394_bus *bus)
{
    int i;

    assert(bus);

    for (i = 0; i < bus->ndev; i++)
    {
        // First, close the device if it is open
        if (forensic1394_device_is_open(bus->dev[i]))
        {
            forensic1394_close_device(bus->dev[i]);
        }

        // Next call the platform specific destruction routine
        platform_device_destroy(bus->dev[i]);

        // Finally, free the general device structure (everything is static)
        free(bus->dev[i]);
    }

    // Free the device list itself (may be NULL, but still okay)
    free(bus->dev);

    bus->dev = NULL;
    bus->ndev = 0;
    bus->size = 0;
}
