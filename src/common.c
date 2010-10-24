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

#include "forensic1394.h"
#include "common.h"

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_E(a) (sizeof(a) / sizeof(*a))

/*
 * SBP-2 unit directory.  The entries are in the form <8-bit key><24-bit value>.
 *  Precise definitions of the keys and associated values can be found in the
 *  SBP-2 specification.
 *
 * The unit directory includes the number of entries and their CRC16 as the
 *  first element.  Platform APIs which do not require this (such as IOKit)
 *  should skip over this.
 */
static const uint32_t sbp2_unit_dir[] =
{
    0x000dc4fc,     // # entries (13 << 16) and CRC16
    0x1200609e,     // Spec ID
    0x13010483,     // Version
    0x21000001,     // Revision
    0x3a000a08,     // Unit char
    0x3e004c10,     // Fast start
    0x3800609e,     // Command set spec
    0x390104d8,     // SCSI
    0x3b000000,     // Command set rev
    0x3c0a2700,     // Firmware rev
    0x54004000,     // -->
    0x3d000003,     // Reconnect timeout
    0x140e0000,     // Logical unit number
    0x17000021      // Model
};

static const char *result_str[] =
{
    "Success",
    "General error",
    "Bus reset has occurred",
    "Insufficient permisisons",
    "Device is busy",
    "General I/O error",
    "Bad I/O request size",
    "I/O timeout"
};

static void forensic1394_destroy_all_devices(forensic1394_bus *bus);

forensic1394_bus *forensic1394_alloc(void)
{
    forensic1394_bus *b = malloc(sizeof(forensic1394_bus));

    if (!b)
    {
        return NULL;
    }

    // SBP-2 needs to be enabled explicitly
    b->sbp2_enabled = 0;

    // We have no devices (yet!)
    b->dev = NULL;
    b->dev_link = NULL;
    b->ndev = 0;

    // No ondestroy callback
    b->ondestroy = NULL;

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
    platform_bus_destroy(bus);

    // Free the bus
    free(bus);
}

void *forensic1394_get_bus_user_data(forensic1394_bus *bus)
{
    assert(bus);

    return bus->user_data;
}

void forensic1394_set_bus_user_data(forensic1394_bus *bus, void *u)
{
    assert(bus);

    bus->user_data = u;
}

forensic1394_result forensic1394_enable_sbp2(forensic1394_bus *bus)
{
    forensic1394_result ret;

    assert(bus);

    // Check that it is not already enabled
    if (bus->sbp2_enabled)
    {
        return 1;
    }

    ret = platform_enable_sbp2(bus, sbp2_unit_dir, ARRAY_E(sbp2_unit_dir));

    // If successful mark SBP-2 as being enabled
    if (ret == FORENSIC1394_RESULT_SUCCESS)
    {
        bus->sbp2_enabled = 1;
    }

    return ret;
}

forensic1394_dev **forensic1394_get_devices(forensic1394_bus *bus,
                                            int *ndev,
                                            forensic1394_device_callback ondestroy)
{
    int i = 0;

    forensic1394_result ret;
    forensic1394_dev *cdev;

    assert(bus);

    // Void the current device list, freeing any memory associated with it
    forensic1394_destroy_all_devices(bus);

    // Update the device list
    ret = platform_update_device_list(bus);

    // Allocate space for the device array and sentinel
    bus->dev = malloc(sizeof(forensic1394_dev *) * (bus->ndev + 1));

    // Copy the linked list of devices to the array
    for (cdev = bus->dev_link; cdev; cdev = cdev->next)
    {
	bus->dev[i++] = cdev;
    }

    // NULL terminate the last item in the list
    bus->dev[bus->ndev] = NULL;

    // If ndev was passed populate it with the number of devices
    if (ndev)
    {
        *ndev = (bus->ndev > 0) ? bus->ndev : ret;
    }

    // Save the ondestroy callback for later (may be NULL)
    bus->ondestroy = ondestroy;

    return bus->dev;
}

forensic1394_result forensic1394_open_device(forensic1394_dev *dev)
{
    forensic1394_result ret;

    assert(dev);

    // Ensure the device is not already open
    if (forensic1394_is_device_open(dev))
    {
        return FORENSIC1394_RESULT_SUCCESS;
    }

    // Try to open the device
    ret = platform_open_device(dev);

    // If successful mark the device as open
    if (ret == FORENSIC1394_RESULT_SUCCESS)
    {
        dev->is_open = 1;
    }

    return ret;
}

void forensic1394_close_device(forensic1394_dev *dev)
{
    assert(dev);

    // Ensure the device is open
    if (!forensic1394_is_device_open(dev))
    {
        return;
    }

    platform_close_device(dev);

    // The device is now closed
    dev->is_open = 0;
}

void *forensic1394_get_device_user_data(forensic1394_dev *dev)
{
    assert(dev);

    return dev->user_data;
}

void forensic1394_set_device_user_data(forensic1394_dev *dev, void *u)
{
    assert(dev);

    dev->user_data = u;
}

forensic1394_result forensic1394_read_device(forensic1394_dev *dev,
                                             uint64_t addr,
                                             size_t len,
                                             void *buf)
{
    forensic1394_req r;

    assert(dev);
    assert(dev->is_open);

    // Fill out a request structure
    r.addr  = addr;
    r.len   = len;
    r.buf   = buf;

    return platform_send_requests(dev, REQUEST_TYPE_READ, &r, 1);
}

forensic1394_result forensic1394_read_device_v(forensic1394_dev *dev,
                                               forensic1394_req *req,
                                               size_t nreq)
{
    assert(dev);
    assert(dev->is_open);
    assert(req);

    return platform_send_requests(dev, REQUEST_TYPE_READ, req, nreq);
}

forensic1394_result forensic1394_write_device(forensic1394_dev *dev,
                                              uint64_t addr,
                                              size_t len,
                                              void *buf)
{
    forensic1394_req r;

    assert(dev);
    assert(dev->is_open);

    // Fill out a request structure
    r.addr  = addr;
    r.len   = len;
    r.buf   = buf;

    return platform_send_requests(dev, REQUEST_TYPE_WRITE, &r, 1);
}

forensic1394_result forensic1394_write_device_v(forensic1394_dev *dev,
                                                const forensic1394_req *req,
                                                size_t nreq)
{
    assert(dev);
    assert(dev->is_open);

    return platform_send_requests(dev, REQUEST_TYPE_WRITE, req, nreq);
}

void forensic1394_get_device_csr(forensic1394_dev *dev, uint32_t *rom)
{
    assert(dev);
    assert(rom);

    memcpy(rom, dev->rom, sizeof(dev->rom));
}

uint16_t forensic1394_get_device_node_id(forensic1394_dev *dev)
{
    assert(dev);

    return dev->node_id;
}

int64_t forensic1394_get_device_guid(forensic1394_dev *dev)
{
    assert(dev);

    return dev->guid;
}

int forensic1394_is_device_open(forensic1394_dev *dev)
{
    assert(dev);

    return dev->is_open;
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

int forensic1394_get_device_request_size(forensic1394_dev *dev)
{
    assert(dev);

    return dev->max_req;
}

void forensic1394_destroy_all_devices(forensic1394_bus *bus)
{
    forensic1394_dev *cdev, *ndev;

    assert(bus);

    for (cdev = bus->dev_link; cdev; cdev = ndev)
    {
	// Save a reference to the next device
	ndev = cdev->next;

        // First, close the device if it is open
        if (forensic1394_is_device_open(cdev))
        {
            forensic1394_close_device(cdev);
        }

        // If a device-destroy callback is set; call it
        if (bus->ondestroy)
        {
            bus->ondestroy(bus, cdev);
        }

        // Next call the platform specific destruction routine
        platform_device_destroy(cdev);

        // Finally, free the general device structure (everything is static)
        free(cdev);
    }

    // Free the device list itself (may be NULL, but still okay)
    free(bus->dev);

    bus->dev = NULL;
    bus->dev_link = NULL;
    bus->ndev = 0;
}

const char *forensic1394_get_result_str(forensic1394_result r)
{
    // Check the result is valid
    if (r <= 0 && r > FORENSIC1394_RESULT_END)
    {
        return result_str[-r];
    }
    // Invalid
    else
    {
        return NULL;
    }
}
