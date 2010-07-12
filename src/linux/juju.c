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

#include "common.h"

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <linux/firewire-cdev.h>

#include <unistd.h>
#include <fcntl.h>

#include <glob.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// The kernel ioctl structures store pointers as 64-bit integers
#define PTR_TO_U64(p) ((__u64)(p))
#define U64_TO_PTR(p) ((void *)(__u64)(p)

/*
 * These constants come from linux/drivers/firewire/fw-device.h and are used
 * as the `key' field when adding a local unit directory.
 */
#define CSR_DIRECTORY   0xc0
#define CSR_UNIT        0x11

struct _platform_bus
{
    int sbp2_fd;
};

struct _platform_dev
{
    char path[64];
    int fd;
    int generation;
};

static forensic1394_dev *alloc_dev(const char *devpath,
                                   uint32_t nodeid, uint32_t generation,
                                   const uint32_t *rom);

/**
 * Attempts to read a firewire sysfs property for the firewire device specified
 *  by devpath.  The file is read and copied as a NUL-terminated string to
 *  contents, with a maximum of maxb bytes being copied. The trailing \n is
 *  stripped (and replaced with a NUL byte).
 *
 * devpath should be of the form /dev/fw<n>, where n is an integer.  The
 *  device name (fw<n>) is extracted from this and used to form the full sysfs
 *  path:
 *    /sys/bus/firewire/devices/fw<n>/<prop>
 */
static void read_fw_sysfs_prop(const char *devpath, const char *prop,
                               char *contents, size_t maxb);

static int send_request(forensic1394_dev *dev,
                        int tcode,
                        uint64_t addr,
                        size_t inlen, void *in,
                        size_t outlen, void *out);

platform_bus *platform_bus_alloc(void)
{
    platform_bus *pbus = malloc(sizeof(platform_bus));

    pbus->sbp2_fd = -1;

    return pbus;
}

void platform_bus_destory(forensic1394_bus *bus)
{
    // If the SBP-2 unit directory is enabled close its fd
    if (bus->sbp2Enabled)
    {
        assert(bus->pbus->sbp2_fd != -1);

        close(bus->pbus->sbp2_fd);
    }

    free(bus->pbus);
}

int platform_enable_sbp2(forensic1394_bus *bus, const uint32_t *sbp2dir,
                         size_t len)
{
    int i;
    glob_t globdev;

    // In order to enable SBP-2 we first need a local node
    glob("/dev/fw*", 0, NULL, &globdev);

    for (i = 0; i < globdev.gl_pathc; i++)
    {
        struct fw_cdev_get_info get_info = {};
        struct fw_cdev_event_bus_reset reset = {};

        // Open up the device
        int fd = open(globdev.gl_pathv[i], O_RDWR);

        // Ensure the device was opened
        if (fd == -1)
        {
            // Not fatal; continue
            continue;
        }

        // Fill out an info request
        get_info.version = FW_CDEV_VERSION;
        get_info.bus_reset = PTR_TO_U64(&reset);

        // Send the request
        if (ioctl(fd, FW_CDEV_IOC_GET_INFO, &get_info) == -1)
        {
            perror("Get info ioctl");
        }

        // See if the node is local
        if (reset.node_id == reset.local_node_id)
        {
            struct fw_cdev_add_descriptor add_desc = {};

            add_desc.data   = PTR_TO_U64(sbp2dir);
            add_desc.length = len;
            add_desc.key    = (CSR_DIRECTORY | CSR_UNIT) << 24;

            if (ioctl(fd, FW_CDEV_IOC_ADD_DESCRIPTOR, &add_desc) == -1)
            {
                perror("Add descriptor ioctl");
            }

            // We're done, save the fd and break (ensuring not to close the fd)
            bus->pbus->sbp2_fd = fd;
            break;
        }

        // Close the device
        close(fd);
    }

    globfree(&globdev);

    // Successful if we have a valid fd
    return bus->pbus->sbp2_fd == -1;
}

void platform_update_device_list(forensic1394_bus *bus)
{
    int i;
    glob_t globdev;

    // Glob the available firewire devices attached to the system
    glob("/dev/fw*", 0, NULL, &globdev);

    for (i = 0; i < globdev.gl_pathc; i++)
    {
        const char *devpath = globdev.gl_pathv[i];
        struct fw_cdev_get_info get_info = {};
        struct fw_cdev_event_bus_reset reset = {};
        uint32_t rom[256];

        // Open up the device
        int fd = open(devpath, O_RDWR);

        // Ensure the device was opened
        if (fd == -1)
        {
            // Not fatal (usually perm related); continue
            continue;
        }

        // Fill out an info request
        get_info.version    = FW_CDEV_VERSION;
        get_info.rom        = PTR_TO_U64(rom);
        get_info.rom_length = 1024;
        get_info.bus_reset  = PTR_TO_U64(&reset);

        // Send the request
        if (ioctl(fd, FW_CDEV_IOC_GET_INFO, &get_info) == -1)
        {
            perror("Get info ioctl");
        }

        // See if the node is foreign (we only want attached devices)
        if (reset.node_id != reset.local_node_id)
        {
            // Allocate memory for the device
            forensic1394_dev *currdev = alloc_dev(devpath,
                                                  reset.node_id,
                                                  reset.generation,
                                                  rom);

            // See if we need to extend the device list; +1 as the last device
            // is always NULL, hence taking up a slot
            if (bus->ndev + 1 == bus->size)
            {
                bus->size += FORENSIC1394_DEV_LIST_SZ;
                bus->dev = realloc(bus->dev, sizeof(forensic1394_dev *) * bus->size);
            }

            currdev->bus = bus;

            // Add this new device to the device list
            bus->dev[bus->ndev++] = currdev;
        }

        // Close the device (it may be opened up later)
        close(fd);
    }

    globfree(&globdev);
}

void platform_device_destroy(forensic1394_dev *dev)
{
    // Just free the platform specific memory
    free(dev->pdev);
}

int platform_open_device(forensic1394_dev *dev)
{
    dev->pdev->fd = open(dev->pdev->path, O_RDWR);

    if (dev->pdev->fd == -1)
    {
        perror("Open device");
    }

    return dev->pdev->fd != -1;
}

void platform_close_device(forensic1394_dev *dev)
{
    close(dev->pdev->fd);
}

int platform_read_device(forensic1394_dev *dev,
                         uint64_t addr,
                         uint64_t len,
                         void *buf)
{
    int tcode = (len == 4) ? TCODE_READ_QUADLET_REQUEST
                           : TCODE_READ_BLOCK_REQUEST;

    return send_request(dev, tcode, addr, 0, NULL, len, buf);
}

int platform_write_device(forensic1394_dev *dev,
                          uint64_t addr,
                          size_t len,
                          void *buf)
{
    int tcode = (len == 4) ? TCODE_WRITE_QUADLET_REQUEST
                           : TCODE_WRITE_BLOCK_REQUEST;

    return send_request(dev, tcode, addr, len, buf, 0, NULL);
}

forensic1394_dev *alloc_dev(const char *devpath,
                            uint32_t node_id, uint32_t generation,
                            const uint32_t *rom)
{
    char tmp[128];

    // Allocate memory for a device
    forensic1394_dev *dev = malloc(sizeof(forensic1394_dev));

    // And for the platform-specific stuff
    dev->pdev = malloc(sizeof(platform_dev));

    // Copy the device path into the platform specific structure
    strncpy(dev->pdev->path, devpath, sizeof(dev->pdev->path));

    // Mark the file descriptor as invalid
    dev->pdev->fd = -1;

    // The device is not open-by-default
    dev->isOpen = 0;

    // Copy the ROM over (this comes from an ioctl as opposed to sysfs)
    memcpy(dev->rom, rom, sizeof(dev->rom));

    // Same with the node ID and generation
    dev->nodeid = node_id;
    dev->pdev->generation = generation;

    // Product name
    read_fw_sysfs_prop(devpath, "model_name",
                       dev->product_name, sizeof(dev->product_name));

    // Product ID
    read_fw_sysfs_prop(devpath, "model", tmp, sizeof(tmp));
    dev->product_id = strtol(tmp, NULL, 0);

    // Vendor name
    read_fw_sysfs_prop(devpath, "vendor_name",
                       dev->vendor_name, sizeof(dev->vendor_name));

    // Vendor ID
    read_fw_sysfs_prop(devpath, "vendor", tmp, sizeof(tmp));
    dev->vendor_id = strtol(tmp, NULL, 0);

    return dev;
}

void read_fw_sysfs_prop(const char* devpath, const char* prop,
                        char* contents, size_t maxb)
{
    /*
     * The sysfs properties reside in /sys/bus/firewire/devices/fw<n>/<prop>;
     * when read they are presented as strings, ending with a \n. Hence to
     * extract the property it is necessary to find the complete path given
     * /dev/fw<n>; read the property into memry and nul-terminate it.
     */
    char sysfspath[128];
    int fd;
    ssize_t actualb;

    // devpath is of the form /dev/fw<n> => (devpath + 5) = fw<n>
    snprintf(sysfspath, sizeof(sysfspath), "/sys/bus/firewire/devices/%s/%s",
             devpath + 5, prop);

    // Open the file for reading
    fd = open(sysfspath, O_RDONLY);

    if (fd == -1)
    {
        perror("Open sysfs property");
        return;
    }

    // Zero the contents (ensures termination no matter what)
    memset(contents, '\0', maxb);

    // Read the contents
    actualb = read(fd, contents, maxb);


    if (actualb > 0 && contents[actualb - 1] == '\n')
    {
        // The last character should be a \n; replace with a nul
        contents[actualb - 1] = '\0';
    }

    close(fd);
}

int send_request(forensic1394_dev *dev,
                 int tcode,
                 uint64_t addr,
                 size_t inlen, void *in,
                 size_t outlen, void *out)
{
    struct fw_cdev_send_request request = {};
    size_t response_len;
    int done = 0;

    // Fill out the request structure
    request.tcode       = tcode;
    request.length      = MAX(inlen, outlen);
    request.offset      = addr;
    request.data        = PTR_TO_U64(in);
    request.closure     = 0;
    request.generation  = dev->pdev->generation;


    // Make the request
    if (ioctl(dev->pdev->fd, FW_CDEV_IOC_SEND_REQUEST, &request) == -1)
    {
        perror("Send request");
        return 0;
    }

    // Keep going until we get a response
    while (!done)
    {
        char buffer[16 * 1024];
        union fw_cdev_event *event = (void *) buffer;

        // Read the reponse to our request; blocking if need be
        response_len = read(dev->pdev->fd, buffer, 16*1024);

        if (response_len != -1) switch (event->common.type)
        {
            // We have a response to our request for data, copy it
            case FW_CDEV_EVENT_RESPONSE:
            {
                if (out)
                {
                    memcpy(out, event->response.data, outlen);
                }

                done = 1;
                break;
            }
            default:
                break;
        }
        else
        {
            perror("Read event");
            return 0;
        }
    }

    return 1;
}
