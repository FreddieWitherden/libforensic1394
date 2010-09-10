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

#include "common.h"

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/ioctl.h>
#include <linux/firewire-cdev.h>

#include <unistd.h>
#include <fcntl.h>

#include <glob.h>

#include <poll.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// The kernel ioctl structures store pointers as 64-bit integers
#define PTR_TO_U64(p) ((__u64)(intptr_t)(p))
#define U64_TO_PTR(p) ((void *)(intptr_t)(p))

/*
 * These constants come from linux/drivers/firewire/fw-device.h and are used
 * as the `key' field when adding a local unit directory.
 */
#define CSR_DIRECTORY   0xc0
#define CSR_UNIT        0x11

/**
 * The size of the request pipeline.  This determines how many asynchronous
 *  requests can be in the pipeline at any one time.  Due to serious bugs in
 *  current kernels (at least up to 2.6.35) this is currently limited to 1.
 */
#define REQUEST_PIPELINE_SZ 1

struct _platform_bus
{
    int sbp2_fd;
};

struct _platform_dev
{
    char path[64];
    int fd;
};

static forensic1394_dev *alloc_dev(const char *devpath,
                                   const struct fw_cdev_get_info *info,
                                   const struct fw_cdev_event_bus_reset *reset);

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

/**
 * Returns the most suitable TCODE for a given request.  Requests with a length
 *  of 4-bytes should be QUADLET requests while everything else should use
 *  BLOCK requests.
 */
static inline int request_tcode(const forensic1394_req* r, request_type t);

/**
 * Generic request-issuing function which can be used to make either read/write
 *  requests depending on the value of \a t.
 */
static forensic1394_result send_requests(forensic1394_dev *dev,
                                         request_type t,
                                         const forensic1394_req *req,
                                         size_t nreq);

platform_bus *platform_bus_alloc(void)
{
    platform_bus *pbus = malloc(sizeof(platform_bus));

    pbus->sbp2_fd = -1;

    return pbus;
}

void platform_bus_destory(forensic1394_bus *bus)
{
    // If the SBP-2 unit directory is enabled close its fd
    if (bus->sbp2_enabled)
    {
        assert(bus->pbus->sbp2_fd != -1);

        close(bus->pbus->sbp2_fd);
    }

    free(bus->pbus);
}

forensic1394_result platform_enable_sbp2(forensic1394_bus *bus,
                                         const uint32_t *sbp2dir, size_t len)
{
    int i;
    int perm_skipped = 0;

    forensic1394_result ret = FORENSIC1394_RESULT_SUCCESS;

    glob_t globdev;

    assert(bus->pbus->sbp2_fd == -1);

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
            // Make a note if the problem is permission related
            if (errno == EACCES)
            {
                perm_skipped++;
            }

            // Not fatal; continue
            continue;
        }

        // Fill out an info request
        get_info.version = FW_CDEV_VERSION;
        get_info.bus_reset = PTR_TO_U64(&reset);

        // Send the request (really should not fail)
        if (ioctl(fd, FW_CDEV_IOC_GET_INFO, &get_info) == -1)
        {
            continue;
        }

        // See if the node is local to the system
        if (reset.node_id == reset.local_node_id)
        {
            // We've found what we need; save and break (but do not close)
            bus->pbus->sbp2_fd = fd;
            break;
        }

        // Close the device
        close(fd);
    }

    globfree(&globdev);

    // If we got a valid local file descriptor use it to update the CSR
    if (bus->pbus->sbp2_fd != -1)
    {
        struct fw_cdev_add_descriptor add_desc = {};

        add_desc.data   = PTR_TO_U64(sbp2dir);
        add_desc.length = len;
        add_desc.key    = (CSR_DIRECTORY | CSR_UNIT) << 24;

        // Attempt to add the SBP-2 unit directory
        if (ioctl(bus->pbus->sbp2_fd, FW_CDEV_IOC_ADD_DESCRIPTOR, &add_desc) == -1)
        {
            close(bus->pbus->sbp2_fd);
            bus->pbus->sbp2_fd = -1;

            ret = FORENSIC1394_RESULT_IO_ERROR;
        }
    }
    // We didn't get a valid descriptor and were forced to skip some devices
    else if (perm_skipped > 0)
    {
        ret = FORENSIC1394_RESULT_NO_PERM;
    }
    // Something else is awry
    else
    {
        ret = FORENSIC1394_RESULT_IO_ERROR;
    }

    return ret;
}

forensic1394_result platform_update_device_list(forensic1394_bus *bus)
{
    int i;
    int perm_skipped = 0;
    forensic1394_result ret = FORENSIC1394_RESULT_SUCCESS;

    glob_t globdev;

    // Glob the available firewire devices attached to the system
    glob("/dev/fw*", 0, NULL, &globdev);

    for (i = 0; i < globdev.gl_pathc; i++)
    {
        const char *devpath = globdev.gl_pathv[i];
        struct fw_cdev_get_info get_info = {};
        struct fw_cdev_event_bus_reset reset = {};
        uint32_t rom[FORENSIC1394_CSR_SZ];

        // Open up the device
        int fd = open(devpath, O_RDWR);

        // Ensure the device was opened
        if (fd == -1)
        {
            // See if the failure was due to a permissions problem
            if (errno == EACCES)
            {
                perm_skipped++;
            }

            // Not fatal; continue
            continue;
        }

        // Fill out an info request
        get_info.version    = FW_CDEV_VERSION;
        get_info.rom        = PTR_TO_U64(rom);
        get_info.rom_length = sizeof(rom);
        get_info.bus_reset  = PTR_TO_U64(&reset);

        // Send the request
        if (ioctl(fd, FW_CDEV_IOC_GET_INFO, &get_info) == -1)
        {
            perror("Get info ioctl");
        }

        // See if the node is foreign (we only want attached devices)
        if (reset.node_id != reset.local_node_id)
        {
            // Allocate a new device
            forensic1394_dev *currdev = alloc_dev(devpath,
                                                  &get_info,
                                                  &reset);

            // Save a reference to the bus
            currdev->bus = bus;

            // See if we need to extend the device list; +1 as the last device
            // is always NULL, hence taking up a slot
            if (bus->ndev + 1 == bus->size)
            {
                bus->size += FORENSIC1394_DEV_LIST_SZ;
                bus->dev = realloc(bus->dev, sizeof(forensic1394_dev *) * bus->size);
            }

            // Add this new device to the device list
            bus->dev[bus->ndev++] = currdev;
        }

        // Close the device (it may be opened up later)
        close(fd);
    }

    globfree(&globdev);

    // If we found no devices but were forced to skip some due to permission-
    // related errors then return FORENSIC1394_RESULT_NO_PERM.
    if (bus->ndev == 0 && perm_skipped > 0)
    {
        ret = FORENSIC1394_RESULT_NO_PERM;
    }

    return ret;
}

void platform_device_destroy(forensic1394_dev *dev)
{
    // Just free the platform specific memory
    free(dev->pdev);
}

forensic1394_result platform_open_device(forensic1394_dev *dev)
{
    dev->pdev->fd = open(dev->pdev->path, O_RDWR);

    if (dev->pdev->fd == -1)
    {
        /*
         * Return a general I/O error here as it is unlikely to be permission
         * related on account of the device previously being opened in a similar
         * way during the scanning process.
         */
        return FORENSIC1394_RESULT_IO_ERROR;
    }
    else
    {
        return FORENSIC1394_RESULT_SUCCESS;
    }
}

void platform_close_device(forensic1394_dev *dev)
{
    close(dev->pdev->fd);
}

forensic1394_result platform_read_device_v(forensic1394_dev *dev,
                                           forensic1394_req *req,
                                           size_t nreq)
{
    return send_requests(dev, REQUEST_TYPE_READ, req, nreq);
}

forensic1394_result platform_write_device_v(forensic1394_dev *dev,
                                            const forensic1394_req *req,
                                            size_t nreq)
{
    return send_requests(dev, REQUEST_TYPE_WRITE, req, nreq);
}

forensic1394_dev *alloc_dev(const char *devpath,
                            const struct fw_cdev_get_info *info,
                            const struct fw_cdev_event_bus_reset *reset)
{
    char tmp[128];

    // Allocate memory for a device (calloc initialises to 0)
    forensic1394_dev *dev = calloc(1, sizeof(forensic1394_dev));

    // And for the platform-specific stuff
    dev->pdev = malloc(sizeof(platform_dev));

    // Copy the device path into the platform specific structure
    strncpy(dev->pdev->path, devpath, sizeof(dev->pdev->path));

    // Mark the file descriptor as invalid
    dev->pdev->fd = -1;

    // Copy the ROM over (this comes from an ioctl as opposed to sysfs)
    memcpy(dev->rom, U64_TO_PTR(info->rom), info->rom_length);

    // Same with the node ID and generation
    dev->nodeid     = reset->node_id;
    dev->generation = reset->generation;

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

    // GUID
    read_fw_sysfs_prop(devpath, "guid", tmp, sizeof(tmp));
    dev->guid = strtoll(tmp, NULL, 0);

    return dev;
}

void read_fw_sysfs_prop(const char *devpath, const char *prop,
                        char *contents, size_t maxb)
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

    // Zero the contents (ensures termination no matter what)
    memset(contents, '\0', maxb);

    // Open the file for reading
    fd = open(sysfspath, O_RDONLY);

    // Unable to open the property; usually because it does not exist
    if (fd == -1)
    {
        return;
    }

    // Read the contents
    actualb = read(fd, contents, maxb);


    if (actualb > 0 && contents[actualb - 1] == '\n')
    {
        // The last character should be a \n; replace with a nul
        contents[actualb - 1] = '\0';
    }

    close(fd);
}

static int request_tcode(const forensic1394_req *r, request_type t)
{
    if (t == REQUEST_TYPE_READ)
    {
        return (r->len == 4) ? TCODE_READ_QUADLET_REQUEST
                             : TCODE_READ_BLOCK_REQUEST;
    }
    else
    {
        return (r->len == 4) ? TCODE_WRITE_QUADLET_REQUEST
                             : TCODE_WRITE_BLOCK_REQUEST;
    }
}

forensic1394_result send_requests(forensic1394_dev *dev, request_type t,
                                  const forensic1394_req *req,
                                  size_t nreq)
{
    int i = 0;
    int in_pipeline = 0;

    struct pollfd fdp = {
        .fd     = dev->pdev->fd,
        .events = POLLIN
    };

    // Keep going until all requests have been sent and all responses received
    while (i < nreq || in_pipeline > 0)
    {
        // Ensure the request pipeline is full
        while (in_pipeline < REQUEST_PIPELINE_SZ && i < nreq)
        {
            struct fw_cdev_send_request request;

            // Fill out the common request structure
            request.tcode       = request_tcode(&req[i], t);
            request.length      = req[i].len;
            request.offset      = req[i].addr;
            request.data        = (t == REQUEST_TYPE_WRITE) ? PTR_TO_U64(req[i].buf)
                                                            : 0;
            request.closure     = i;
            request.generation  = dev->generation;

            // Make the request
            if (ioctl(dev->pdev->fd, FW_CDEV_IOC_SEND_REQUEST, &request) == -1)
            {
                // EIO errors are usually because of bad request sizes
                return (errno == EIO) ? FORENSIC1394_RESULT_IO_SIZE
                                      : FORENSIC1394_RESULT_IO_ERROR;
            }

            i++; in_pipeline++;
        }

        // Wait for a response
        poll(&fdp, 1, FORENSIC1394_TIMEOUT_MS);

        // If we got a response (and not a timeout)
        if (fdp.revents == POLLIN)
        {
            char buffer[16 * 1024];
            ssize_t response_len;
            union fw_cdev_event *event = (void *) buffer;

            // Read an event from the device; blocking if need be
            response_len = read(dev->pdev->fd, buffer, 16*1024);

            if (response_len != -1) switch (event->common.type)
            {
                // We have a response to our request (input or output)
                case FW_CDEV_EVENT_RESPONSE:
                {
                    // Check the response code
                    switch (event->response.rcode)
                    {
                        // Request was okay; continue processing
                        case RCODE_COMPLETE:
                            break;
                        case RCODE_BUSY:
                            return FORENSIC1394_RESULT_BUSY;
                            break;
                        // Different generations are a consequence of bus resets
                        case RCODE_GENERATION:
                            return FORENSIC1394_RESULT_BUS_RESET;
                            break;
                        default:
                            return FORENSIC1394_RESULT_IO_ERROR;
                            break;
                    }

                    // If we are expecting some data
                    if (t == REQUEST_TYPE_READ)
                    {
                        // Check the lengths match (they should!)
                        if (event->response.length == req[event->common.closure].len)
                        {
                            memcpy(req[event->common.closure].buf,
                                   event->response.data, event->response.length);
                        }
                        else
                        {
                            return FORENSIC1394_RESULT_IO_ERROR;
                        }
                    }

                    in_pipeline--;
                    break;
                }
                // Ignore everything else
                default:
                    break;
            }
            // Problem reading the response back from the device
            else
            {
                return FORENSIC1394_RESULT_IO_ERROR;
            }
        }
        // Poll timed out
        else
        {
            return FORENSIC1394_RESULT_IO_TIMEOUT;
        }
    }

    return FORENSIC1394_RESULT_SUCCESS;
}
