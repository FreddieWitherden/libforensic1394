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

/**
 * \mainpage Forensic1394
 *
 * The latest version of Forensic1394 can be found at:
 *      http://freddie.witherden.org/tools/forensic1394/
 *
 * This API gives you access to the firewire bus of contemporary operating
 *  systems in order to facilitate digital forensics on an attached device.
 *  Unlike existing APIs Forensic1394 is:
 *
 *   - Modern; unlike existing firewire libraries Forensic1394 supports the
 *      new `Juju' stack introduced in Linux 2.6.22.
 *   - Portable; with platform drivers existing for both Linux (Juju stack
 *      only) and Mac OS X (via I/O Kit).
 *   - Minimal; only functions required for performing digital forensics are
 *      provided.
 *
 * By omitting features not required in forensic applications (such as
 *  isochronous transfers) the API is both simple to use and port. For example
 *  the memory of an attached device can be read using the following code:
 *
 * \code
 * forensic1394_bus *bus; forensic1394_dev **dev; char data[512];
 *
 * bus = forensic1394_alloc(); assert(bus);
 *
 * forensic1394_enable_sbp2(bus);
 *
 * dev = forensic1394_get_devices(bus, NULL); assert(dev);
 *
 * forensic1394_open_device(dev[0]);
 *
 * forensic1394_read_device(dev[0], 50 * 1024 * 1024, 512, data);
 *
 * // Data now contains 512 bytes of memory starting at an offset of 50MiB
 *
 * forensic1394_close_device(dev[0]); forensic1394_destroy(bus);
 * \endcode
 *
 * \author Freddie Witherden
 */

#ifndef _FORENSIC_1394_H
#define _FORENSIC_1394_H

#if defined(FORENSIC1394_DECL)
    // No op
#elif defined(_MSC_VER)
#   define FORENSIC1394_DECL __declspec(dllexport)
#elif (__GNUC__ >= 3)
#   define FORENSIC1394_DECL __attribute__((visibility("default")))
#else
#   define FORENSIC1394_DECL
#endif

#include <stdlib.h>
#include <stdint.h>

typedef struct _forensic1394_bus forensic1394_bus;

typedef struct _forensic1394_dev forensic1394_dev;

/**
 * Allocates and initialises a new handle to the systems firewire
 * bus. This bus can then be used to query the devices attached to the
 * bus and to update the configuration status ROM (`CSR') of the bus.
 *
 * @return A handle to a forensic1394_bus on success, NULL otherwise.
 */
FORENSIC1394_DECL forensic1394_bus *
forensic1394_alloc(void);

/**
 * Updates the configuration status ROM of the bus to contain an SBP-2
 * unit directory. This is required in order for some connected
 * devices to allow for direct memory access (`DMA').
 *
 * Note that this is usually a global change, affecting all firewire
 * ports on the system.
 *
 * As calling this method usually results in a bus reset it is advisable to
 * call it as soon as a bus is available.
 *
 * @param bus The 1394 bus to add the SBP-2 unit directory to.
 */
FORENSIC1394_DECL int
forensic1394_enable_sbp2(forensic1394_bus *bus);

/**
 * Gets the list of (foreign) devices attached to the firewire bus.
 *
 * The list of devices returned by this method is NULL terminated, making it
 * possible to iterate over the list with a while loop.
 */
FORENSIC1394_DECL forensic1394_dev **
forensic1394_get_devices(forensic1394_bus *bus,
                         int *ndev);

/**
 * Destroys a bus handle, releasing all of the memory associated with
 * the handle.
 *
 * After a call to this method all forensic1394 device handles are
 * invalidated.
 *
 * @param bus The forensic1394_bus to destroy.
 */
FORENSIC1394_DECL void
forensic1394_destroy(forensic1394_bus *bus);

/**
 * Attempts to open up the firewire device dev. It is necessary to open a
 * device before attempting to read/write from it.
 *
 * @param dev The device to open.
 * @return True if the device was successfully opened; false otherwise.
 */
FORENSIC1394_DECL int
forensic1394_open_device(forensic1394_dev *dev);

/**
 * Closes the firewire device dev. This can only be called on an open device.
 *
 * @param dev The device to close.
 */
FORENSIC1394_DECL void
forensic1394_close_device(forensic1394_dev *dev);

/**
 * Determines if the firewire device dev is open or not.
 *
 * @param dev The firewire device.
 * @return True if the device is open; false otherwise.
 */
FORENSIC1394_DECL int
forensic1394_device_is_open(forensic1394_dev *dev);

/**
 * Performs a blocking (synchronous) read on the device dev, starting at the
 * address addr and attempting to read len bytes. The resulting bytes are copied
 * into buf.
 *
 * It is worth noting that many devices impose a limit on the maximum transfer
 * size. 512 bytes is usually a safe bet, however, YMMV.
 *
 * @param dev The firewire device.
 * @param addr The memory address to read from.
 * @param len The number of bytes to read.
 * @param buf The buffer to copy the read bytes into, must be at least len in
 *            size.
 * @return ...
 */
FORENSIC1394_DECL int
forensic1394_read_device(forensic1394_dev *dev,
                         uint64_t addr,
                         size_t len,
                         void *buf);

FORENSIC1394_DECL int
forensic1394_write_device(forensic1394_dev *dev,
                          uint64_t addr,
                          size_t len,
                          void *buf);

/**
 * Fetches the configuration status ROM (`csr') for the device and copies it
 * into ROM. rom is assumed to be at least 1024 bytes in size (256 entires).
 *
 * @param dev The device.
 * @param rom The pointer to copy the CSR into.
 */
FORENSIC1394_DECL void
forensic1394_get_device_csr(forensic1394_dev *dev,
                            uint32_t *rom);

FORENSIC1394_DECL uint16_t
forensic1394_get_device_nodeid(forensic1394_dev *dev);

FORENSIC1394_DECL const char *
forensic1394_get_device_product_name(forensic1394_dev *dev);

FORENSIC1394_DECL int
forensic1394_get_device_product_id(forensic1394_dev *dev);

FORENSIC1394_DECL const char *
forensic1394_get_device_vendor_name(forensic1394_dev *dev);

FORENSIC1394_DECL int
forensic1394_get_device_vendor_id(forensic1394_dev *dev);

#endif // _FORENSIC_1394_H
