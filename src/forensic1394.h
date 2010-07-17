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

/**
 * \mainpage libforensic1394
 *
 * The latest version of libforensic1394 can be found at:
 *      http://freddie.witherden.org/tools/libforensic1394/
 *
 * This API gives you access to the firewire bus of contemporary operating
 *  systems in order to facilitate digital forensics on an attached device.
 *  Unlike existing APIs Forensic1394 is:
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
 * forensic1394_enable_sbp2(bus); sleep(2);
 *
 * dev = forensic1394_get_devices(bus, NULL, NULL); assert(dev);
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
 * \par Handling bus resets
 * Bus resets occur when devices are added/removed from the system or when the
 *  configuration ROM of a device is updated.  The following methods are
 *  affected by bus resets:
 *   - \c forensic1394_open_device
 *   - \c forensic1394_read_device
 *   - \c forensic1394_read_device
 *
 * \par
 * After a bus reset calls to all three of these methods will result in
 *  \c FORENSIC1394_RESULT_BUS_RESET being returned.  Applications should
 *  handle this by saving the GUIDs of any devices being accessed and then call
 *  \c forensic1394_get_devices.  Calling this will void all device handles.
 *  The new list of devices can then be iterated through and their GUIDs
 *  compared against saved GUIDs.
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

/// An opaque bus handle
typedef struct _forensic1394_bus forensic1394_bus;

/// An opaque device handle
typedef struct _forensic1394_dev forensic1394_dev;

/**
 * A function to be called when a \c forensic1394_dev is about to be destroyed.
 *  This should be passed to \c forensic1394_get_devices and will be associated
 *  with all devices returned by the method.  The callback will fire either when
 *  the bus is destroyed via \c forensic1394_destroy or the next time that
 *  \c forensic1394_get_devices is called (which has the implicit effect of
 *  destroying all existing devices first).
 *
 * If user data is required it can be attached on either a per-bus or per-device
 *  level.
 *
 *   \param bus The bus owning the device.
 *   \param dev The device being destroyed.
 *
 * \sa forensic1394_bus_set_user_data
 * \sa forensic1394_device_set_user_data
 */
typedef void (*forensic1394_device_callback) (forensic1394_bus *bus,
                                              forensic1394_dev *dev);

/**
 * \brief Possible return status codes.
 *
 * The possible return codes for a forensic1394 function.  In general methods
 *  return 0 on success and a negative integer on failure.  These codes may be
 *  used to ascertain precisely why a method failed.
 *
 * It is worth noting that invalid input parameters are handled with assertions
 *  as opposed to status codes.
 *
 * \sa forensic1394_get_result_str
 */
typedef enum
{
    /// No errors encountered
    FORENSIC1394_RESULT_SUCCESS     = 0,
    /// General, unspecified, error
    FORENSIC1394_RESULT_OTHER_ERROR = -1,
    /// A bus reset has occured
    FORENSIC1394_RESULT_BUS_RESET   = -2,
    /// Permissions related error
    FORENSIC1394_RESULT_NO_PERM     = -3,
    /// Device is busy
    FORENSIC1394_RESULT_BUSY        = -4,
    /// General I/O error
    FORENSIC1394_RESULT_IO_ERROR    = -5,
    /// Bad transfer size (normally too large)
    FORENSIC1394_RESULT_IO_SIZE     = -6,
    /// Sentinel; internal use only
    FORENSIC1394_RESULT_END         = -7
} forensic1394_result;

/**
 * \brief Allocates a new forensic1394 handle.
 *
 * Allocates and initialises a new handle to the systems firewire bus.  This bus
 *  can then be used to query the devices attached to the bus and to update the
 *  configuration status ROM (`CSR') of the bus.
 *
 *  \return A handle to a forensic1394_bus on success, NULL otherwise.
 */
FORENSIC1394_DECL forensic1394_bus *forensic1394_alloc(void);

/**
 * \brief Provides an SBP-2 unit directory; required for DMA to Windows systems.
 *
 * Updates the configuration status ROM of the bus to contain an SBP-2
 *  unit directory.  This is required in order for some connected
 *  devices to allow for direct memory access (`DMA').
 *
 * Note that this is usually a global change, affecting all firewire
 *  ports on the system.
 *
 * As calling this method usually results in a bus reset it is advisable to
 *  call it as soon as a bus is available.
 *
 *   \param bus The 1394 bus to add the SBP-2 unit directory to.
 *  \return A result status code.
 */
FORENSIC1394_DECL forensic1394_result
forensic1394_enable_sbp2(forensic1394_bus *bus);

/**
 * \brief Gets the devices attached to the firewire bus.
 *
 * This method scans the (foreign) devices attached to \a bus and returns a
 *  NULL-terminated list of them.
 *
 * The out-parameter \a ndev, if not NULL, serves a dual purpose.  After a call
 *  to the function if \c *ndev is:
 *
 *   - >= 0 then the call was successful and it contains the number of devices
 *      attached to the system, which may be 0 if no devices are attached.
 *   - < 0 then the call was not successful and it contains the appropriate
 *      \a forensic1394_result error code.
 *
 * Getting the attached devices is a destructive process; voiding any existing
 *  device handles.  To compensate for this the \a ondestroy callback is
 *  provided.  This argument, if not NULL, will be called when the new device
 *  list is destroyed, usually as a result of a subsequent call to
 *  \c forensic1394_get_devices or a call to \c forensic1394_destroy.  The
 *  function is called for each device in the list.
 *
 * \warning Calling this method will invalidate all active device handles.
 *
 *   \param bus The bus to get the devices for.
 *   \param[out] ndev The number of devices found; NULL is acceptable.
 *   \param[in] ondestroy Function to be called when the returned device list is
 *                         destroyed; NULL for no callback.
 *  \return A NULL-terminated list of devices.
 *
 * \sa forensic1394_device_callback
 * \sa forensic1394_result
 */
FORENSIC1394_DECL forensic1394_dev **
forensic1394_get_devices(forensic1394_bus *bus,
                         int *ndev,
                         forensic1394_device_callback ondestroy);

/**
 * \brief Destroys a bus handle.
 *
 * Destroys a bus handle, releasing all of the memory associated with
 *  the handle.
 *
 * After a call to this method all forensic1394 device handles are
 *  invalidated.
 *
 *  \param bus The forensic1394_bus to destroy.
 */
FORENSIC1394_DECL void
forensic1394_destroy(forensic1394_bus *bus);

/**
 * \brief Fetches the user data for \a bus.
 *
 * Returns the user data for \a bus.  If \c forensic1394_set_bus_user_data is
 *  yet to be called on the bus the result is undefined.
 *
 *   \param bus The bus.
 *  \return The user data associated with the bus.
 *
 * \sa forensic1394_set_bus_user_data
 */
FORENSIC1394_DECL void *
forensic1394_get_bus_user_data(forensic1394_bus *bus);

/**
 * \brief Sets the user data for the bus.
 *
 * Sets the user data for \a bus to \a u.
 *
 *   \param bus The bus.
 *   \param[in] u The user data to set.
 *
 * \sa forensic1394_get_bus_user_data
 */
FORENSIC1394_DECL void
forensic1394_set_bus_user_data(forensic1394_bus *bus, void *u);

/**
 * \brief Opens the device \a dev for reading/writing.
 *
 * Attempts to open up the firewire device dev.  It is necessary to open a
 *  device before attempting to read/write from it.
 *
 *   \param dev The device to open.
 *  \return A result status code.
 */
FORENSIC1394_DECL forensic1394_result
forensic1394_open_device(forensic1394_dev *dev);

/**
 * \brief Closes the device \a dev.
 *
 * Closes the firewire device \a dev.  This can only be called on an open
 *  device.
 *
 *   \param dev The device to close.
 */
FORENSIC1394_DECL void
forensic1394_close_device(forensic1394_dev *dev);

/**
 * \brief Checks if a device is open or not.
 *
 * Determines if the firewire device dev is open or not.
 *
 *   \param dev The firewire device.
 *  \return Non-zero if the device is open; 0 if it is closed.
 */
FORENSIC1394_DECL int
forensic1394_is_device_open(forensic1394_dev *dev);

/**
 * \brief Reads \a len bytes from \a dev starting at \a addr into \a buf.
 *
 * Performs a blocking (synchronous) read on the device \a dev, starting at the
 *  address \a addr and attempting to read \a len bytes.  The resulting bytes
 *  are copied inton \a buf.
 *
 * It is worth noting that many devices impose a limit on the maximum transfer
 *  size.  This limit can be obtained by parsing the CSR, however, it is usually
 *  at least 2048-bytes in size.  As there is currently not support for
 *  parsing the CSR an heuristic algorithm is used to determine if the transfer
 *  size is at fault.
 *
 *   \param dev The device to read from.
 *   \param addr The memory address to start reading from.
 *   \param len The number of bytes to read.
 *   \param[out] buf The buffer to copy the read bytes into; must be at least
 *                   \a len bytes in size.
 *  \return A result status code.
 */
FORENSIC1394_DECL forensic1394_result
forensic1394_read_device(forensic1394_dev *dev,
                         uint64_t addr,
                         size_t len,
                         void *buf);

/**
 * \brief Writes \a len bytes from \a buf to \a dev starting at \a addr.
 *
 * Performs a blocking (synchronous) write on the device \a dev attempting to
 *  copy \a len bytes from \a buf to the device address \a addr.  See
 *  the documentation for \a forensic1394_read_device for a discussion on the
 *  maximum transfer size.
 *
 *   \param dev The device to write to.
 *   \param addr The memory address to start writing to.
 *   \param len The number of bytes to write.
 *   \param[in] buf The buffer to write.
 *  \return A result status code.
 */
FORENSIC1394_DECL forensic1394_result
forensic1394_write_device(forensic1394_dev *dev,
                          uint64_t addr,
                          size_t len,
                          void *buf);

/**
 * \brief Copies the configuration ROM for the device \a dev into \a rom.
 *
 * Fetches the configuration status ROM (`csr') for the device and copies it
 *  into ROM. rom is assumed to be at least 1024 bytes in size (256 entires).
 *
 *   \param dev The device.
 *   \param rom The pointer to copy the CSR into.
 */
FORENSIC1394_DECL void
forensic1394_get_device_csr(forensic1394_dev *dev,
                            uint32_t *rom);

/**
 * \brief Returns the node ID of the device.
 *
 * Returns the node ID of the device \a dev.  It is important to note that this
 *  value does not remain constant across bus resets and is hence unsuitable
 *  for device identification.
 *
 *   \param dev The device.
 *  \return The node ID of the device.
 */
FORENSIC1394_DECL uint16_t
forensic1394_get_device_nodeid(forensic1394_dev *dev);

/**
 * \brief Returns the product name of the device, if any.
 *
 * Returns the product name of the device \a dev.  Should the property not
 *  exist for the device an empty string ("") is returned.  The string is
 *  guaranteed to remain valid for the lifetime of the device.
 *
 *   \param dev The device.
 *  \return The product name of the device, if any.
 */
FORENSIC1394_DECL const char *
forensic1394_get_device_product_name(forensic1394_dev *dev);

/**
 * \brief Returns the product ID of the device, if any.
 *
 * Returns the product ID of the device \a dev.  Should the property not exist
 *  then 0 is returned.
 *
 *   \param dev The device.
 *  \return The product ID of the device, or 0 if it is not defined.
 */
FORENSIC1394_DECL int
forensic1394_get_device_product_id(forensic1394_dev *dev);

/**
 * \brief Returns the vendor name of the device, if any.
 *
 * Returns the vendor name of the device \a dev.  Should the property not
 *  exist for the device an empty string ("") is returned.  The string is
 *  guaranteed to remain valid for the lifetime of the device.
 *
 *   \param dev The device.
 *  \return The vendor name of the device, if any.
 */
FORENSIC1394_DECL const char *
forensic1394_get_device_vendor_name(forensic1394_dev *dev);

/**
 * \brief Returns the vendor ID of the device, if any.
 *
 * Returns the vendor ID of the device \a dev.  Should the property not exist
 *  then 0 is returned.
 *
 *   \param dev The device.
 *  \return The vendor ID of the device, or 0 if it is not defined.
 */
FORENSIC1394_DECL int
forensic1394_get_device_vendor_id(forensic1394_dev *dev);

/**
 * \brief Fetches the user data for the device \a dev.
 *
 * Returns the user data for \a dev.  If \c forensic1394_set_device_user_data is
 *  yet to be called on the device the result is undefined.
 *
 *   \param dev The device.
 *  \return The user data associated with the device.
 *
 * \sa forensic1394_set_device_user_data
 */
FORENSIC1394_DECL void *
forensic1394_get_device_user_data(forensic1394_dev *dev);

/**
 * \brief Sets the user data for the device \a dev.
 *
 * Sets the user data for \a device to \a u.
 *
 *   \param dev The device.
 *   \param[in] u The user data to set.
 *
 * \sa forensic1394_get_device_user_data
 */
FORENSIC1394_DECL void
forensic1394_set_device_user_data(forensic1394_dev *dev, void *u);

/**
 * \brief Converts a return status code to a string.
 *
 * Returns a textual representation of the return status code \a result.  The
 *  string returned is guarenteed to be valid for the lifetime of the program.
 *
 * In the event of an invalid code NULL is returned.
 *
 *   \param r The return status code.
 *  \return A description of the error code on success; NULL otherwise.
 */
FORENSIC1394_DECL const char *
forensic1394_get_result_str(forensic1394_result r);

#endif // _FORENSIC_1394_H
