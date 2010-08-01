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

#include <arpa/inet.h>  // For ntohl

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/firewire/IOFireWireLib.h>

/**
 * Requires that the \c IOReturn \a ret be equal to \c kIOReturnSuccess.
 *  Otherwise the \c forensic1394_result variable \a fret is set to the
 *  appropriate error code and a \c goto jump to \a label is made.
 *
 *  \param ret The return value to check.
 *  \param label The label to jump to if the check fails.
 *  \param fret The variable to place the corresponding forensic1394 error in.
 *
 * \sa require_assertion
 */
#define require_success(ret, label, fret) \
do                                        \
{                                         \
    if (ret != kIOReturnSuccess)          \
    {                                     \
        fret = convert_ioreturn(ret);     \
        goto label;                       \
    }                                     \
} while (0);

/**
 * Requires the assertion \a assertion be true.  Otherwise \a fret is set to
 * \a fretcode and a jump to \a label is made.
 *
 *   \param assertion The expression to check.
 *   \param label The label to jump to if the assertion is false.
 *   \param fret The local variable to copy \a fretcode into.
 *   \param fretcode The forensic1394 return code.
 *
 * \sa require_success
 */
#define require_assertion(assertion, label, fret, fretcode) \
do                                                          \
{                                                           \
    if (!(assertion))                                       \
    {                                                       \
        fret = fretcode;                                    \
        goto label;                                         \
    }                                                       \
} while (0);

struct _platform_bus
{
    IOFireWireLibDeviceRef localDev;
    IOFireWireLibLocalUnitDirectoryRef localUnitDir;
};

struct _platform_dev
{
    IOFireWireLibDeviceRef devIntrf;
    io_object_t dev;
};

/**
 * \brief Converts \a i into the closest matching \c forensic1394_result.
 *
 *   \param i The return value to convert.
 *  \return The corresponding \c forensic1394_result.
 */
static forensic1394_result convert_ioreturn(IOReturn i);

static void copy_device_property_string(io_registry_entry_t dev,
                                        CFStringRef prop,
                                        char *buf,
                                        size_t bufsiz);

static void copy_device_property_int(io_registry_entry_t dev,
                                     CFStringRef prop,
                                     void *num,
                                     CFNumberType type);

static void copy_device_property_int32(io_registry_entry_t dev,
                                       CFStringRef prop,
                                       int32_t *num);

static void copy_device_property_int64(io_registry_entry_t dev,
                                       CFStringRef prop,
                                       int64_t *num);

static void copy_device_property_csr(io_registry_entry_t dev,
                                     uint32_t *rom);

platform_bus *platform_bus_alloc()
{
    platform_bus *pbus = malloc(sizeof(platform_bus));

    pbus->localDev      = NULL;
    pbus->localUnitDir  = NULL;

    return pbus;
}

void platform_bus_destory(forensic1394_bus *bus)
{
    // Un-publish any changes we made to the CSR
    if (bus->sbp2_enabled)
    {
        assert(bus->pbus->localDev);
        assert(bus->pbus->localUnitDir);

        // Un-publish the changes and release the unit dir interface
        (*bus->pbus->localUnitDir)->Unpublish(bus->pbus->localUnitDir);
        (*bus->pbus->localUnitDir)->Release(bus->pbus->localUnitDir);

        // Close and release the device interface
        (*bus->pbus->localDev)->Close(bus->pbus->localDev);
        (*bus->pbus->localDev)->Release(bus->pbus->localDev);
    }

    // Free the platform bus structure
    free(bus->pbus);
}

forensic1394_result platform_enable_sbp2(forensic1394_bus *bus,
                                         const uint32_t *sbp2dir, size_t len)
{
    int i;

    CFMutableDictionaryRef matchingDict;

    io_iterator_t iterator;
    io_object_t currdev;

    IOCFPlugInInterface **plugIn;
    SInt32 theScore;    // Unused

    IOFireWireLibDeviceRef localDev;
    IOFireWireLibLocalUnitDirectoryRef localUnitDir;

    IOReturn iret;
    forensic1394_result fret = FORENSIC1394_RESULT_SUCCESS;

    // We need to get the systems local device node to update the CSR
    matchingDict = IOServiceMatching("IOFireWireLocalNode");
    iret = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                        matchingDict,
                                        &iterator);

    // If the call fails then we do not need to release the iterator
    require_success(iret, cleanupNull, fret);

    // There should only be one of these; so grab the first
    currdev = IOIteratorNext(iterator);

    // Get a plug-in interface to the device
    IOCreatePlugInInterfaceForService(currdev,
                                      kIOFireWireLibTypeID,
                                      kIOCFPlugInInterfaceID,
                                      &plugIn,
                                      &theScore);

    // Ensure plugIn is != NULL; otherwise this is a general error
    require_assertion(plugIn, cleanupCurrdev, fret, FORENSIC1394_RESULT_OTHER_ERROR);

    // Use this plug-in to get a firewire device interface
    iret = (*plugIn)->QueryInterface(plugIn,
                                     CFUUIDGetUUIDBytes(kIOFireWireDeviceInterfaceID_v9),
                                     (void **) &localDev);

    require_success(iret, cleanupPlugIn, fret);

    // Use this device interface to open up the device
    (*localDev)->Open(localDev);

    // And grab a unit local directory interface
    localUnitDir = (*localDev)->CreateLocalUnitDirectory(localDev,
                                                         CFUUIDGetUUIDBytes(kIOFireWireLocalUnitDirectoryInterfaceID));


    // Add the unit directory, ignoring the first entry
    for (i = 1; i < len; i++)
    {
        // The entries are passed as <8-bit key><24-bit value>
        UInt32 key      = sbp2dir[i] >> 24;
        UInt32 value    = sbp2dir[i] & 0x00ffffff;

        // Add the key-value pair to the local unit directory
        (*localUnitDir)->AddEntry_UInt32(localUnitDir, key, value, NULL);
    }

    // Publish this unit directory
    (*localUnitDir)->Publish(localUnitDir);

    // Save the interface references for later
    bus->pbus->localDev     = localDev;
    bus->pbus->localUnitDir = localUnitDir;

cleanupPlugIn:
    // Release the plug-in interface
    IODestroyPlugInInterface(plugIn);

cleanupCurrdev:
    // Release the current device io_object
    IOObjectRelease(currdev);

    // Release the iterator used to find the device
    IOObjectRelease(iterator);

cleanupNull:
    // Should be FORENSIC1394_RESULT_SUCCESS unless changed by an error macro
    return fret;
}

forensic1394_result platform_update_device_list(forensic1394_bus *bus)
{
    CFMutableDictionaryRef matchingDict;

    io_iterator_t iterator;
    io_object_t currdev;

    IOReturn iret;
    forensic1394_result fret = FORENSIC1394_RESULT_SUCCESS;

    // We need to get the systems local device node to update the CSR
    matchingDict = IOServiceMatching("IOFireWireDevice");
    iret = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                        matchingDict,
                                        &iterator);

    require_assertion(iret == kIOReturnSuccess, cleanupMatchingServices,
                      fret, FORENSIC1394_RESULT_OTHER_ERROR);

    while ((currdev = IOIteratorNext(iterator)))
    {
        IOCFPlugInInterface **plugIn;
        SInt32 theScore;

        // Allocate memory for a forensic1394 device
        forensic1394_dev *fdev = malloc(sizeof(forensic1394_dev));

        // And for the platform specific structure
        fdev->pdev = malloc(sizeof(platform_bus));

        // Copy over the device IO object to the structure
        fdev->pdev->dev = currdev;

        // Get an plug-in interface to the device
        IOCreatePlugInInterfaceForService(currdev,
                                          kIOFireWireLibTypeID,
                                          kIOCFPlugInInterfaceID,
                                          &plugIn, &theScore);

        // Ensure we got an interface
        require_assertion(plugIn, cleanupPlugIn, fret, FORENSIC1394_RESULT_OTHER_ERROR);

        // Use this to get an interface to the firewire device
        (*plugIn)->QueryInterface(plugIn,
                                  CFUUIDGetUUIDBytes(kIOFireWireDeviceInterfaceID_v9),
                                  (void **) &fdev->pdev->devIntrf);


        // Ensure the interface is inited
        require_assertion((*fdev->pdev->devIntrf)->InterfaceIsInited(fdev->pdev->devIntrf),
                          cleanupDevIntrf, fret, FORENSIC1394_RESULT_OTHER_ERROR);

        // Save the bus the device is attached to
        fdev->bus = bus;

        // The device is not open
        fdev->is_open = 0;

        // Get the product name
        copy_device_property_string(currdev, CFSTR("FireWire Product Name"),
                                    fdev->product_name, sizeof(fdev->product_name));

        // Get the product id
        copy_device_property_int32(currdev, CFSTR("Model_ID"), &fdev->product_id);

        // Get the vendor name
        copy_device_property_string(currdev, CFSTR("FireWire Vendor Name"),
                                    fdev->vendor_name, sizeof(fdev->vendor_name));

        // Get the vendor id
        copy_device_property_int32(currdev, CFSTR("Vendor_ID"), &fdev->vendor_id);

        // Get the GUID
        copy_device_property_int64(currdev, CFSTR("GUID"), &fdev->guid);

        // Copy the ROM
        copy_device_property_csr(currdev, fdev->rom);

        // Get the bus generation
        (*fdev->pdev->devIntrf)->GetBusGeneration(fdev->pdev->devIntrf,
                                                  &fdev->generation);

        // Get the node ID
        (*fdev->pdev->devIntrf)->GetRemoteNodeID(fdev->pdev->devIntrf,
                                                 fdev->generation,
                                                 &fdev->nodeid);

        // See if we need to extend the device list; +1 as the last device
        // is always NULL, hence taking up a slot
        if (bus->ndev + 1 == bus->size)
        {
            bus->size += FORENSIC1394_DEV_LIST_SZ;
            bus->dev = realloc(bus->dev, sizeof(forensic1394_dev *) * bus->size);
        }

        // Add this new device to the device list
        bus->dev[bus->ndev++] = fdev;

        // Continue; everything from here on in is damage control
        continue;

    cleanupDevIntrf:
        // Release the device interface
        (*fdev->pdev->devIntrf)->Release(fdev->pdev->devIntrf);

    cleanupPlugIn:
        // Release the plug-in interface
        IODestroyPlugInInterface(plugIn);

        // Release the IO object
        IOObjectRelease(fdev->pdev->dev);

        // Release the partially allocated device
        free(fdev->pdev);
        free(fdev);
    }

    // Release the iterator
    IOObjectRelease(iterator);

cleanupMatchingServices:
    return fret;
}

void platform_device_destroy(forensic1394_dev *dev)
{
    // Release the device interface
    (*dev->pdev->devIntrf)->Release(dev->pdev->devIntrf);

    // Release the device IO object itself
    IOObjectRelease(dev->pdev->dev);

    // Free the platform device structure
    free(dev->pdev);
}

forensic1394_result platform_open_device(forensic1394_dev *dev)
{
    IOReturn iret;

    // Attempt to open the device
    iret = (*dev->pdev->devIntrf)->Open(dev->pdev->devIntrf);

    return convert_ioreturn(iret);
}

void platform_close_device(forensic1394_dev *dev)
{
    (*dev->pdev->devIntrf)->Close(dev->pdev->devIntrf);
}

int platform_read_device(forensic1394_dev *dev,
                         uint64_t addr,
                         size_t len,
                         void *buf)
{
    FWAddress fwaddr;
    IOReturn ret;
    UInt32 bufsize = len;

    // Decompose the address; the nodeID is handled by IOKit
    fwaddr.nodeID       = 0;
    fwaddr.addressHi    = addr >> 32;
    fwaddr.addressLo    = addr & 0xffffffffULL;

    // Perform the read
    ret = (*dev->pdev->devIntrf)->Read(dev->pdev->devIntrf, dev->pdev->dev,
                                       &fwaddr, buf, &bufsize, false, 0);


    return convert_ioreturn(ret);
}

int platform_write_device(forensic1394_dev *dev,
                          uint64_t addr,
                          size_t len,
                          void *buf)
{
    FWAddress fwaddr;
    IOReturn ret;
    UInt32 bufsize = len;

    // Decompose the address
    fwaddr.nodeID       = 0;
    fwaddr.addressHi    = addr >> 32;
    fwaddr.addressLo    = addr & 0xffffffffULL;

    // Perform the write
    ret = (*dev->pdev->devIntrf)->Write(dev->pdev->devIntrf, dev->pdev->dev,
                                        &fwaddr, buf, &bufsize, false, 0);

    return convert_ioreturn(ret);
}

forensic1394_result convert_ioreturn(IOReturn i)
{
    switch (i)
    {
        case kIOReturnSuccess:
            return FORENSIC1394_RESULT_SUCCESS;
            break;
        case kIOReturnBusy:
            return FORENSIC1394_RESULT_BUSY;
            break;
        case kIOFireWireBusReset:
            return FORENSIC1394_RESULT_BUS_RESET;
            break;
        default:
            return FORENSIC1394_RESULT_IO_ERROR;
            break;
    }
}

void copy_device_property_string(io_registry_entry_t dev,
                                 CFStringRef prop,
                                 char *buf,
                                 size_t bufsiz)
{
    // Attempt to extract the property as a CFString
    CFStringRef propstr = IORegistryEntryCreateCFProperty(dev, prop, NULL, 0);

    // Clear the property first
    memset(buf, 0, bufsiz);

    // Ensure that the property exists
    if (propstr)
    {
        // And that it is really a CFString
        if (CFGetTypeID(propstr) == CFStringGetTypeID())
        {
            // Copy the string to the buffer provided
            CFStringGetCString(propstr, buf, bufsiz, kCFStringEncodingUTF8);
        }
        // Invalid property type
        else
        {
            return;
        }


        // Release the string
        CFRelease(propstr);
    }
    // Property not found
    else
    {
        return;
    }
}

void copy_device_property_int(io_registry_entry_t dev,
                              CFStringRef prop,
                              void *num,
                              CFNumberType type)
{
    // Attempt to extract the property as a CFNumber
    CFNumberRef propnum = IORegistryEntryCreateCFProperty(dev, prop, NULL, 0);

    // Ensure that the property exists
    if (propnum)
    {
        // And that it is really a CFNumber
        if (CFGetTypeID(propnum) == CFNumberGetTypeID())
        {
            // Copy the number to the buffer provided
            CFNumberGetValue(propnum, type, num);
        }
        // Invalid property type
        else
        {
            return;
        }

        // Release the number
        CFRelease(propnum);
    }
    // Property not found
    else
    {
        return;
    }
}

void copy_device_property_int32(io_registry_entry_t dev,
                                CFStringRef prop,
                                int32_t *num)
{
    *num = 0;

    copy_device_property_int(dev, prop, num, kCFNumberSInt32Type);
}

void copy_device_property_int64(io_registry_entry_t dev,
                                CFStringRef prop,
                                int64_t *num)
{
    *num = 0;

    copy_device_property_int(dev, prop, num, kCFNumberSInt64Type);
}

void copy_device_property_csr(io_registry_entry_t dev,
                              uint32_t *rom)
{
    // Attempt to extract the "FireWire Device ROM" property
    CFDictionaryRef romdict = IORegistryEntryCreateCFProperty(dev,
                                                              CFSTR("FireWire Device ROM"),
                                                              NULL,
                                                              0);

    memset(rom, '\0', FORENSIC1394_CSR_SZ * sizeof(uint32_t));

    // Ensure the ROM dictionary exists
    if (romdict)
    {
        // And that it is really a dictionary
        if (CFGetTypeID(romdict) == CFDictionaryGetTypeID())
        {
            // The ROM itself is stored in the "Offset 0" key
            CFDataRef romdata = CFDictionaryGetValue(romdict, CFSTR("Offset 0"));

            // Ensure the ROM data exists
            if (romdata)
            {
                // And that it is really a data type
                if (CFGetTypeID(romdata) == CFDataGetTypeID())
                {
                    int i;

                    CFRange datarange = CFRangeMake(0, CFDataGetLength(romdata));

                    // Check the size is not > 1024 bytes
                    assert(datarange.length <= (FORENSIC1394_CSR_SZ * sizeof(uint32_t)));

                    // Copy the data to the buffer
                    CFDataGetBytes(romdata, datarange, (UInt8 *) rom);

                    // Convert from big-endian to CPU-endian (no-op on PPC Macs)
                    for (i = 0; i < (datarange.length / sizeof(uint32_t)); i++)
                    {
                        rom[i] = ntohl(rom[i]);
                    }
                }

                // Release the data
                CFRelease(romdata);
            }
        }

        // Release the dictionary
        CFRelease(romdict);
    }
}
