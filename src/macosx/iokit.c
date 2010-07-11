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

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/firewire/IOFireWireLib.h>

struct _platform_bus
{
    IOFireWireLibDeviceRef localDev;
    IOFireWireLibLocalUnitDirectoryRef localUnitDir;
};

struct _platform_dev
{
    IOFireWireLibDeviceRef devIntrf;
    io_object_t dev;

    UInt32 generation;
};

static void copy_device_property_string(io_registry_entry_t dev,
                                        CFStringRef prop,
                                        char *buf,
                                        size_t bufsiz);

static void copy_device_property_int(io_registry_entry_t dev,
                                     CFStringRef prop,
                                     int *num);

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
    if (bus->sbp2Enabled)
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

int platform_enable_sbp2(forensic1394_bus *bus)
{
    CFMutableDictionaryRef matchingDict;

    io_iterator_t iterator;
    io_object_t currdev;

    IOCFPlugInInterface **plugIn;
    SInt32 theScore;    // Unused

    IOFireWireLibDeviceRef localDev;
    IOFireWireLibLocalUnitDirectoryRef localUnitDir;

    IOReturn ret;

    // We need to get the systems local device node to update the CSR
    matchingDict = IOServiceMatching("IOFireWireLocalNode");
    ret = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                       matchingDict,
                                       &iterator);

    // There should only be one of these; so grab the first
    currdev = IOIteratorNext(iterator);

    // Release the iterator
    IOObjectRelease(iterator);

    // Get a plug-in interface to the device
    ret = IOCreatePlugInInterfaceForService(currdev,
                                            kIOFireWireLibTypeID,
                                            kIOCFPlugInInterfaceID,
                                            &plugIn,
                                            &theScore);

    // Release the device's io_object
    IOObjectRelease(currdev);

    // Use this plug-in to get a firewire device interface
    ret = (*plugIn)->QueryInterface(plugIn,
                                    CFUUIDGetUUIDBytes(kIOFireWireDeviceInterfaceID_v9),
                                    (void **) &localDev);

    // Release the plug-in interface
    IODestroyPlugInInterface(plugIn);

    // Use this device interface to open up the device
    ret = (*localDev)->Open(localDev);

    // And grab a unit local directory interface
    localUnitDir = (*localDev)->CreateLocalUnitDirectory(localDev,
                                                         CFUUIDGetUUIDBytes(kIOFireWireLocalUnitDirectoryInterfaceID));


    // SBP-2
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x12, 0x00609e, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x13, 0x010483, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x21, 0x000001, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x3a, 0x000a08, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x3e, 0x004c10, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x38, 0x00609e, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x39, 0x0104d8, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x3b, 0x000000, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x3c, 0x0a2700, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x54, 0x004000, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x3d, 0x000003, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x14, 0x0e0000, NULL);
    (*localUnitDir)->AddEntry_UInt32(localUnitDir, 0x17, 0x000021, NULL);

    // Publish this unit directory
    (*localUnitDir)->Publish(localUnitDir);

    // Save the interface references for later
    bus->pbus->localDev     = localDev;
    bus->pbus->localUnitDir = localUnitDir;

    return 1;
}

void platform_update_device_list(forensic1394_bus *bus)
{
    CFMutableDictionaryRef matchingDict;

    io_iterator_t iterator;
    io_object_t currdev;

    IOReturn ret;

    // We need to get the systems local device node to update the CSR
    matchingDict = IOServiceMatching("IOFireWireDevice");
    ret = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                       matchingDict,
                                       &iterator);

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
        ret = IOCreatePlugInInterfaceForService(currdev,
                                                kIOFireWireLibTypeID,
                                                kIOCFPlugInInterfaceID,
                                                &plugIn, &theScore);

        // Use this to get an interface to the firewire device
        ret = (*plugIn)->QueryInterface(plugIn,
                                        CFUUIDGetUUIDBytes(kIOFireWireDeviceInterfaceID_v9),
                                        (void **) &fdev->pdev->devIntrf);

        // Release the plug-in interface
        IODestroyPlugInInterface(plugIn);

        // Ensure the interface is inited
        (*fdev->pdev->devIntrf)->InterfaceIsInited(fdev->pdev->devIntrf);

        // Save the bus the device is attached to
        fdev->bus = bus;

        // The device is not open
        fdev->isOpen = 0;

        // Get the product name
        copy_device_property_string(currdev, CFSTR("FireWire Product Name"),
                                    fdev->product_name, sizeof(fdev->product_name));

        // Get the product id
        copy_device_property_int(currdev, CFSTR("FireWire Product ID"), &fdev->product_id);

        // Get the vendor name
        copy_device_property_string(currdev, CFSTR("FireWire Vendor Name"),
                                    fdev->vendor_name, sizeof(fdev->vendor_name));

        // Get the vendor id
        copy_device_property_int(currdev, CFSTR("FireWire Vendor ID"), &fdev->vendor_id);

        // Copy the ROM
        copy_device_property_csr(currdev, fdev->rom);

        // Get the bus generation
        (*fdev->pdev->devIntrf)->GetBusGeneration(fdev->pdev->devIntrf,
                                                  &fdev->pdev->generation);

        // Get the node ID
        (*fdev->pdev->devIntrf)->GetRemoteNodeID(fdev->pdev->devIntrf,
                                                 fdev->pdev->generation,
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
    }

    // Release the iterator
    IOObjectRelease(iterator);
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

int platform_open_device(forensic1394_dev *dev)
{
    return (*dev->pdev->devIntrf)->Open(dev->pdev->devIntrf) == kIOReturnSuccess;
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

    printf("%d\n", ret);

    return 1;
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

    return 1;
}

void copy_device_property_string(io_registry_entry_t dev,
                                 CFStringRef prop,
                                 char *buf,
                                 size_t bufsiz)
{
    // Attempt to extract the property as a CFString
    CFStringRef propstr = IORegistryEntryCreateCFProperty(dev, prop, NULL, 0);

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

        }


        // Release the string
        CFRelease(propstr);
    }
    // Property not found
    else
    {
        memset(buf, 0, bufsiz);
    }
}

void copy_device_property_int(io_registry_entry_t dev,
                              CFStringRef prop,
                              int *num)
{
    // Attempt to extract the property as a CFNumber
    CFNumberRef propnum = IORegistryEntryCreateCFProperty(dev, prop, NULL, 0);

    // Ensure that the property exists
    if (propnum)
    {
        // And that it is really a CFNumber
        if (CFGetTypeID(propnum) == CFNumberGetTypeID())
        {
            // Copy the string to the buffer provided
            CFNumberGetValue(propnum, kCFNumberIntType, num);
        }
        // Invalid property type
        else
        {

        }


        // Release the number
        CFRelease(propnum);
    }
    // Property not found
    else
    {
        *num = -1;
    }
}

void copy_device_property_csr(io_registry_entry_t dev,
                              uint32_t *rom)
{
    // Attempt to extract the "FireWire Device ROM" property
    CFDictionaryRef romdict = IORegistryEntryCreateCFProperty(dev,
                                                              CFSTR("FireWire Device ROM"),
                                                              NULL,
                                                              0);

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
                    CFRange datarange = CFRangeMake(0, CFDataGetLength(romdata));

                    // Check the size is not > 1024 bytes
                    assert(datarange.length <= 1024);

                    // Copy the data to the buffer
                    CFDataGetBytes(romdata, datarange, (UInt8 *) rom);
                }

                // Release the data
                CFRelease(romdata);
            }
        }

        // Release the dictionary
        CFRelease(romdict);
    }
}
