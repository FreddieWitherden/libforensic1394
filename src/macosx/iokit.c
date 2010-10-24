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
#include "csr.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/firewire/IOFireWireLib.h>

/**
 * The number of read commands to allocate per device; these are used
 *  to submit asynchronous read requests.
 */
#define FORENSIC1394_NUM_READ_CMD 4

/**
 * The number of write commands to allocate per device; these are used
 *  to submit asynchronous write requests.
 */
#define FORENSIC1394_NUM_WRITE_CMD 1

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

    IOFireWireLibCommandRef readcmd[FORENSIC1394_NUM_READ_CMD];
    IOFireWireLibCommandRef writecmd[FORENSIC1394_NUM_WRITE_CMD];
    IOReturn cmdret;
};

static void create_commands(forensic1394_dev *dev, request_type t,
                            IOFireWireLibCommandRef *cmd, size_t ncmd);

static void cancel_commands(IOFireWireLibCommandRef *cmd, size_t ncmd);

static void release_commands(IOFireWireLibCommandRef *cmd, size_t ncmd);

/**
 * \brief Converts \a i into the closest matching \c forensic1394_result.
 *
 *   \param i The return value to convert.
 *  \return The corresponding \c forensic1394_result.
 */
static forensic1394_result convert_ioreturn(IOReturn i);

/**
 * \brief Callback handler for when read/write commands complete.
 *
 *   \param refcon User data.
 *   \param ret Return code for the command.
 */
static void request_complete(void *refcon, IOReturn ret);

static forensic1394_result send_requests(forensic1394_dev *dev,
                                         request_type t,
                                         const forensic1394_req *req,
                                         size_t nreq,
                                         size_t ncmd);

static void copy_device_csr(io_registry_entry_t dev, uint32_t *rom);

platform_bus *platform_bus_alloc()
{
    platform_bus *pbus = calloc(1, sizeof(platform_bus));

    return pbus;
}

void platform_bus_destroy(forensic1394_bus *bus)
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
        UInt32 key      = CSR_KEY(sbp2dir[i]);
        UInt32 value    = CSR_VALUE(sbp2dir[i]);

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
        UInt32 generation;
        UInt16 nodeid;

        // Allocate memory for a forensic1394 device
        forensic1394_dev *fdev = malloc(sizeof(forensic1394_dev));

        // And for the platform specific structure
        fdev->pdev = malloc(sizeof(platform_dev));

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

        // Copy the ROM
        copy_device_csr(currdev, fdev->rom);

        // Parse the ROM to extract useful fragments
        common_parse_csr(fdev);

        // Get the bus generation
        (*fdev->pdev->devIntrf)->GetBusGeneration(fdev->pdev->devIntrf,
                                                  &generation);

        // Get the node ID
        (*fdev->pdev->devIntrf)->GetRemoteNodeID(fdev->pdev->devIntrf,
                                                 generation,
                                                 &nodeid);

        fdev->generation = generation;
        fdev->node_id = nodeid;

        // Add this new device to the device list
        fdev->next = bus->dev_link;
        bus->dev_link = fdev;
        bus->ndev++;

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

    IOFireWireLibDeviceRef intrf = dev->pdev->devIntrf;

    // Attempt to open the device
    iret = (*intrf)->Open(intrf);

    if (iret == kIOReturnSuccess)
    {
        // Add a custom callback mode "libforensic1394"
        (*intrf)->AddCallbackDispatcherToRunLoopForMode(intrf,
                                                        CFRunLoopGetCurrent(),
                                                        CFSTR("libforensic1394"));

        // Create the read and write commands
        create_commands(dev, REQUEST_TYPE_READ, dev->pdev->readcmd,
                        FORENSIC1394_NUM_READ_CMD);
        create_commands(dev, REQUEST_TYPE_WRITE, dev->pdev->writecmd,
                        FORENSIC1394_NUM_WRITE_CMD);
    }

    return convert_ioreturn(iret);
}

void platform_close_device(forensic1394_dev *dev)
{
    // Release the read and write commands
    release_commands(dev->pdev->readcmd, FORENSIC1394_NUM_READ_CMD);
    release_commands(dev->pdev->writecmd, FORENSIC1394_NUM_WRITE_CMD);

    // Remove the callback handler added in open_device
    (*dev->pdev->devIntrf)->RemoveCallbackDispatcherFromRunLoop(dev->pdev->devIntrf);

    // Finally, close the device
    (*dev->pdev->devIntrf)->Close(dev->pdev->devIntrf);
}

forensic1394_result platform_send_requests(forensic1394_dev *dev,
                                           request_type type,
                                           const forensic1394_req *req,
                                           size_t nreq)
{
    // Determine the maximum number of commands we can use
    int nmaxcmd = (type == REQUEST_TYPE_READ) ? FORENSIC1394_NUM_READ_CMD
                                              : FORENSIC1394_NUM_WRITE_CMD;
    int ncmd = (nreq > nmaxcmd) ? nmaxcmd : nreq;

    // Dispatch to the internal send_requests method
    return send_requests(dev, type, req, nreq, ncmd);
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
        case kIOReturnTimeout:
            return FORENSIC1394_RESULT_IO_TIMEOUT;
            break;
        case kIOFireWireBusReset:
            return FORENSIC1394_RESULT_BUS_RESET;
            break;
        default:
            return FORENSIC1394_RESULT_IO_ERROR;
            break;
    }
}

void request_complete(void *ref, IOReturn result)
{
    // Cast ref to an IOReturn (ref == &dev->pdev->cmdret)
    IOReturn *r = ref;

    // Only overwrite ref if it does not hold an error-code
    if (*r == kIOReturnSuccess)
    {
        // Save the result; we'll pick it up later
        *r = result;
    }
}

void create_commands(forensic1394_dev *dev, request_type t,
                     IOFireWireLibCommandRef *cmd, size_t ncmd)
{
    int i;

    IOFireWireLibDeviceRef intrf = dev->pdev->devIntrf;
    io_object_t devio = dev->pdev->dev;

    FWAddress nulladdr = { 0, 0, 0 };

    for (i = 0; i < ncmd; i++)
    {
        if (t == REQUEST_TYPE_READ)
        {
            cmd[i] = (*intrf)->CreateReadCommand(intrf, devio,
                                                 &nulladdr, NULL, 0,
                                                 request_complete, 0, false,
                                                 &dev->pdev->cmdret,
                                                 CFUUIDGetUUIDBytes(kIOFireWireReadCommandInterfaceID_v3));
        }
        else
        {
            cmd[i] = (*intrf)->CreateWriteCommand(intrf, devio,
                                                  &nulladdr, NULL, 0,
                                                  request_complete, 0, false,
                                                  &dev->pdev->cmdret,
                                                  CFUUIDGetUUIDBytes(kIOFireWireWriteCommandInterfaceID_v3));
        }
    }
}

void cancel_commands(IOFireWireLibCommandRef *cmd, size_t ncmd)
{
    int i;

    for (i = 0; i < ncmd; i++)
    {
        // If the command is currently executing; cancel it
        if ((*cmd[i])->IsExecuting(cmd[i]))
        {
            (*cmd[i])->Cancel(cmd[i], 0);
        }
    }
}

void release_commands(IOFireWireLibCommandRef *cmd, size_t ncmd)
{
    int i;

    for (i = 0; i < ncmd; i++)
    {
        // Release
        (*cmd[i])->Release(cmd[i]);
    }
}

forensic1394_result send_requests(forensic1394_dev *dev, request_type t,
                                  const forensic1394_req *req, size_t nreq,
                                  size_t ncmd)
{
    forensic1394_result ret = FORENSIC1394_RESULT_SUCCESS;

    int i = 0, j;
    int inPipeline = 0;

    // We need some commands in order to send the requests
    IOFireWireLibCommandRef *cmd = (t == REQUEST_TYPE_READ) ? dev->pdev->readcmd
                                                            : dev->pdev->writecmd;

    // Reset cmdret in case a previous request failed
    dev->pdev->cmdret = kIOReturnSuccess;

    /*
     * We need to keep going until there are firstly no more requests to make
     * and secondly until all requests we've made have been responded to.
     */
    while (i < nreq || inPipeline > 0)
    {
        SInt32 lret;

        // Send as many requests as possible
        for (j = 0; inPipeline < ncmd && j < ncmd && i < nreq; j++)
        {
            IOFireWireLibCommandRef c = cmd[j];

            // See if the command is currently idle
            if (!(*c)->IsExecuting(c))
            {
                // Decompose the address; the nodeID is handled by IOKit
                FWAddress fwaddr = {
                    .nodeID     = 0,
                    .addressHi  = req[i].addr >> 32,
                    .addressLo  = req[i].addr & 0xffffffffULL
                };

                (*c)->SetTarget(c, &fwaddr);
                (*c)->SetBuffer(c, req[i].len, req[i].buf);
                (*c)->Submit(c);

                i++; inPipeline++;
            }
        }

        // Wait for a response to a request
        lret = CFRunLoopRunInMode(CFSTR("libforensic1394"),
                                  FORENSIC1394_TIMEOUT_MS * 1.0e-3, true);

        // So long as the loop did not timeout we're good
        if (lret != kCFRunLoopRunTimedOut)
        {
            inPipeline--;

            // Check the return code
            if (dev->pdev->cmdret != kIOReturnSuccess)
            {
                ret = convert_ioreturn(dev->pdev->cmdret);
                break;
            }
        }
        else
        {
            ret = FORENSIC1394_RESULT_IO_TIMEOUT;
            break;
        }
    }

    // Cancel any commands still executing
    cancel_commands(cmd, ncmd);

    return ret;
}

void copy_device_csr(io_registry_entry_t dev, uint32_t *rom)
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
                        rom[i] = CSR_HOST_QUADLET(rom[i]);
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
