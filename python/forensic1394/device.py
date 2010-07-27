# -*- coding: utf-8 -*-
#############################################################################
#  This file is part of libforensic1394.                                    #
#  Copyright (C) 2010  Freddie Witherden <freddie@witherden.org>            #
#                                                                           #
#  libforensic1394 is free software: you can redistribute it and/or modify  #
#  it under the terms of the GNU Lesser General Public License as           #
#  published by the Free Software Foundation, either version 3 of the       #
#  License, or (at your option) any later version.                          #
#                                                                           #
#  libforensic1394 is distributed in the hope that it will be useful,       #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of           #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
#  GNU Lesser General Public License for more details.                      #
#                                                                           #
#  You should have received a copy of the GNU Lesser General Public         #
#  License along with libforensic1394.  If not, see                         #
#  <http://www.gnu.org/licenses/>.                                          #
#############################################################################

from ctypes import create_string_buffer, byref, c_size_t, c_uint32

from forensic1394.errors import process_result, Forensic1394StaleHandle

from forensic1394.functions import forensic1394_open_device, \
                                   forensic1394_close_device, \
                                   forensic1394_is_device_open, \
                                   forensic1394_read_device, \
                                   forensic1394_write_device, \
                                   forensic1394_get_device_csr, \
                                   forensic1394_get_device_nodeid, \
                                   forensic1394_get_device_guid, \
                                   forensic1394_get_device_product_name, \
                                   forensic1394_get_device_product_id, \
                                   forensic1394_get_device_vendor_name, \
                                   forensic1394_get_device_vendor_id, \
                                   forensic1394_get_device_request_size

def checkStale(f):
    def newf(self, *args, **kwargs):
        if self._stale:
            raise Forensic1394StaleHandle
        return f(self, *args, **kwargs)
    return newf

class Device(object):
    def __init__(self, bus, devptr):
        """
        Constructs a new Device instance.  This should not usually be called
        directly; instead a list of pre-constructed Device instances should be
        requested from the bus.
        """

        # Retain a reference to the Bus (otherwise unused)
        self._bus = bus

        # Set as _as_parameter_ to allow passing of self to functions
        self._as_parameter_ = devptr

        # We are not stale
        self._stale = False

        # Copy over the device properties
        self._nodeid = forensic1394_get_device_nodeid(self)
        self._guid = forensic1394_get_device_guid(self)

        self._product_name = forensic1394_get_device_product_name(self)
        self._product_id = forensic1394_get_device_product_id(self)

        self._vendor_name = forensic1394_get_device_vendor_name(self)
        self._vendor_id = forensic1394_get_device_vendor_id(self)

        self._request_size = forensic1394_get_device_request_size(self)

        self._csr = (c_uint32 * 256)()
        forensic1394_get_device_csr(self, self._csr)

    def __del__(self):
        if self.isopen():
            self.close()

    @checkStale
    def open(self):
        """
        Attempts to open the device.  If the device can not be opened, or if the
        device is stale, an exception is raised.
        """
        forensic1394_open_device(self)

    def close(self):
        """
        Closes the device.
        """
        forensic1394_close_device(self)

    def isopen(self):
        """
        Checks to see if the device is open or not, returning a boolean value.
        """
        return bool(forensic1394_is_device_open(self))

    @checkStale
    def read(self, addr, numb):
        """
        Attempts to read numb bytes from the device starting at addr.  The
        device must be open and the handle can not be stale.  Requests larger
        than self.request_size will automatically be broken down into smaller
        chunks.  The resulting data is returned.  An exception is raised should
        an errors occur.
        """
        assert self.isopen()

        # Allocate a buffer for the data
        b = create_string_buffer(numb)

        # Break the request up into request_size chunks
        for off in range(0, numb, self._request_size):
            # Last chunk is a special case (numb - off)
            n = min(numb - off, self._request_size)

            forensic1394_read_device(self, addr + off, n, byref(b, off))

        return b.raw

    @checkStale
    def write(self, addr, buf):
        """
        Attempts to write len(buf) bytes to the device starting at addr.  The
        device must be open and the handle can not be stale.  Requests larger
        than self.request_size will automatically be broken down into smaller
        chunks.
        """
        assert self.isopen()

        numb = len(buf)

        # Break up the request
        for off in range(0, numb, self._request_size):
            n = min(numb - off, self._request_size)

            forensic1394_write_device(self, addr + off, n, buf[off:off + n])

    @property
    def nodeid(self):
        """
        The node ID of the device on the bus.
        """
        return self._nodeid

    @property
    def guid(self):
        """
        The 48-bit GUID of the device.
        """
        return self._guid

    @property
    def product_name(self):
        """
        The product name of the device; may be ''.
        """
        return self._product_name

    @property
    def product_id(self):
        """
        The product id of the device; integer.
        """
        return self._product_id

    @property
    def vendor_name(self):
        """
        The vendor name of the device; may be ''.
        """
        return self._vendor_name

    @property
    def vendor_id(self):
        """
        The vendor id of the device; integer.
        """
        return self._vendor_id

    @property
    def request_size(self):
        """
        The maximum request size supported by the device in bytes; this is
        always a power of two.
        """
        return self._request_size

    @property
    def csr(self):
        """
        Configuration status ROM for the device, list of 32-bit host-endian
        integers.
        """
        return self._csr
