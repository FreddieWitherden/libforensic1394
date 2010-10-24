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

from ctypes import create_string_buffer, byref, cast, POINTER, \
                   c_char, c_size_t, c_uint32, c_void_p

from forensic1394.errors import process_result, Forensic1394StaleHandle

from forensic1394.functions import forensic1394_open_device, \
                                   forensic1394_close_device, \
                                   forensic1394_is_device_open, \
                                   forensic1394_read_device_v, \
                                   forensic1394_write_device_v, \
                                   forensic1394_get_device_csr, \
                                   forensic1394_get_device_node_id, \
                                   forensic1394_get_device_guid, \
                                   forensic1394_get_device_product_name, \
                                   forensic1394_get_device_product_id, \
                                   forensic1394_get_device_vendor_name, \
                                   forensic1394_get_device_vendor_id, \
                                   forensic1394_get_device_request_size, \
                                   forensic1394_req

from functools import wraps

def checkStale(f):
    @wraps(f)
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
        self._node_id = forensic1394_get_device_node_id(self)
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
        Closes the device.  If the device is stale this is a no-op
        """
        if not self._stale:
            forensic1394_close_device(self)

    def isopen(self):
        """
        Checks to see if the device is open or not, returning a boolean value.
        In the case of a stale handle False is returned.
        """
        if self._stale:
            return False
        else:
            return bool(forensic1394_is_device_open(self))

    def _readreq(self, req, buf):
        """
        Internal low level read function.
        """
        assert self.isopen()

        # Get a pointer directly into the buffer which we can perform
        # arithmetic on. Compared to cast(byref(buf, off), c_void_p)
        # directly accessing the pointer gives a ~10% performance
        # improvement for scatter requests.
        pbuf = cast(buf, c_void_p).value

        # Create the request tuples
        init = []
        for addr, numb in req:
            init.append((addr, numb, c_void_p(pbuf)))
            pbuf += numb

        # Create the array of forensic1394 requests
        creq = (forensic1394_req * len(req))(*init)

        # Dispatch the requests
        forensic1394_read_device_v(self, creq, len(creq))

    @checkStale
    def read(self, addr, numb, buf=None):
        """
        Attempts to read numb bytes from the device starting at addr.
        The device must be open and the handle can not be stale.
        Requests larger than self.request_size will automatically be
        broken down into smaller chunks.  The resulting data is
        returned.  An exception is raised should an error occur.  The
        optional buf parameter can be used to pass a specific ctypes
        c_char array to read into.  If no buffer is passed then
        create_string_buffer will be used to allocate one.
        """
        if buf == None:
            # No buffer passed; allocate one
            buf = create_string_buffer(numb)

        # Break the request up into rs size chunks; if numb % rs = 0 then
        # lens may have an extra element; zip will take care of this
        rs = self._request_size
        addrs = range(addr, addr + numb, rs)
        lens = [rs] * (numb // rs) + [numb % rs]

        self._readreq(list(zip(addrs, lens)), buf)

        return buf.raw

    @checkStale
    def readv(self, req):
        """
        Performs a batch of read requests of the form: [(addr1, len1),
        (addr2, len2), ...] and returns a generator yielding, in
        sequence, (addr1, buf1), (addr2, buf2), ..., .  This is useful
        when performing a series of `scatter reads' from a device.
        """
        # Create the request buffer
        buf = create_string_buffer(sum(numb for _addr, numb in req))

        # Use _readreq to read the requests into buf
        self._readreq(req, buf)

        # Generate the resulting buffers
        off = 0
        for addr, numb in req:
            yield (addr, buf.raw[off:off + numb])
            off += numb

    @checkStale
    def write(self, addr, buf):
        """
        Attempts to write len(buf) bytes to the device starting at addr.  The
        device must be open and the handle can not be stale.  Requests larger
        than self.request_size will automatically be broken down into smaller
        chunks.  Uses writev internally.
        """
        # Break up the request
        req = []
        for off in range(0, len(buf), self._request_size):
            req.append((addr + off, buf[off:off + self._request_size]))

        # Dispatch
        self.writev(req)

    @checkStale
    def writev(self, req):
        assert self.isopen()

        # Prepare the request array (addr, len, buf)
        creq = (forensic1394_req * len(req)) \
               (*[(addr, len(buf), cast(buf, c_void_p)) \
                  for addr, buf in req])

        # Send off the requests
        forensic1394_write_device_v(self, creq, len(creq))

    @property
    def node_id(self):
        """
        The node ID of the device on the bus.
        """
        return self._node_id

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
