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

from ctypes import cdll, CFUNCTYPE, POINTER, Structure, c_int, c_size_t, \
                   c_uint64, c_int64, c_uint32, c_uint16, c_void_p, c_char, \
                   c_char_p
from ctypes.util import find_library

from forensic1394.errors import process_result

# Try to find the forensic1394 shared library
loc = find_library("forensic1394")

if loc is None:
    raise ImportError

# Open up the library
lib = cdll.LoadLibrary(loc)

# Opaque bus and device pointers
class busptr(c_void_p):
    pass

class devptr(c_void_p):
    pass

# Wrap the forensic1394_req structure
# C def: struct { uint64_t addr, size_t len, void *buf }
class forensic1394_req(Structure):
    _fields_ = [("addr", c_uint64),
                ("len", c_size_t),
                ("buf", c_void_p)]

# Wrap the forensic1394_device_callback type
# C def: void (*forensic1394_device_callback) (forensic1394_bus *bus,
#                                              forensic1394_dev *dev)
forensic1394_device_callback = CFUNCTYPE(None, busptr, devptr)

# Wrap the alloc function
# C def: forensic1394_bus *forensic1394_alloc(void)
forensic1394_alloc = lib.forensic1394_alloc
forensic1394_alloc.argtypes = []
forensic1394_alloc.restype = busptr

# Wrap the enable_sbp2 function
# C def: forensic1394_result forensic1394_enable_sbp2(forensic1394_bus *bus)
forensic1394_enable_sbp2 = lib.forensic1394_enable_sbp2
forensic1394_enable_sbp2.argtypes = [busptr]
forensic1394_enable_sbp2.restype = c_int
forensic1394_enable_sbp2.errcheck = process_result

# Wrap the get devices function
# C def: forensic1394_dev **forensic1394_get_devices(forensic1394_bus *bus,
#                                                    int *ndev,
#                                                    forensic1394_device_callback ondestroy)
forensic1394_get_devices = lib.forensic1394_get_devices
forensic1394_get_devices.argtypes = [busptr, POINTER(c_int), c_void_p]
forensic1394_get_devices.restype = POINTER(devptr)

# Wrap the destroy function
# C def: void forensic1394_destroy(forensic1394_bus *bus)
forensic1394_destroy = lib.forensic1394_destroy
forensic1394_destroy.argtypes = [busptr]
forensic1394_destroy.restype = None

# Wrap the open device function
# C def: forensic1394_result forensic1394_open_device(forensic1394_dev *dev)
forensic1394_open_device = lib.forensic1394_open_device
forensic1394_open_device.argtypes = [devptr]
forensic1394_open_device.restype = c_int
forensic1394_open_device.errcheck = process_result

# Wrap the close device function
# C def: void forensic1394_close_device(forensic1394_dev *dev)
forensic1394_close_device = lib.forensic1394_close_device
forensic1394_close_device.argtypes = [devptr]
forensic1394_close_device.restype = None

# Wrap the is device open function
# C def: int forensic1394_device_is_open(forensic1394_dev *dev)
forensic1394_is_device_open = lib.forensic1394_is_device_open
forensic1394_is_device_open.argtypes = [devptr]
forensic1394_is_device_open.restype = c_int

# Wrap the read device function
# C def: forensic1394_result forensic1394_read_device(forensic1394_dev *dev,
#                                                     uint64_t addr,
#                                                     size_t len, void *buf)
forensic1394_read_device = lib.forensic1394_read_device
forensic1394_read_device.argtypes = [devptr, c_uint64, c_size_t, c_void_p]
forensic1394_read_device.restype = c_int
forensic1394_read_device.errcheck = process_result

# Wrap the vectorised read device function
# C def: forensic1394_result forensic1394_read_device_v(forensic1394_dev *dev,
#                                                       forensic1394_req *req,
#                                                       size_t nreq)
forensic1394_read_device_v = lib.forensic1394_read_device_v
forensic1394_read_device_v.argtypes = [devptr,
                                       POINTER(forensic1394_req),
                                       c_size_t]
forensic1394_read_device_v.restype = c_int
forensic1394_read_device_v.errcheck = process_result

# Wrap the write device function
# C def: forensic1394_result forensic1394_write_device(forensic1394_dev *dev,
#                                                      uint64_t addr,
#                                                      size_t len, void *buf)
forensic1394_write_device = lib.forensic1394_write_device
forensic1394_write_device.argtypes = [devptr, c_uint64, c_size_t, POINTER(c_char)]
forensic1394_write_device.restype = c_int
forensic1394_write_device.errcheck = process_result

# Wrap the vectorised write device function
# C def: forensic1394_result forensic1394_write_device_v(forensic1394_dev *dev,
#                                                        forensic1394_req *req,
#                                                        size_t nreq)
forensic1394_write_device_v = lib.forensic1394_write_device_v
forensic1394_write_device_v.argtypes = [devptr,
                                        POINTER(forensic1394_req),
                                        c_size_t]
forensic1394_write_device_v.restype = c_int
forensic1394_write_device_v.errcheck = process_result

# Wrap the device CSR function
# C def: void forensic1394_get_device_csr(forensic1394_dev *dev, uint32_t *rom)
forensic1394_get_device_csr = lib.forensic1394_get_device_csr
forensic1394_get_device_csr.argtypes = [devptr, POINTER(c_uint32)]
forensic1394_get_device_csr.restype = None

# Wrap the device node id function
# C def: uint16_t forensic1394_get_device_node_id(forensic1394_dev *dev)
forensic1394_get_device_node_id = lib.forensic1394_get_device_node_id
forensic1394_get_device_node_id.argtypes = [devptr]
forensic1394_get_device_node_id.restype = c_uint16

# Wrap the device guid function
# C def: int64_t forensic1394_get_device_guid(forensic1394_dev *dev)
forensic1394_get_device_guid = lib.forensic1394_get_device_guid
forensic1394_get_device_guid.argtypes = [devptr]
forensic1394_get_device_guid.restype = c_int64

# Wrap the device product name function
# C def: const char *forensic1394_get_device_product_name(forensic1394_dev *dev)
forensic1394_get_device_product_name = lib.forensic1394_get_device_product_name
forensic1394_get_device_product_name.argtypes = [devptr]
forensic1394_get_device_product_name.restype = c_char_p

# Wrap the device product id function
# C def: int forensic1394_get_device_product_name(forensic1394_dev *dev)
forensic1394_get_device_product_id = lib.forensic1394_get_device_product_id
forensic1394_get_device_product_id.argtypes = [devptr]
forensic1394_get_device_product_id.restype = c_int

# Wrap the vendor name function
# C def: const char *forensic1394_get_vendor_product_name(forensic1394_dev *dev)
forensic1394_get_device_vendor_name = lib.forensic1394_get_device_vendor_name
forensic1394_get_device_vendor_name.argtypes = [devptr]
forensic1394_get_device_vendor_name.restype = c_char_p

# Wrap the device vendor id function
# C def: int forensic1394_get_device_vendor_name(forensic1394_dev *dev)
forensic1394_get_device_vendor_id = lib.forensic1394_get_device_vendor_id
forensic1394_get_device_vendor_id.argtypes = [devptr]
forensic1394_get_device_vendor_id.restype = c_int

# Wrap the maximum request size function
# C def: int forensic1394_get_device_request_size(forensic1394_dev *dev);
forensic1394_get_device_request_size  = lib.forensic1394_get_device_request_size
forensic1394_get_device_request_size.argtypes = [devptr]
forensic1394_get_device_request_size.restype = c_int

# Wrap the error string function
# C def: const char *forensic1394_get_result_str(forensic1394_result r);
forensic1394_get_result_str = lib.forensic1394_get_result_str
forensic1394_get_result_str.argtypes = [c_int]
forensic1394_get_result_str.restype = c_char_p
