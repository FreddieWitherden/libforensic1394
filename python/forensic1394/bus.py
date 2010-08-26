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

from ctypes import c_int, byref

from forensic1394.errors import process_result

from forensic1394.functions import forensic1394_alloc, forensic1394_destroy, \
                                   forensic1394_enable_sbp2, \
                                   forensic1394_get_devices
from forensic1394.device import Device

import weakref

class Bus(object):
    def __init__(self):
        # Allocate a new bus handle; _as_parameter_ allows passing of self
        self._as_parameter_ = forensic1394_alloc()

        # Weak references to the most recent device list
        self._wrefdev = []

    def enable_sbp2(self):
        # Re-raise for a cleaner stack trace
        forensic1394_enable_sbp2(self)

    def devices(self):
        # Mark any active device handles as being stale
        for wdev in self._wrefdev:
            if wdev():
                wdev()._stale = True

        # Clear the current list of weak references
        self._wrefdev = []

        dev = []
        ndev = c_int(0)

        # Query the list of devices attached to the system
        devlist = forensic1394_get_devices(self, byref(ndev), None)

        # If ndev is < 0 then it contains a result status code
        if ndev.value < 0:
            process_result(ndev.value, forensic1394_get_devices, ())

        # Create Device instances for the devices found
        for i in range(0, ndev.value):
            d = Device(self, devlist[i])
            dev.append(d)
            # Maintain a weak reference to this device
            self._wrefdev.append(weakref.ref(d))

        # Return the device list
        return dev

    def __del__(self):
        forensic1394_destroy(self)
