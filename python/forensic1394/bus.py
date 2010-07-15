# -*- coding: utf-8 -*-
############################################################################
#   This file is part of Forensic1394.                                     #
#   Copyright (C) 2010  Freddie Witherden <freddie@witherden.org>          #
#                                                                          #
#   Forensic1394 is free software: you can redistribute it and/or modify   #
#   it under the terms of the GNU Lesser General Public License as         #
#   published by the Free Software Foundation, either version 3 of the     #
#   License, or (at your option) any later version.                        #
#                                                                          #
#   Forensic1394 is distributed in the hope that it will be useful,        #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of         #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          #
#   GNU Lesser General Public License for more details.                    #
#                                                                          #
#   You should have received a copy of the GNU Lesser General Public       #
#   License along with Forensic1394.  If not, see                          #
#   <http://www.gnu.org/licenses/>.                                        #
############################################################################

from ctypes import c_int, byref

from forensic1394.errors import ResultCode, Forensic1394BusReset

from forensic1394.functions import forensic1394_alloc, forensic1394_destroy, \
                                   forensic1394_enable_sbp2, \
                                   forensic1394_get_devices
from forensic1394.device import Device

class Bus(object):
    def __init__(self):
        # Allocate a new bus handle; _as_parameter_ allows passing of self
        self._as_parameter_ = forensic1394_alloc()
        
        # Internal copy of the most recent device list
        self._devices = []
    
    def enable_sbp2(self):
        result = forensic1394_enable_sbp2(self)
        
        if result is not ResultCode.Success:
            raise IOError
        
    def devices(self):
        # Mark any active device handles as being stale, preventing further use
        for d in self._devices:
            d._stale = True
        
        # Clear the existing device list
        self._devices = []
        
        ndev = c_int(0)
        
        # Query the list of devices attached to the system
        devlist = forensic1394_get_devices(self, byref(ndev), None)
        
        # ndev contains the number of devices on success; or -ve error code
        if ndev.value is ResultCode.NoPerm:
            raise IOError
        
        # Create Device instances for the devices found
        for i in range(0, ndev.value):
            self._devices.append(Device(self, devlist[i]))
        
        # Return a copy of the device list
        return self._devices[:]
        
    def __del__(self):
        forensic1394_destroy(self)