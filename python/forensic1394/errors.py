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

class ResultCode(object):
    """
    Possible result codes from a forensic1394 function call.  These are
    extracted from the forensic1394.h file.
    """
    Success     = 0
    OtherError  = -1
    BusReset    = -2
    NoPerm      = -3
    Busy        = -4
    IOError     = -5
    IOSize      = -6
    IOTimeout   = -7

class Forensic1394Exception(Exception):
    pass

class Forensic1394ImportError(Forensic1394Exception, ImportError):
    pass

class Forensic1394BusReset(Forensic1394Exception, IOError):
    pass

class Forensic1394StaleHandle(Forensic1394Exception, IOError):
    pass

def process_result(result, fn, args):
    # Call was successful
    if result == ResultCode.Success:
        return

    # Perform a local import to avoid cyclic dependencies
    from forensic1394.functions import forensic1394_get_result_str

    err = fn.__name__ + ": " + forensic1394_get_result_str(result).decode()

    # Decide which exception to throw
    if result == ResultCode.BusReset:
        raise Forensic1394BusReset(err)
    else:
        raise IOError(err)
