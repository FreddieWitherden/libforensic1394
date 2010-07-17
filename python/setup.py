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

from distutils.core import setup

# Standard distutils setup
setup(name='Forensic1394',
      version='0.1',
      description='Python interface to libforensic1394',
      author='Freddie Witherden',
      author_email='freddie@witherden.org',
      url='http://freddie.witherden.org/tools/forensic1394/',
      packages=['forensic1394'])