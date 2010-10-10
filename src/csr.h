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

#ifndef FORENSIC1394_CSR_H
#define FORENSIC1394_CSR_H

#include "common.h"

/*
 * Common definitions platform backends may find useful.
 */
#define CSR_KEY(x) (x >> 24)
#define CSR_VALUE(x) (x & 0x00ffffff)

#define CSR_DIRECTORY   0xc0
#define CSR_UNIT        0x11

#define CSR_REGISTER_BASE   ((int64_t) 0xfffff0000000)

#define CSR_CONFIG_ROM      0x400
#define CSR_CONFIG_ROM_END  0x800

#ifdef FORENSIC1394_LITTLE_ENDIAN
#define CSR_HOST_QUADLET(x) ((x >> 24)             \
                           | (x << 8 & 0x00ff0000) \
                           | (x >> 8 & 0x0000ff00) \
                           | (x << 24))
#else
#define CSR_HOST_QUADLET(x) (x)
#endif

/**
 * Extracts important artifacts fom dev->rom including the GUID of the device,
 *  including the maximum request size and product/vendor information.  This
 *  method should be called by platform backends after the CSR has been copied
 *  over.
 *
 *   \param dev The device.
 */
void common_parse_csr(forensic1394_dev *dev);

#endif // FORENSIC1394_CSR_H
