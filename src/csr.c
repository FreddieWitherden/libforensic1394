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

#include "csr.h"

#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define CSR_NQUAD(x) (x >> 16 & 0xff)
#define CRC_CRC16(x) (x & 0xffff)

#define CSR_1394_BUS        0x31333934

#define CSR_VENDOR_KEY      0x03
#define CSR_MODEL_KEY       0x17
#define CSR_DESC_LEAF_KEY   0x81

/**
 * Returns the length of the directory starting at \a rom[diroff].  This length
 *  is inclusive.  Before returning the length is checked to ensure that the
 *  entire directory resides in \a rom.
 *
 *   \param rom The CSR in host-endian order.
 *   \param diroff The offset in the ROM of the directory of interest.
 *  \return The inclusive length of the directory, or 0 if it is invalid.
 */
static size_t get_length(const uint32_t *rom, size_t diroff);

/**
 * Given the offset of a minimal ASCII descriptor leaf this function reads the
 *  string into \a buf, copying a maximum of \a maxb bytes.
 *
 *   \param rom The CSR in host-endian order.
 *   \param offset The offset of the leaf in the ROM.
 *   \param buf The buffer to copy the string into.
 *   \param maxb The maximum number of bytes to copy.
 */
static void parse_text_leaf(const uint32_t *rom, size_t offset,
                            char *buf, size_t maxb);

/**
 * Searches the (root) directory starting at \a diroff for a entry qualified by
 *  \a key and copies its value into \a value.  If the entry following the key
 *  is a pointer to a descriptor-leaf and \a bufval is non-NULL the textual
 *  descriptor will be copied into \a bufval.
 *
 *   \param rom The CSR in host-endian order.
 *   \param diroff The offset of the directory in the ROM.
 *   \param key The key to search the directory for.
 *   \param[out] value Where to copy the value to.
 *   \param[out] bufval Optional pointer to a string buffer to copy a textual
 *                      description of the value to (if any).
 *   \param buflen Maximum number of bytes to copy into the buffer.
 */
static void parse_key(const uint32_t *rom, size_t diroff, int key,
                      int *value, char *bufval, size_t buflen);


void common_parse_csr(forensic1394_dev *dev)
{    
    const uint32_t *rom = dev->rom;

    // Get the number of elements in the bus-block
    size_t buslen = get_length(rom, 0);

    // If less than five, give up
    if (buslen < 5)
    {
        return;
    }

    /*
     * The maximum request size is a 4-bit value starting at the 12th bit of the
     * third element of the ROM.  The value is the base-2 logarithm of the
     * maximum request size. (So a value of 10 corresponds to a size of 2^10 or
     * 2048 bytes.) In the case where the second element of the ROM is not equal
     * to CSR_1394_BUS then the third element is interpreted as being
     * bus-specific and hence ignored.
     */
    if (rom[1] == CSR_1394_BUS)
    {
        // Extract lg size from the ROM
        int lgsz = dev->rom[2] >> 12 & 0xf;

        // Size in bytes is 2^lgsz
        dev->max_req = 2 << lgsz;
    }
    // Otherwise just use the safe value of 512-bytes
    else
    {
        dev->max_req = 512;
    }

    /*
     * The GUID is a 48-bit integer split into two 32-bit components (the fourth
     * and fith elements of the ROM).
     */
    dev->guid = (int64_t) rom[3] << 32 | (int64_t) rom[4];

    /*
     * Get the vendor and model information from the root directory.  This is
     * located directly after the bus information block.
     */
    parse_key(rom, buslen, CSR_VENDOR_KEY, &dev->vendor_id,
              dev->vendor_name, sizeof(dev->vendor_name));
    parse_key(rom, buslen, CSR_MODEL_KEY, &dev->product_id,
              dev->product_name, sizeof(dev->product_name));
}

size_t get_length(const uint32_t *rom, size_t diroff)
{
    size_t nquad;
    
    // Ensure that diroff is inside the ROM
    if (diroff > 255)
    {
        return 0;
    }

    // Extract the number of quads
    nquad = CSR_NQUAD(rom[diroff]);

    // Ensure that the entire directory is inside the ROM
    if (diroff + nquad > 255)
    {
        return 0;
    }

    // Otherwise, we're good, return the length, including ourself
    return nquad + 1;
}

void parse_key(const uint32_t *rom, size_t diroff, int key,
               int *value, char *bufval, size_t buflen)
{
    size_t i;
    size_t nq = get_length(rom, diroff);

    for (i = 1; i < nq; i++)
    {
        uint32_t entry = rom[diroff + i];

        // See if the keys match
        if (CSR_KEY(entry) == key)
        {
            // Copy over the value and break
            *value = CSR_VALUE(entry);
            break;
        }
    }

    // If we found the key (++i < nq) see if there is a text leaf
    if (bufval
     && ++i < nq
     && CSR_KEY(rom[diroff + i]) == CSR_DESC_LEAF_KEY)
    {
        // Find the offset of the leaf
        size_t leafoff = diroff + i + CSR_VALUE(rom[diroff + i]);
        
        // Process the text leaf
        parse_text_leaf(rom, leafoff, bufval, buflen);
    }
}

void parse_text_leaf(const uint32_t *rom, size_t offset,
                     char *buf, size_t maxb)
{
    size_t i;
    size_t numq, numb;

    // Zero the string to ensure termination
    memset(buf, '\0', maxb);

    // Get the number of quads in the descriptor
    if ((numq = get_length(rom, offset)) == 0)
    {
        return;
    }

    // Use rom to walk through the leaf
    rom += offset + 1;

    // Ensure that we have a minimal ASCII text leaf
    if (*rom++ != 0 || *rom++ != 0)
    {
        return;
    }

    // Decide how many bytes we can safely copy into buf
    numb = MIN((numq - 3) * 4, maxb - 1);

    for (i = 0; i < numb; i++)
    {
        const int shift[] = { 24, 16, 8, 0 };
        
        // Copy the byte over in an endian-neutral manor
        buf[i] = (*(rom + i/4) >> shift[i%4]) & 0xff;
    }
}

