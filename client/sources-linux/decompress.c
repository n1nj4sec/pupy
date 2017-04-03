#include <zlib.h>
#include "decompress.h"

/* Zpipe code */

#define CHUNK 8196

int decompress(int fd, const char *buf, size_t size) {
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, 15+32);

    if (ret != Z_OK)
        return ret;

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = size < CHUNK? size : CHUNK;
        if (strm.avail_in == 0)
            break;

        strm.next_in = (unsigned char *) buf;

        buf += strm.avail_in;
        size -= strm.avail_in;

        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = CHUNK - strm.avail_out;
            unsigned char *ptr = out;
            while (have) {
                int n = write(fd, ptr, have);
                if (n == -1) {
                    (void)inflateEnd(&strm);
                    return Z_ERRNO;
                }
                have -= n;
                ptr += n;
            }

        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}
