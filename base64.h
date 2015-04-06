#ifndef __BASE64_H
#define __BASE64_H

int b64_ntop(const void *src, size_t src_len,
	     void *dest, size_t dest_len);

int b64_pton(const void *src, void *dest, size_t dest_len);

#define B64_DECODE_LEN(_len)	(((_len) / 4) * 3 + 1)
#define B64_ENCODE_LEN(_len)	((((_len) / 3) + 1) * 4 + 1)

#endif
