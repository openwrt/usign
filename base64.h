#ifndef __BASE64_H
#define __BASE64_H

int b64_encode(const void *src, size_t src_len,
	       void *dest, size_t dest_len);

int b64_decode(const void *src, void *dest, size_t dest_len);

#define B64_ENCODE_LEN(_len)	((((_len) + 2) / 3) * 4 + 1)
#define B64_DECODE_LEN(_len)	(((_len) / 4) * 3 + 1)

#endif
