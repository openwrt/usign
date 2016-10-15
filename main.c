/*
 * usign - tiny signify replacement
 *
 * Copyright (C) 2015 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#include "base64.h"
#include "edsign.h"
#include "ed25519.h"

struct pubkey {
	char pkalg[2];
	uint8_t fingerprint[8];
	uint8_t pubkey[EDSIGN_PUBLIC_KEY_SIZE];
};

struct seckey {
	char pkalg[2];
	char kdfalg[2];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t checksum[8];
	uint8_t fingerprint[8];
	uint8_t seckey[64];
};

struct sig {
	char pkalg[2];
	uint8_t fingerprint[8];
	uint8_t sig[EDSIGN_SIGNATURE_SIZE];
};

static const char *pubkeyfile;
static const char *pubkeydir;
static const char *sigfile;
static const char *seckeyfile;
static const char *comment;
static bool quiet;
static enum {
	CMD_NONE,
	CMD_VERIFY,
	CMD_SIGN,
	CMD_FINGERPRINT,
	CMD_GENERATE,
} cmd = CMD_NONE;

static uint64_t fingerprint_u64(const uint8_t *data)
{
	uint64_t val = 0;

#define ADD(_v) val = (val << 8) | _v
	ADD(data[0]);
	ADD(data[1]);
	ADD(data[2]);
	ADD(data[3]);
	ADD(data[4]);
	ADD(data[5]);
	ADD(data[6]);
	ADD(data[7]);
#undef ADD

	return val;
}

static void
file_error(const char *filename, bool _read)
{
	if (!quiet || cmd != CMD_VERIFY)
		fprintf(stderr, "Cannot open file '%s' for %s\n", filename,
			_read ? "reading" : "writing");
	exit(1);
}

static FILE *
open_file(const char *filename, bool _read)
{
	FILE *f;

	if (!strcmp(filename, "-"))
		return _read ? stdin : stdout;

	f = fopen(filename, _read ? "r" : "w");
	if (!f)
		file_error(filename, _read);

	return f;
}

static void
get_file(const char *filename, char *buf, int buflen)
{
	FILE *f = open_file(filename, true);
	int len;

	while (1) {
		char *cur = fgets(buf, buflen, f);

		if (!cur) {
			fprintf(stderr, "Premature end of file\n");
			exit(1);
		}

		if (strchr(buf, '\n'))
			break;
	}

	len = fread(buf, 1, buflen - 1, f);
	buf[len] = 0;
}

static bool
get_base64_file(const char *file, void *dest, int size, void *buf, int buflen)
{
	get_file(file, buf, buflen - 1);
	return b64_decode(buf, dest, size) == size;
}

static void write_file(const char *name, const uint8_t *fingerprint,
		       const char *prefix, char *buf)
{
	FILE *f;

	f = open_file(name, false);
	fputs("untrusted comment: ", f);
	if (comment)
		fputs(comment, f);
	else
		fprintf(f, "%s %"PRIx64, prefix,
			fingerprint_u64(fingerprint));
	fprintf(f, "\n%s\n", buf);
	fclose(f);
}

static int verify(const char *msgfile)
{
	struct pubkey pkey;
	struct sig sig;
	struct edsign_verify_state vst;
	FILE *f;
	char buf[512];

	f = open_file(msgfile, true);
	if (!f) {
		fprintf(stderr, "Cannot open message file\n");
		return 1;
	}

	if (!get_base64_file(sigfile, &sig, sizeof(sig), buf, sizeof(buf)) ||
	    memcmp(sig.pkalg, "Ed", 2) != 0) {
		fprintf(stderr, "Failed to decode signature\n");
		return 1;
	}

	if (!pubkeyfile) {
		snprintf(buf, sizeof(buf), "%s/%"PRIx64, pubkeydir,
			 fingerprint_u64(sig.fingerprint));
		pubkeyfile = buf;
	}

	if (!get_base64_file(pubkeyfile, &pkey, sizeof(pkey), buf, sizeof(buf)) ||
	    memcmp(pkey.pkalg, "Ed", 2) != 0) {
		fprintf(stderr, "Failed to decode public key\n");
		return 1;
	}

	edsign_verify_init(&vst, sig.sig, pkey.pubkey);

	while (!feof(f)) {
		int len = fread(buf, 1, sizeof(buf), f);
		edsign_verify_add(&vst, buf, len);
	}
	fclose(f);

	if (!edsign_verify(&vst, sig.sig, pkey.pubkey)) {
		if (!quiet)
			fprintf(stderr, "verification failed\n");
		return 1;
	}

	if (!quiet)
		fprintf(stderr, "OK\n");
	return 0;
}

static int sign(const char *msgfile)
{
	struct seckey skey;
	struct sig sig = {
		.pkalg = "Ed",
	};
	struct stat st;
	char buf[512];
	void *pubkey = buf;
	long mlen;
	void *m;
	int mfd;

	if (!get_base64_file(seckeyfile, &skey, sizeof(skey), buf, sizeof(buf)) ||
	    memcmp(skey.pkalg, "Ed", 2) != 0) {
		fprintf(stderr, "Failed to decode secret key\n");
		return 1;
	}

	if (skey.kdfrounds) {
		fprintf(stderr, "Password protected secret keys are not supported\n");
		return 1;
	}

	mfd = open(msgfile, O_RDONLY, 0);
	if (mfd < 0 || fstat(mfd, &st) < 0 ||
		(m = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, mfd, 0)) == MAP_FAILED) {
		if (mfd >= 0)
			close(mfd);
		perror("Cannot open message file");
		return 1;
	}
	mlen = st.st_size;

	memcpy(sig.fingerprint, skey.fingerprint, sizeof(sig.fingerprint));
	edsign_sec_to_pub(pubkey, skey.seckey);
	edsign_sign(sig.sig, pubkey, skey.seckey, m, mlen);
	munmap(m, mlen);
	close(mfd);

	if (b64_encode(&sig, sizeof(sig), buf, sizeof(buf)) < 0)
		return 1;

	write_file(sigfile, sig.fingerprint, "signed by key", buf);

	return 0;
}

static int fingerprint(void)
{
	struct seckey skey;
	struct pubkey pkey;
	struct sig sig;
	char buf[512];
	uint8_t *fp;

	if (seckeyfile &&
	    get_base64_file(seckeyfile, &skey, sizeof(skey), buf, sizeof(buf)))
		fp = skey.fingerprint;
	else if (pubkeyfile &&
	         get_base64_file(pubkeyfile, &pkey, sizeof(pkey), buf, sizeof(buf)))
		fp = pkey.fingerprint;
	else if (sigfile &&
	         get_base64_file(sigfile, &sig, sizeof(sig), buf, sizeof(buf)))
		fp = sig.fingerprint;
	else
		return 1;

	fprintf(stdout, "%"PRIx64"\n", fingerprint_u64(fp));
	return 0;
}

static int generate(void)
{
	struct seckey skey = {
		.pkalg = "Ed",
		.kdfalg = "BK",
		.kdfrounds = 0,
	};
	struct pubkey pkey = {
		.pkalg = "Ed",
	};
	struct sha512_state s;
	char buf[512];
	FILE *f;

	f = fopen("/dev/urandom", "r");
	if (!f ||
	    fread(skey.fingerprint, sizeof(skey.fingerprint), 1, f) != 1 ||
	    fread(skey.seckey, EDSIGN_SECRET_KEY_SIZE, 1, f) != 1 ||
	    fread(skey.salt, sizeof(skey.salt), 1, f) != 1) {
		fprintf(stderr, "Can't read data from /dev/urandom\n");
		return 1;
	}
	if (f)
		fclose(f);

	ed25519_prepare(skey.seckey);
	edsign_sec_to_pub(skey.seckey + 32, skey.seckey);

	sha512_init(&s);
	sha512_add(&s, skey.seckey, sizeof(skey.seckey));
	memcpy(skey.checksum, sha512_final_get(&s), sizeof(skey.checksum));

	if (b64_encode(&skey, sizeof(skey), buf, sizeof(buf)) < 0)
		return 1;

	write_file(seckeyfile, skey.fingerprint, "private key", buf);

	memcpy(pkey.fingerprint, skey.fingerprint, sizeof(pkey.fingerprint));
	memcpy(pkey.pubkey, skey.seckey + 32, sizeof(pkey.pubkey));

	if (b64_encode(&pkey, sizeof(pkey), buf, sizeof(buf)) < 0)
		return 1;

	write_file(pubkeyfile, pkey.fingerprint, "public key", buf);

	return 0;
}

static int usage(const char *cmd)
{
	fprintf(stderr,
		"Usage: %s <command> <options>\n"
		"Commands:\n"
		"  -V:			verify (needs at least -m and -p|-P)\n"
		"  -S:			sign (needs at least -m and -s)\n"
		"  -F:			print key fingerprint of public/secret key or signature\n"
		"  -G:			generate a new keypair (needs at least -p and -s)\n"
		"Options:\n"
		"  -c <comment>: 	add comment to keys\n"
		"  -m <file>:		message file\n"
		"  -p <file>:		public key file (verify/fingerprint only)\n"
		"  -P <path>:		public key directory (verify only)\n"
		"  -q:			quiet (do not print verification result, use return code only)\n"
		"  -s <file>:		secret key file (sign/fingerprint only)\n"
		"  -x <file>:		signature file (defaults to <message file>.sig)\n"
		"\n",
		cmd);
	return 1;
}

static void set_cmd(const char *prog, int val)
{
	if (cmd != CMD_NONE)
		exit(usage(prog));

	cmd = val;
}

int main(int argc, char **argv)
{
	const char *msgfile = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "FGSVc:m:P:p:qs:x:")) != -1) {
		switch (ch) {
		case 'V':
			set_cmd(argv[0], CMD_VERIFY);
			break;
		case 'S':
			set_cmd(argv[0], CMD_SIGN);
			break;
		case 'F':
			set_cmd(argv[0], CMD_FINGERPRINT);
			break;
		case 'G':
			set_cmd(argv[0], CMD_GENERATE);
			break;
		case 'c':
			comment = optarg;
			break;
		case 'm':
			msgfile = optarg;
			break;
		case 'P':
			pubkeydir = optarg;
			break;
		case 'p':
			pubkeyfile = optarg;
			break;
		case 's':
			seckeyfile = optarg;
			break;
		case 'x':
			sigfile = optarg;
			break;
		case 'q':
			quiet = true;
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (!sigfile && msgfile) {
		char *buf = alloca(strlen(msgfile) + 5);

		if (!strcmp(msgfile, "-")) {
			fprintf(stderr, "Need signature file when reading message from stdin\n");
			return 1;
		}

		sprintf(buf, "%s.sig", msgfile);
		sigfile = buf;
	}

	switch (cmd) {
	case CMD_VERIFY:
		if ((!pubkeyfile && !pubkeydir) || !msgfile)
			return usage(argv[0]);
		return verify(msgfile);
	case CMD_SIGN:
		if (!seckeyfile || !msgfile || !sigfile)
			return usage(argv[0]);
		return sign(msgfile);
	case CMD_FINGERPRINT:
		if (!!seckeyfile + !!pubkeyfile + !!sigfile != 1) {
			fprintf(stderr, "Need one secret/public key or signature\n");
			return usage(argv[0]);
		}
		return fingerprint();
	case CMD_GENERATE:
		if (!seckeyfile || !pubkeyfile)
			return usage(argv[0]);
		return generate();
	default:
		return usage(argv[0]);
	}
}
