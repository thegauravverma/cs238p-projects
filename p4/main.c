/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * main.c
 */

#include "term.h"
#include "kvdb.h"
#include "logfs.h"
#include <pthread.h>

#define SLEN(s) (safe_strlen(s) + 1)

#define TEST(f, m)                            \
	do                                          \
	{                                           \
		uint64_t t = ref_time();                  \
		if (f())                                  \
		{                                         \
			t = ref_time() - t;                     \
			term_color(TERM_COLOR_RED);             \
			term_bold();                            \
			printf("\t [FAIL] ");                   \
			term_reset();                           \
			printf("%20s %6.1fs\n", (m), 1e-6 * t); \
		}                                         \
		else                                      \
		{                                         \
			t = ref_time() - t;                     \
			term_color(TERM_COLOR_GREEN);           \
			term_bold();                            \
			printf("\t [PASS] ");                   \
			term_reset();                           \
			printf("%20s %6.1fs\n", (m), 1e-6 * t); \
		}                                         \
	} while (0)

struct logfs
{
	void *writebuffer;					/* Buffer to write to, aligned */
	void *writebuffer_toDelete; /* Buffer to write to, unaligned to delete on close */

	void *readbuffer;					 /* Buffer to read from, aligned */
	void *readbuffer_toDelete; /* Buffer to read from, unaligned to delete on close */
	uint64_t *readblock_check; /* A list of a block attached to each readbuffer slot */
	uint8_t *readblock_valid;	 /* A list of if the slot is valid */

	size_t BUFFER_SIZE; /* The buffer size. A constant */
	size_t BLOCK_SIZE;	/* The block size. A constant */
	size_t head;				/* The offset on the buffer to write to */
	size_t tail;				/* The offset on the buffer to read from (for writing to disk) */

	pthread_t writer;						/* Our worker thread for writing */
	pthread_mutex_t lock;				/* A mutex to lock down our threadwork */
	pthread_cond_t data_avail;	/* Flag to mark if we have data available (if we can write more to disk) */
	pthread_cond_t space_avail; /* Flag to mark if we have space available (if we can write more to buffer) */

	struct device *device; /* Device */

	int done; /* If we are done. For closing up threadwork */
};

static const char *PATHNAME;

static void
mk_object(char *key,
					char *val,
					uint64_t key_len,
					uint64_t val_len,
					uint64_t *key_len_,
					uint64_t *val_len_,
					uint64_t i,
					char code)
{
	const uint64_t MIN_LEN = 16;
	char key_[16], val_[16];
	uint64_t j, h;

	assert(MIN_LEN < key_len);
	assert(MIN_LEN < val_len);

	srand((int)i + 100);
	h = ((uint64_t)rand() << 32) + (uint64_t)rand();
	(*key_len_) = MIN_LEN + (h % (key_len - MIN_LEN));
	(*val_len_) = MIN_LEN + (h % (val_len - MIN_LEN));
	for (j = 0; j < (*key_len_); ++j)
	{
		key[j] = (char)(h % 256);
	}
	for (j = 0; j < (*val_len_); ++j)
	{
		val[j] = (char)(h % 256);
	}
	safe_sprintf(key_, MIN_LEN, "k%lu", (unsigned long)i);
	safe_sprintf(val_, MIN_LEN, "%c%lu", code, (unsigned long)i);
	memmove(key + (*key_len_) - MIN_LEN, key_, safe_strlen(key_));
	memmove(val + (*val_len_) - MIN_LEN, val_, safe_strlen(val_));
}

static int
read_write(const uint64_t N, const uint64_t K, const uint64_t V)
{
	uint64_t i, j, key_len, val_len, val_len_;
	void *key, *val, *val_;
	struct kvdb *kvdb;

	key = val = val_ = NULL;
	if (!(kvdb = kvdb_open(PATHNAME)))
	{
		TRACE(0);
		return -1;
	}
	if (!(key = malloc(K)) || !(val = malloc(V)) || !(val_ = malloc(V)))
	{
		kvdb_close(kvdb);
		FREE(key);
		FREE(val);
		FREE(val_);
		TRACE("out of memory");
		return -1;
	}

	/* insert */

	for (i = 0; i < N; ++i)
	{
		mk_object(key, val, K, V, &key_len, &val_len, i, 'i');
		val_len_ = V;
		if (kvdb_insert(kvdb, key, key_len, val, val_len) ||
				kvdb_lookup(kvdb, key, key_len, val_, &val_len_) ||
				(val_len != val_len_) ||
				memcmp(val, val_, val_len_) ||
				((i + 1) != kvdb_size(kvdb)) ||
				(0 != kvdb_waste(kvdb)))
		{
			kvdb_close(kvdb);
			FREE(key);
			FREE(val);
			FREE(val_);
			TRACE("software");
			return -1;
		}
	}

	/* lookup */

	for (i = 0; i < N; ++i)
	{
		j = rand() % N;
		mk_object(key, val, K, V, &key_len, &val_len, j, 'i');
		val_len_ = V;
		if (kvdb_lookup(kvdb, key, key_len, val_, &val_len_) ||
				(val_len != val_len_) ||
				memcmp(val, val_, val_len_) ||
				(N != kvdb_size(kvdb)) ||
				(0 != kvdb_waste(kvdb)))
		{
			kvdb_close(kvdb);
			FREE(key);
			FREE(val);
			FREE(val_);
			TRACE("software");
			return -1;
		}
	}
	kvdb_close(kvdb);
	FREE(key);
	FREE(val);
	FREE(val_);
	return 0;
}

static int read_write_large(void) { return read_write(1234, 1234, 1234); }
static int read_write_small(void) { return read_write(1234, 123, 123); }
static int read_write_single(void) { return read_write(1, 23, 23); }

static int
heavy_rewrite(void)
{
	const char *const KEY = "KEY";
	uint64_t i, n, val_len_;
	char val[64], val_[64];
	struct kvdb *kvdb;

	n = 9876;
	if (!(kvdb = kvdb_open(PATHNAME)))
	{
		TRACE(0);
		return -1;
	}
	for (i = 0; i < n; ++i)
	{
		safe_sprintf(val, sizeof(val), "v%lu", (unsigned long)i);
		val_len_ = sizeof(val_);
		if (kvdb_update(kvdb, KEY, SLEN(KEY), val, SLEN(val)) ||
				kvdb_lookup(kvdb, KEY, SLEN(KEY), val_, &val_len_) ||
				(SLEN(val) != val_len_) ||
				memcmp(val, val_, val_len_) ||
				(1 != kvdb_size(kvdb)) ||
				(i != kvdb_waste(kvdb)))
		{
			kvdb_close(kvdb);
			TRACE("software");
			return -1;
		}
	}
	kvdb_close(kvdb);
	return 0;
}

static int
basicer_logic_restore(void)
{
	char *buf, *buf2;
	struct logfs *logfs, *logfs2;
	buf = malloc(sizeof(char) * 12);
	buf2 = malloc(sizeof(char) * 12);
	logfs = logfs_open("block_device");
	logfs_append(logfs, "Hello", 6);
	logfs_read(logfs, buf, 0, 6);
	printf("First: [%s]\n", buf);
	logfs_close(logfs);

	logfs2 = logfs_open("block_device");
	logfs_append(logfs2, "World", 6);
	logfs_read(logfs2, buf2, 0, 12);
	printf("Second: [%s]\n", buf2);
	logfs_close(logfs2);
	strcat(buf2, (char *)shift(buf2, 6));
	printf("[%s]\n", buf2);
	if (0 != strcmp(buf2, "HelloWorld"))
	{
		return -1;
	}

	free(buf);
	free(buf2);
	return 0;
}

static int test_store_restore_state(void)
{
	const char *const KEY = "KEY";
	const char *const VAL = "VAL";
	struct kvdb *kvdb;
	uint64_t val_len;
	char val[32];

	if (!(kvdb = kvdb_open(PATHNAME)))
	{
		TRACE(0);
		return -1;
	}
	if ((0 != kvdb_size(kvdb)) || (0 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* insert, lookup */

	val_len = sizeof(val);
	if (kvdb_insert(kvdb, KEY, SLEN(KEY), VAL, SLEN(VAL)) ||
			kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL) != val_len) ||
			memcmp(VAL, val, val_len) ||
			(1 != kvdb_size(kvdb)) ||
			(0 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	TRACE("Got to the end!");
	kvdb_close(kvdb);

	if (!(kvdb = kvdb_open(PATHNAME)))
	{
		TRACE(0);
		return -1;
	}

	/* lookup */

	val_len = sizeof(val);
	if (kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL) != val_len) ||
			memcmp(VAL, val, val_len) ||
			(1 != kvdb_size(kvdb)) ||
			(0 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	kvdb_close(kvdb);
	return 0;
}

static int
basicer_logic(void)
{
	char *buf;
	struct logfs *logfs;
	buf = malloc(sizeof(char) * 12);
	logfs = logfs_open("block_device");
	logfs_append(logfs, "Hello", 6);
	logfs_read(logfs, buf, 0, 6);
	printf("First: [%s]\n", buf);

	logfs_append(logfs, "World", 6);
	logfs_read(logfs, buf, 0, 12);
	printf("Second: [%s%s]\n", buf, (char *)shift(buf, 6));

	logfs_close(logfs);
	free(buf);
	return 0;
}

static int
basic_logic(void)
{
	const char *const KEY = "KEY";
	const char *const VAL1 = "VAL";
	const char *const VAL2 = "val2";
	const char *const VAL3 = "val2VAL";
	struct kvdb *kvdb;
	uint64_t val_len;
	char val[32];

	if (!(kvdb = kvdb_open(PATHNAME)))
	{
		TRACE(0);
		return -1;
	}
	if ((0 != kvdb_size(kvdb)) || (0 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* invalid lookup */

	val_len = 0;
	if ((+1 != kvdb_lookup(kvdb, KEY, SLEN(KEY), 0, 0)) ||
			(+1 != kvdb_lookup(kvdb, KEY, SLEN(KEY), 0, &val_len)) ||
			(+1 != kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len)) ||
			(0 != kvdb_size(kvdb)) ||
			(0 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* invalid replace */

	if ((+1 != kvdb_replace(kvdb, KEY, SLEN(KEY), VAL1, SLEN(VAL1))) ||
			(0 != kvdb_size(kvdb)) ||
			(0 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* insert, lookup, re-insert, lookup */

	val_len = sizeof(val);
	if (kvdb_insert(kvdb, KEY, SLEN(KEY), VAL1, SLEN(VAL1)) ||
			kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL1) != val_len) ||
			memcmp(VAL1, val, val_len) ||
			(+1 != kvdb_insert(kvdb, KEY, SLEN(KEY), VAL1, SLEN(VAL1))) ||
			kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL1) != val_len) ||
			memcmp(VAL1, val, val_len) ||
			(1 != kvdb_size(kvdb)) ||
			(0 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* replace, lookup, re-insert, lookup */

	val_len = sizeof(val);
	if (kvdb_replace(kvdb, KEY, SLEN(KEY), VAL2, SLEN(VAL2)) ||
			kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL2) != val_len) ||
			memcmp(VAL2, val, val_len) ||
			(+1 != kvdb_insert(kvdb, KEY, SLEN(KEY), VAL2, SLEN(VAL2))) ||
			kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL2) != val_len) ||
			memcmp(VAL2, val, val_len) ||
			(1 != kvdb_size(kvdb)) ||
			(1 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* update, lookup, re-insert, lookup */

	val_len = sizeof(val);
	if (kvdb_update(kvdb, KEY, SLEN(KEY), VAL3, SLEN(VAL3)) ||
			kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL3) != val_len) ||
			memcmp(VAL3, val, val_len) ||
			(+1 != kvdb_insert(kvdb, KEY, SLEN(KEY), VAL3, SLEN(VAL3))) ||
			kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL3) != val_len) ||
			memcmp(VAL3, val, val_len) ||
			(1 != kvdb_size(kvdb)) ||
			(2 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* lookup */

	val_len = sizeof(val);
	if (kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL3) != val_len) ||
			memcmp(VAL3, val, val_len) ||
			(1 != kvdb_size(kvdb)) ||
			(2 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}

	/* remove */

	val_len = sizeof(val);
	if (kvdb_remove(kvdb, KEY, SLEN(KEY), val, &val_len) ||
			(SLEN(VAL3) != val_len) ||
			memcmp(VAL3, val, val_len) ||
			(+1 != kvdb_lookup(kvdb, KEY, SLEN(KEY), val, &val_len)) ||
			(0 != kvdb_size(kvdb)) ||
			(3 != kvdb_waste(kvdb)))
	{
		kvdb_close(kvdb);
		TRACE("software");
		return -1;
	}
	kvdb_close(kvdb);
	return 0;
}

int main(int argc, char *argv[])
{
	if (2 != argc)
	{
		printf("usage: %s block-device\n", argv[0]);
		return -1;
	}

	/* initialize */

	PATHNAME = argv[1];
	term_init(0);

	/* prelude */

	term_bold();
	term_color(TERM_COLOR_BLUE);
	printf("---------- TEST BEG ----------\n");
	term_reset();

	/* test */

	/*
	TEST(basicer_logic, "basicer_logic");
		TEST(basic_logic, "basic_logic");
		TEST(read_write_single, "read_write_single");
		TEST(read_write_small, "read_write_small");
		TEST(read_write_large, "read_write_large");
		TEST(heavy_rewrite, "heavy_rewrite");
		UNUSED(test_store_restore_state);
	*/

	TEST(basicer_logic_restore, "basicer_logic_restore");
	UNUSED(basicer_logic);
	UNUSED(basic_logic);
	UNUSED(read_write_single);
	UNUSED(read_write_small);
	UNUSED(read_write_large);
	UNUSED(heavy_rewrite);
	UNUSED(test_store_restore_state);

	/* postlude */

	term_bold();
	term_color(TERM_COLOR_BLUE);
	printf("---------- TEST END ----------\n");
	term_reset();
	return 0;
}
