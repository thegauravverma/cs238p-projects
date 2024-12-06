/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * main.c
 */

#include <signal.h>
#include "system.h"

static volatile int done;

static void
_signal_(int signum)
{
	assert(SIGINT == signum);

	done = 1;
}

struct net_stats
{
	int received;
	int sent;
};

double
cpu_util(const char *s)
{
	static unsigned sum_, vector_[7];
	unsigned sum, vector[7];
	const char *p;
	double util;
	uint64_t i;

	/*
		user
		nice
		system
		idle
		iowait
		irq
		softirq
	*/

	if (!(p = strstr(s, " ")) ||
			(7 != sscanf(p,
									 "%u %u %u %u %u %u %u",
									 &vector[0],
									 &vector[1],
									 &vector[2],
									 &vector[3],
									 &vector[4],
									 &vector[5],
									 &vector[6])))
	{
		return 0;
	}
	sum = 0.0;
	for (i = 0; i < ARRAY_SIZE(vector); ++i)
	{
		sum += vector[i];
	}
	util = (1.0 - (vector[3] - vector_[3]) / (double)(sum - sum_)) * 100.0;
	sum_ = sum;
	for (i = 0; i < ARRAY_SIZE(vector); ++i)
	{
		vector_[i] = vector[i];
	}

	return util;
}

int disk_io_time()
{
	const char *const DISK_STAT = "/proc/diskstats";

	FILE *disk_file;
	static unsigned sum_;
	unsigned sum = 0, vector[20], diff;
	char diskstat_line[1024];
	const char *p;
	char str[20];
	int scanned;

	if (!(disk_file = fopen(DISK_STAT, "r")))
	{
		TRACE("fopen()");
		return -1;
	}

	while (fgets(diskstat_line, sizeof(diskstat_line), disk_file))
	{
		if (!(p = strstr(diskstat_line, " ")) ||
				(20 != (scanned = sscanf(p,
																 "%u %u %s %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u",
																 &vector[0],
																 &vector[1],
																 str,
																 &vector[3],
																 &vector[4],
																 &vector[5],
																 &vector[6],
																 &vector[7],
																 &vector[8],
																 &vector[9],
																 &vector[10],
																 &vector[11],
																 &vector[12],
																 &vector[13],
																 &vector[14],
																 &vector[15],
																 &vector[16],
																 &vector[17],
																 &vector[18],
																 &vector[19]))))
		{
			return 0;
		}
		sum += vector[12];
	}
	diff = sum - sum_;
	sum_ = sum;

	fclose(disk_file);
	return diff;
}

int netbytes(struct net_stats *net_stats)
{
	const char *const NET_STAT = "/proc/net/dev";

	FILE *net_file;
	static unsigned sumRec_, sumSnt_;
	unsigned sumRec = 0, sumSnt = 0, vector[17];
	const char *p;
	char netstat_line[1024];
	int scanned;
	char str[20];

	if (!(net_file = fopen(NET_STAT, "r")))
	{
		TRACE("fopen()");
		return -1;
	}

	/* Eat two header lines */
	if (!fgets(netstat_line, sizeof(netstat_line), net_file) ||
			!fgets(netstat_line, sizeof(netstat_line), net_file))
	{
		TRACE("Couldn't read header lines for netstat.");
		return -1;
	}

	while (fgets(netstat_line, sizeof(netstat_line), net_file))
	{
		if (!(p = strstr(netstat_line, " ")) ||
				(17 != (scanned = sscanf(p,
																 "%s %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u",
																 str,
																 &vector[1],
																 &vector[2],
																 &vector[3],
																 &vector[4],
																 &vector[5],
																 &vector[6],
																 &vector[7],
																 &vector[8],
																 &vector[9],
																 &vector[10],
																 &vector[11],
																 &vector[12],
																 &vector[13],
																 &vector[14],
																 &vector[15],
																 &vector[16]))))
		{
			/* Bad read, but that's okay.*/
			printf("Bad read!\n");
			return 0;
		}
		sumRec += vector[1];
		sumSnt += vector[9];
	}

	net_stats->received = sumRec - sumRec_;
	sumRec_ = sumRec;
	net_stats->sent = sumSnt - sumSnt_;
	sumSnt_ = sumSnt;

	fclose(net_file);
	return 0;
}

int main(int argc, char *argv[])
{
	const char *const PROC_STAT = "/proc/stat";
	char line[1024];
	FILE *file;

	struct net_stats *net_stats;
	if (!(net_stats = malloc(sizeof(struct net_stats))))
	{
		TRACE("Could not allocate net_stats.");
		return -1;
	}

	UNUSED(argc);
	UNUSED(argv);

	if (SIG_ERR == signal(SIGINT, _signal_))
	{
		TRACE("signal()");
		return -1;
	}
	printf("  CPU%%  Disc IO  Net Bytes Received  Net Bytes Sent\n");
	while (!done)
	{
		if (!(file = fopen(PROC_STAT, "r")))
		{
			TRACE("fopen()");
			return -1;
		}
		if (fgets(line, sizeof(line), file))
		{
			printf("\r%5.1f%% ", cpu_util(line));
			fflush(stdout);
		}

		printf("%8d", disk_io_time());

		if (netbytes(net_stats))
		{
			TRACE(0);
			return -1;
		}
		printf("%20d%16d              ", net_stats->received, net_stats->sent);

		us_sleep(500000);
		fclose(file);
	}

	free(net_stats);
	printf("\nDone!   \n");
	return 0;
}
