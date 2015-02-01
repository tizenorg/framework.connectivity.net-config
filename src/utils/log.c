/*
 * Network Configuration Module
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <glib.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>

#include "log.h"

#define LOG_FILE_PATH	"/opt/usr/data/network/netconfig.log"
#define MAX_LOG_SIZE	1 * 1024 * 1024
#define MAX_LOG_COUNT	1

static FILE *log_file = NULL;

static inline void __netconfig_log_update_file_revision(int rev)
{
	int next_log_rev = 0;
	char *log_file = NULL;
	char *next_log_file = NULL;

	next_log_rev = rev + 1;

	log_file = g_strdup_printf("%s.%d", LOG_FILE_PATH, rev);
	next_log_file = g_strdup_printf("%s.%d", LOG_FILE_PATH, next_log_rev);

	if (next_log_rev >= MAX_LOG_COUNT)
		remove(next_log_file);

	if (access(next_log_file, F_OK) == 0)
		__netconfig_log_update_file_revision(next_log_rev);

	if (rename(log_file, next_log_file) != 0)
		remove(log_file);

	g_free(log_file);
	g_free(next_log_file);
}

static inline void __netconfig_log_make_backup(void)
{
	const int rev = 0;
	char *backup = NULL;

	backup = g_strdup_printf("%s.%d", LOG_FILE_PATH, rev);

	if (access(backup, F_OK) == 0)
		__netconfig_log_update_file_revision(rev);

	if (rename(LOG_FILE_PATH, backup) != 0)
		remove(LOG_FILE_PATH);

	g_free(backup);
}

static inline void __netconfig_log_get_local_time(char *strtime, const int size)
{
	time_t buf;
	struct tm *local_ptm;

	time(&buf);
	buf = time(NULL);
	local_ptm = localtime(&buf);

	strftime(strtime, size, "%m/%d %H:%M:%S", local_ptm);
}

void __netconfig_debug(const char *format, ...)
{
	va_list ap;
	int log_size = 0;
	struct stat buf;
	char str[256];
	char strtime[40];

	if (log_file == NULL)
		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");

	if (log_file == NULL)
		return;

	va_start(ap, format);

	if (fstat(fileno(log_file), &buf) == 0)
		log_size = buf.st_size;

	if (log_size >= MAX_LOG_SIZE) {
		fclose(log_file);
		log_file = NULL;

		__netconfig_log_make_backup();

		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");

		if (log_file == NULL) {
			va_end(ap);
			return;
		}
	}

	__netconfig_log_get_local_time(strtime, sizeof(strtime));

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		fprintf(log_file, "%s %s", strtime, str);

	va_end(ap);
}
