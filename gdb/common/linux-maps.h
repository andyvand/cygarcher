/* Linux-specific memory maps manipulation routines.
   Copyright (C) 2014 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef COMMON_LINUX_MAPS_H
#define COMMON_LINUX_MAPS_H

extern void
  read_mapping (const char *line,
		ULONGEST *addr, ULONGEST *endaddr,
		const char **permissions, size_t *permissions_len,
		ULONGEST *offset,
		const char **device, size_t *device_len,
		ULONGEST *inode,
		const char **filename);

/* Callback function for linux_find_memory_regions_full.  If it returns
   non-zero linux_find_memory_regions_full returns immediately with that
   value.  */

typedef int linux_find_memory_region_ftype (ULONGEST vaddr, ULONGEST size,
					    ULONGEST offset, ULONGEST inode,
					    int read, int write,
					    int exec, int modified,
					    const char *filename,
					    void *data);

extern int
  linux_find_memory_regions_full (pid_t pid,
				  linux_find_memory_region_ftype *func,
				  void *func_data, void **memory_to_free_ptr);

#endif /* COMMON_LINUX_MAPS_H */
