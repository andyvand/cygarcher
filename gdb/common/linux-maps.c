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

#ifdef GDBSERVER
#include "server.h"
#include <fcntl.h>
#include <unistd.h>
#else
#include "defs.h"
#include "target.h"
#endif

#include "linux-maps.h"
#include "gdb_assert.h"
#include <ctype.h>
#include <string.h>
#include "target-utils.h"

/* Service function for corefiles and info proc.  */

void
read_mapping (const char *line,
	      ULONGEST *addr, ULONGEST *endaddr,
	      const char **permissions, size_t *permissions_len,
	      ULONGEST *offset,
              const char **device, size_t *device_len,
	      ULONGEST *inode,
	      const char **filename)
{
  const char *p = line;

  *addr = strtoulst (p, &p, 16);
  if (*p == '-')
    p++;
  *endaddr = strtoulst (p, &p, 16);

  p = skip_spaces_const (p);
  *permissions = p;
  while (*p && !isspace (*p))
    p++;
  *permissions_len = p - *permissions;

  *offset = strtoulst (p, &p, 16);

  p = skip_spaces_const (p);
  *device = p;
  while (*p && !isspace (*p))
    p++;
  *device_len = p - *device;

  *inode = strtoulst (p, &p, 10);

  p = skip_spaces_const (p);
  *filename = p;
}

#ifdef GDBSERVER

static int
linux_find_memory_read_stralloc_1_pread (int handle, gdb_byte *read_buf,
                                         int len, ULONGEST offset,
					 int *target_errno)
{
  int retval = pread (handle, read_buf, len, offset);

  *target_errno = errno;
  return retval;
}

static LONGEST
linux_find_memory_read_stralloc_1 (const char *filename, gdb_byte **buf_p,
				   int padding)
{
  int fd;
  LONGEST retval;

  fd = open (filename, O_RDONLY);
  if (fd == -1)
    return -1;

  retval = read_alloc (buf_p, fd, linux_find_memory_read_stralloc_1_pread,
                       padding, NULL);

  close (fd);

  return retval;
}

#endif /* GDBSERVER */

static char *
linux_find_memory_read_stralloc (const char *filename)
{
#ifndef GDBSERVER
  return target_fileio_read_stralloc (filename);
#else /* GDBSERVER */
  return read_stralloc (filename, linux_find_memory_read_stralloc_1);
#endif /* GDBSERVER */
}

/* List memory regions in the inferior PID for a corefile.  Call FUNC
   with FUNC_DATA for each such region.  Return immediately with the
   value returned by FUNC if it is non-zero.  *MEMORY_TO_FREE_PTR should
   be registered to be freed automatically if called FUNC throws an
   exception.  MEMORY_TO_FREE_PTR can be also passed as NULL if it is
   not used.  Return -1 if error occurs, 0 if all memory regions have
   been processed or return the value from FUNC if FUNC returns
   non-zero.  */

int
linux_find_memory_regions_full (pid_t pid, linux_find_memory_region_ftype *func,
				void *func_data, void **memory_to_free_ptr)
{
  char mapsfilename[100];
  char *data;

  xsnprintf (mapsfilename, sizeof mapsfilename, "/proc/%d/smaps", (int) pid);
  data = linux_find_memory_read_stralloc (mapsfilename);
  if (data == NULL)
    {
      /* Older Linux kernels did not support /proc/PID/smaps.  */
      xsnprintf (mapsfilename, sizeof mapsfilename, "/proc/%d/maps", (int) pid);
      data = linux_find_memory_read_stralloc (mapsfilename);
    }
  if (data)
    {
      char *line;
      int retval = 0;

      if (memory_to_free_ptr != NULL)
	{
	  gdb_assert (*memory_to_free_ptr == NULL);
	  *memory_to_free_ptr = data;
	}

      line = strtok (data, "\n");
      while (line)
	{
	  ULONGEST addr, endaddr, offset, inode;
	  const char *permissions, *device, *filename;
	  size_t permissions_len, device_len;
	  int read, write, exec;
	  int modified = 0, has_anonymous = 0;

	  read_mapping (line, &addr, &endaddr, &permissions, &permissions_len,
			&offset, &device, &device_len, &inode, &filename);

	  /* Decode permissions.  */
	  read = (memchr (permissions, 'r', permissions_len) != 0);
	  write = (memchr (permissions, 'w', permissions_len) != 0);
	  exec = (memchr (permissions, 'x', permissions_len) != 0);

	  /* Try to detect if region was modified by parsing smaps counters.  */
	  for (line = strtok (NULL, "\n");
	       line && line[0] >= 'A' && line[0] <= 'Z';
	       line = strtok (NULL, "\n"))
	    {
	      char keyword[64 + 1];

	      if (sscanf (line, "%64s", keyword) != 1)
		{
		  warning (_("Error parsing {s,}maps file '%s'"), mapsfilename);
		  break;
		}
	      if (strcmp (keyword, "Anonymous:") == 0)
		has_anonymous = 1;
	      if (strcmp (keyword, "Shared_Dirty:") == 0
		  || strcmp (keyword, "Private_Dirty:") == 0
		  || strcmp (keyword, "Swap:") == 0
		  || strcmp (keyword, "Anonymous:") == 0)
		{
		  unsigned long number;

		  if (sscanf (line, "%*s%lu", &number) != 1)
		    {
		      warning (_("Error parsing {s,}maps file '%s' number"),
			       mapsfilename);
		      break;
		    }
		  if (number != 0)
		    modified = 1;
		}
	    }

	  /* Older Linux kernels did not support the "Anonymous:" counter.
	     If it is missing, we can't be sure - dump all the pages.  */
	  if (!has_anonymous)
	    modified = 1;

	  /* Invoke the callback function to create the corefile segment.  */
	  retval = func (addr, endaddr - addr, offset, inode,
			 read, write, exec, modified, filename, func_data);
	  if (retval != 0)
	    break;
	}

      if (memory_to_free_ptr != NULL)
	{
	  gdb_assert (data == *memory_to_free_ptr);
	  *memory_to_free_ptr = NULL;
	}
      xfree (data);
      return retval;
    }

  return -1;
}
