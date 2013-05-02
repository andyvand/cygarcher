/* Branch trace support for GDB, the GNU debugger.

   Copyright (C) 2013 Free Software Foundation, Inc.

   Contributed by Intel Corp. <markus.t.metzger@intel.com>

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

#include "defs.h"
#include "record.h"
#include "gdbthread.h"
#include "target.h"
#include "gdbcmd.h"
#include "disasm.h"
#include "observer.h"
#include "exceptions.h"
#include "cli/cli-utils.h"
#include "source.h"
#include "ui-out.h"
#include "symtab.h"
#include "filenames.h"
#include "regcache.h"
#include "frame-unwind.h"

/* The target_ops of record-btrace.  */
static struct target_ops record_btrace_ops;

/* A new thread observer enabling branch tracing for the new thread.  */
static struct observer *record_btrace_thread_observer;

/* Print a record-btrace debug message.  Use do ... while (0) to avoid
   ambiguities when used in if statements.  */

#define DEBUG(msg, args...)						\
  do									\
    {									\
      if (record_debug != 0)						\
        fprintf_unfiltered (gdb_stdlog,					\
			    "[record-btrace] " msg "\n", ##args);	\
    }									\
  while (0)


/* Update the branch trace for the current thread and return a pointer to its
   branch trace information struct.

   Throws an error if there is no thread or no trace.  This function never
   returns NULL.  */

static struct btrace_thread_info *
require_btrace (void)
{
  struct thread_info *tp;
  struct btrace_thread_info *btinfo;

  DEBUG ("require");

  tp = find_thread_ptid (inferior_ptid);
  if (tp == NULL)
    error (_("No thread."));

  btrace_fetch (tp);

  btinfo = &tp->btrace;

  if (btinfo->begin == NULL)
    error (_("No trace."));

  return btinfo;
}

/* Enable branch tracing for one thread.  Warn on errors.  */

static void
record_btrace_enable_warn (struct thread_info *tp)
{
  volatile struct gdb_exception error;

  TRY_CATCH (error, RETURN_MASK_ERROR)
    btrace_enable (tp);

  if (error.message != NULL)
    warning ("%s", error.message);
}

/* Callback function to disable branch tracing for one thread.  */

static void
record_btrace_disable_callback (void *arg)
{
  struct thread_info *tp;

  tp = arg;

  btrace_disable (tp);
}

/* Enable automatic tracing of new threads.  */

static void
record_btrace_auto_enable (void)
{
  DEBUG ("attach thread observer");

  record_btrace_thread_observer
    = observer_attach_new_thread (record_btrace_enable_warn);
}

/* Disable automatic tracing of new threads.  */

static void
record_btrace_auto_disable (void)
{
  /* The observer may have been detached, already.  */
  if (record_btrace_thread_observer == NULL)
    return;

  DEBUG ("detach thread observer");

  observer_detach_new_thread (record_btrace_thread_observer);
  record_btrace_thread_observer = NULL;
}

/* The to_open method of target record-btrace.  */

static void
record_btrace_open (char *args, int from_tty)
{
  struct cleanup *disable_chain;
  struct thread_info *tp;

  DEBUG ("open");

  if (RECORD_IS_USED)
    error (_("The process is already being recorded."));

  if (!target_has_execution)
    error (_("The program is not being run."));

  if (!target_supports_btrace ())
    error (_("Target does not support branch tracing."));

  gdb_assert (record_btrace_thread_observer == NULL);

  disable_chain = make_cleanup (null_cleanup, NULL);
  ALL_THREADS (tp)
    if (args == NULL || *args == 0 || number_is_in_list (args, tp->num))
      {
	btrace_enable (tp);

	make_cleanup (record_btrace_disable_callback, tp);
      }

  record_btrace_auto_enable ();

  push_target (&record_btrace_ops);

  observer_notify_record_changed (current_inferior (),  1);

  discard_cleanups (disable_chain);
}

/* The to_stop_recording method of target record-btrace.  */

static void
record_btrace_stop_recording (void)
{
  struct thread_info *tp;

  DEBUG ("stop recording");

  record_btrace_auto_disable ();

  ALL_THREADS (tp)
    if (tp->btrace.target != NULL)
      btrace_disable (tp);
}

/* The to_close method of target record-btrace.  */

static void
record_btrace_close (void)
{
  /* Make sure automatic recording gets disabled even if we did not stop
     recording before closing the record-btrace target.  */
  record_btrace_auto_disable ();

  /* We already stopped recording.  */
}

/* The to_info_record method of target record-btrace.  */

static void
record_btrace_info (void)
{
  struct btrace_thread_info *btinfo;
  struct btrace_function *bfun;
  struct thread_info *tp;
  unsigned int insts, funcs;

  DEBUG ("info");

  tp = find_thread_ptid (inferior_ptid);
  if (tp == NULL)
    error (_("No thread."));

  btrace_fetch (tp);

  btinfo = &tp->btrace;
  bfun = btinfo->end;
  insts = 0;
  funcs = 0;

  if (bfun != NULL)
    {
      funcs = bfun->number;
      insts = bfun->insn_offset + VEC_length (btrace_insn_s, bfun->insn);
    }

  printf_unfiltered (_("Recorded %u instructions in %u functions for thread "
		       "%d (%s).\n"), insts, funcs, tp->num,
		     target_pid_to_str (tp->ptid));

  if (btrace_is_replaying (tp))
    printf_unfiltered (_("Replay in progress.  At instruction %u.\n"),
		       btrace_insn_number (btinfo->replay));
}

/* Print an unsigned int.  */

static void
ui_out_field_uint (struct ui_out *uiout, const char *fld, unsigned int val)
{
  ui_out_field_fmt (uiout, fld, "%u", val);
}

/* Disassemble a section of the recorded instruction trace.  */

static void
btrace_insn_history (struct ui_out *uiout,
		     const struct btrace_insn_iterator *begin,
		     const struct btrace_insn_iterator *end, int flags)
{
  struct gdbarch *gdbarch;
  struct btrace_insn *inst;
  struct btrace_insn_iterator it;

  DEBUG ("itrace (0x%x): [%u; %u)", flags, btrace_insn_number (begin),
	 btrace_insn_number (end));

  gdbarch = target_gdbarch ();

  for (it = *begin; btrace_insn_cmp (&it, end) < 0; btrace_insn_next (&it, 1))
    {
      const struct btrace_insn *insn;

      insn = btrace_insn_get (&it);

      /* Print the instruction index.  */
      ui_out_field_uint (uiout, "index", btrace_insn_number (&it));
      ui_out_text (uiout, "\t");

      /* Disassembly with '/m' flag may not produce the expected result.
	 See PR gdb/11833.  */
      gdb_disassembly (gdbarch, uiout, NULL, flags, 1, insn->pc, insn->pc + 1);
    }
}

/* The to_insn_history method of target record-btrace.  */

static void
record_btrace_insn_history (int size, int flags)
{
  struct btrace_thread_info *btinfo;
  struct btrace_insn_history *history;
  struct btrace_insn_iterator begin, end;
  struct cleanup *uiout_cleanup;
  struct ui_out *uiout;
  unsigned int context, covered;

  uiout = current_uiout;
  uiout_cleanup = make_cleanup_ui_out_tuple_begin_end (uiout,
						       "insn history");
  btinfo = require_btrace ();
  context = abs (size);
  if (context == 0)
    error (_("Bad record instruction-history-size."));

  history = btinfo->insn_history;
  if (history == NULL)
    {
      struct btrace_insn_iterator *replay;

      /* If we're replaying, we start at the replay position.  Otherwise, we
	 start at the tail of the trace.  */
      replay = btinfo->replay;
      if (replay != NULL)
	begin = *replay;
      else
	btrace_insn_end (&begin, btinfo);

      /* We start from here and expand in the requested direction.  Then we
	 expand in the other direction, as well, to fill up any remaining
	 context.  */
      end = begin;
      if (size < 0)
	{
	  /* We want the current position covered, as well.  */
	  covered = btrace_insn_next (&end, 1);
	  covered += btrace_insn_prev (&begin, context - covered);
	  covered += btrace_insn_next (&end, context - covered);
	}
      else
	{
	  covered = btrace_insn_next (&end, context);
	  covered += btrace_insn_prev (&begin, context - covered);
	}
    }
  else
    {
      begin = history->begin;
      end = history->end;

      DEBUG ("insn-history (0x%x): %d, prev: [%u; %u)", flags, size,
	     btrace_insn_number (&begin), btrace_insn_number (&end));

      if (size < 0)
	{
	  end = begin;
	  covered = btrace_insn_prev (&begin, context);
	}
      else
	{
	  begin = end;
	  covered = btrace_insn_next (&end, context);
	}
    }

  if (covered > 0)
    btrace_insn_history (uiout, &begin, &end, flags);
  else
    {
      if (size < 0)
	printf_unfiltered (_("At the start of the branch trace record.\n"));
      else
	printf_unfiltered (_("At the end of the branch trace record.\n"));
    }

  btrace_set_insn_history (btinfo, &begin, &end);
  do_cleanups (uiout_cleanup);
}

/* The to_insn_history_range method of target record-btrace.  */

static void
record_btrace_insn_history_range (ULONGEST from, ULONGEST to, int flags)
{
  struct btrace_thread_info *btinfo;
  struct btrace_insn_history *history;
  struct btrace_insn_iterator begin, end;
  struct cleanup *uiout_cleanup;
  struct ui_out *uiout;
  unsigned int low, high;
  int found;

  uiout = current_uiout;
  uiout_cleanup = make_cleanup_ui_out_tuple_begin_end (uiout,
						       "insn history");
  low = (unsigned int) from;
  high = (unsigned int) to;

  DEBUG ("insn-history (0x%x): [%u; %u)", flags, low, high);

  /* Check for wrap-arounds.  */
  if (low != from || high != to)
    error (_("Bad range."));

  if (high <= low)
    error (_("Bad range."));

  btinfo = require_btrace ();

  found = btrace_find_insn_by_number (&begin, btinfo, low);
  if (found == 0)
    error (_("Range out of bounds."));

  found = btrace_find_insn_by_number (&end, btinfo, high);
  if (found == 0)
    {
      /* Silently truncate the range.  */
      btrace_insn_end (&end, btinfo);
    }
  else
    {
      /* We want both begin and end to be inclusive.  */
      btrace_insn_next (&end, 1);
    }

  btrace_insn_history (uiout, &begin, &end, flags);
  btrace_set_insn_history (btinfo, &begin, &end);

  do_cleanups (uiout_cleanup);
}

/* The to_insn_history_from method of target record-btrace.  */

static void
record_btrace_insn_history_from (ULONGEST from, int size, int flags)
{
  ULONGEST begin, end, context;

  context = abs (size);
  if (context == 0)
    error (_("Bad record instruction-history-size."));

  if (size < 0)
    {
      end = from;

      if (from < context)
	begin = 0;
      else
	begin = from - context + 1;
    }
  else
    {
      begin = from;
      end = from + context - 1;

      /* Check for wrap-around.  */
      if (end < begin)
	end = ULONGEST_MAX;
    }

  record_btrace_insn_history_range (begin, end, flags);
}

/* Print the instruction number range for a function call history line.  */

static void
btrace_call_history_insn_range (struct ui_out *uiout,
				const struct btrace_function *bfun)
{
  unsigned int begin, end, size;

  size = VEC_length (btrace_insn_s, bfun->insn);
  if (size == 0)
    return;

  begin = bfun->insn_offset;
  end = begin + size - 1;

  ui_out_field_uint (uiout, "insn begin", begin);
  ui_out_text (uiout, ",");
  ui_out_field_uint (uiout, "insn end", end);
}

/* Print the source line information for a function call history line.  */

static void
btrace_call_history_src_line (struct ui_out *uiout,
			      const struct btrace_function *bfun)
{
  struct symbol *sym;
  int begin, end;

  sym = bfun->sym;
  if (sym == NULL)
    return;

  ui_out_field_string (uiout, "file",
		       symtab_to_filename_for_display (sym->symtab));

  begin = bfun->lbegin;
  end = bfun->lend;

  if (end == 0)
    return;

  ui_out_text (uiout, ":");
  ui_out_field_int (uiout, "min line", begin);

  if (end == begin)
    return;

  ui_out_text (uiout, ",");
  ui_out_field_int (uiout, "max line", end);
}

/* Disassemble a section of the recorded function trace.  */

static void
btrace_call_history (struct ui_out *uiout,
		     const struct btrace_thread_info *btinfo,
		     const struct btrace_function *begin,
		     const struct btrace_function *end,
		     enum record_print_flag flags)
{
  const struct btrace_function *bfun;

  DEBUG ("ftrace (0x%x): [%u; %u)", flags, begin->number, end->number);

  for (bfun = begin; bfun != end; bfun = bfun->flow.next)
    {
      struct minimal_symbol *msym;
      struct symbol *sym;

      msym = bfun->msym;
      sym = bfun->sym;

      /* Print the function index.  */
      ui_out_field_uint (uiout, "index", bfun->number);
      ui_out_text (uiout, "\t");

      if ((flags & record_print_indent_calls) != 0)
	{
	  int level = bfun->level + btinfo->level, i;

	  for (i = 0; i < level; ++i)
	    ui_out_text (uiout, "  ");
	}

      if (sym != NULL)
	ui_out_field_string (uiout, "function", SYMBOL_PRINT_NAME (sym));
      else if (msym != NULL)
	ui_out_field_string (uiout, "function", SYMBOL_PRINT_NAME (msym));
      else
	ui_out_field_string (uiout, "function", "<unknown>");

      if ((flags & record_print_insn_range) != 0)
	{
	  ui_out_text (uiout, "\tinst ");
	  btrace_call_history_insn_range (uiout, bfun);
	}

      if ((flags & record_print_src_line) != 0)
	{
	  ui_out_text (uiout, "\tat ");
	  btrace_call_history_src_line (uiout, bfun);
	}

      ui_out_text (uiout, "\n");
    }
}

/* Decrement a btrace function iterator.  Return the number of functions
   by which the iterator has been decremented.
   Returns zero, if the operation failed.  */

static unsigned int
btrace_func_prev (struct btrace_function **it, unsigned int stride)
{
  struct btrace_function *bfun;
  unsigned int covered;

  bfun = *it;
  covered = 0;
  while (covered < stride)
    {
      struct btrace_function *prev;

      prev = bfun->flow.prev;
      if (prev == NULL)
	break;

      bfun = prev;
      covered += 1;
    }

  *it = bfun;
  return covered;
}

/* Increment a btrace function iterator.  Return the number of functions
   by which the iterator has been incremented.
   Returns zero, if the operation failed.  */

static unsigned int
btrace_func_next (struct btrace_function **it, unsigned int stride)
{
  struct btrace_function *bfun;
  unsigned int covered;

  bfun = *it;
  covered = 0;
  while (covered < stride)
    {
      struct btrace_function *next;

      next = bfun->flow.next;
      if (next == NULL)
	break;

      bfun = next;
      covered += 1;
    }

  *it = bfun;
  return covered;
}

/* The to_call_history method of target record-btrace.  */

static void
record_btrace_call_history (int size, int flags)
{
  struct btrace_thread_info *btinfo;
  struct btrace_call_history *history;
  struct btrace_function *begin, *end;
  struct cleanup *uiout_cleanup;
  struct ui_out *uiout;
  unsigned int context, covered;

  uiout = current_uiout;
  uiout_cleanup = make_cleanup_ui_out_tuple_begin_end (uiout,
						       "insn history");
  context = abs (size);
  if (context == 0)
    error (_("Bad record function-call-history-size."));

  btinfo = require_btrace ();
  history = btinfo->call_history;
  if (history == NULL)
    {
      struct btrace_insn_iterator *replay;

      /* If we're replaying, we start at the replay position.  Otherwise, we
	 start at the tail of the trace.  */
      replay = btinfo->replay;
      if (replay != NULL)
	begin = replay->function;
      else
	begin = btinfo->end;

      /* We start from here and expand in the requested direction.  Then we
	 expand in the other direction, as well, to fill up any remaining
	 context.  */
      end = begin;
      if (size < 0)
	{
	  /* We want the current position covered, as well.  */
	  covered = btrace_func_next (&end, 1);
	  covered += btrace_func_prev (&begin, context - covered);
	  covered += btrace_func_next (&end, context - covered);
	}
      else
	{
	  covered = btrace_func_next (&end, context);
	  covered += btrace_func_prev (&begin, context- covered);
	}
    }
  else
    {
      begin = history->begin;
      end = history->end;

      DEBUG ("call-history (0x%x): %d, prev: [%u; %u[", flags, size,
	     begin->number, end->number);

      if (size < 0)
	{
	  end = begin;
	  covered = btrace_func_prev (&begin, context);
	}
      else
	{
	  begin = end;
	  covered = btrace_func_next (&end, context);
	}
    }

  if (covered > 0)
    btrace_call_history (uiout, btinfo, begin, end, flags);
  else
    {
      if (size < 0)
	printf_unfiltered (_("At the start of the branch trace record.\n"));
      else
	printf_unfiltered (_("At the end of the branch trace record.\n"));
    }

  btrace_set_call_history (btinfo, begin, end);
  do_cleanups (uiout_cleanup);
}

/* The to_call_history_range method of target record-btrace.  */

static void
record_btrace_call_history_range (ULONGEST from, ULONGEST to, int flags)
{
  struct btrace_thread_info *btinfo;
  struct btrace_call_history *history;
  struct btrace_function *begin, *end;
  struct cleanup *uiout_cleanup;
  struct ui_out *uiout;
  unsigned int low, high;

  uiout = current_uiout;
  uiout_cleanup = make_cleanup_ui_out_tuple_begin_end (uiout,
						       "func history");
  low = (unsigned int) from;
  high = (unsigned int) to;

  DEBUG ("call-history (0x%x): [%u; %u[", flags, low, high);

  /* Check for wrap-arounds.  */
  if (low != from || high != to)
    error (_("Bad range."));

  if (high <= low)
    error (_("Bad range."));

  btinfo = require_btrace ();

  begin = btrace_find_function_by_number (btinfo, low);
  if (begin == NULL)
    error (_("Range out of bounds."));

  end = btrace_find_function_by_number (btinfo, high);
  /* We want both begin and end to be inclusive.  */
  if (end != NULL)
    end = end->flow.next;

  /* Silently truncate the range, if necessary.  */
  if (end == NULL)
    end = btinfo->end;

  btrace_call_history (uiout, btinfo, begin, end, flags);
  btrace_set_call_history (btinfo, begin, end);

  do_cleanups (uiout_cleanup);
}

/* The to_call_history_from method of target record-btrace.  */

static void
record_btrace_call_history_from (ULONGEST from, int size, int flags)
{
  ULONGEST begin, end, context;

  context = abs (size);
  if (context == 0)
    error (_("Bad record function-call-history-size."));

  if (size < 0)
    {
      end = from;

      if (from < context)
	begin = 0;
      else
	begin = from - context + 1;
    }
  else
    {
      begin = from;
      end = from + context - 1;

      /* Check for wrap-around.  */
      if (end < begin)
	end = ULONGEST_MAX;
    }

  record_btrace_call_history_range (begin, end, flags);
}

/* The to_record_is_replaying method of target record-btrace.  */

static int
record_btrace_is_replaying (void)
{
  struct thread_info *tp;

  ALL_THREADS (tp)
    if (btrace_is_replaying (tp))
      return 1;

  return 0;
}

/* The to_xfer_partial method of target record-btrace.  */

static LONGEST
record_btrace_xfer_partial (struct target_ops *ops, enum target_object object,
			    const char *annex, gdb_byte *readbuf,
			    const gdb_byte *writebuf, ULONGEST offset,
			    LONGEST len)
{
  struct target_ops *t;

  /* Normalize the request so len is positive.  */
  if (len < 0)
    {
      offset += len;
      len = - len;
    }

  /* Filter out requests that don't make sense during replay.  */
  if (record_btrace_is_replaying ())
    {
      switch (object)
	{
	case TARGET_OBJECT_MEMORY:
	case TARGET_OBJECT_RAW_MEMORY:
	case TARGET_OBJECT_STACK_MEMORY:
	  {
	    /* We allow reading readonly memory.  */
	    struct target_section *section;

	    section = target_section_by_addr (ops, offset);
	    if (section != NULL)
	      {
		/* Check if the section we found is readonly.  */
		if ((bfd_get_section_flags (section->bfd,
					    section->the_bfd_section)
		     & SEC_READONLY) != 0)
		  {
		    /* Truncate the request to fit into this section.  */
		    len = min (len, section->endaddr - offset);
		    break;
		  }
	      }

	    throw_error (NOT_AVAILABLE_ERROR,
			 _("This record target does not trace memory."));
	  }
	}
    }

  /* Forward the request.  */
  for (t = ops->beneath; t != NULL; t = t->beneath)
    if (t->to_xfer_partial != NULL)
      return t->to_xfer_partial (t, object, annex, readbuf, writebuf,
				 offset, len);

  return -1;
}

/* The to_fetch_registers method of target record-btrace.  */

static void
record_btrace_fetch_registers (struct target_ops *ops,
			       struct regcache *regcache, int regno)
{
  struct btrace_insn_iterator *replay;
  struct thread_info *tp;

  tp = find_thread_ptid (inferior_ptid);
  if (tp == NULL)
    return;

  replay = tp->btrace.replay;
  if (replay != NULL)
    {
      const struct btrace_insn *insn;
      struct gdbarch *gdbarch;
      int pcreg;

      gdbarch = get_regcache_arch (regcache);
      pcreg = gdbarch_pc_regnum (gdbarch);
      if (pcreg < 0)
	error (_("Failed to determine PC register number."));

      /* We can only provide the PC register.  */
      if (regno >= 0 && regno != pcreg)
	throw_error (NOT_AVAILABLE_ERROR,
		     _("This record target does not trace registers."));

      insn = btrace_insn_get (replay);
      if (insn == NULL)
	error (_("Failed to determine the current replay position."));

      regcache_raw_supply (regcache, regno, &insn->pc);
    }
  else
    {
      struct target_ops *t;

      for (t = ops->beneath; t != NULL; t = t->beneath)
	if (t->to_fetch_registers != NULL)
	  {
	    t->to_fetch_registers (t, regcache, regno);
	    break;
	  }
    }
}

/* The to_store_registers method of target record-btrace.  */

static void
record_btrace_store_registers (struct target_ops *ops,
			       struct regcache *regcache, int regno)
{
  struct target_ops *t;

  if (record_btrace_is_replaying ())
    throw_error (NOT_AVAILABLE_ERROR,
		 _("This record target does not trace registers."));

  if (may_write_registers == 0)
    error (_("Writing to registers is not allowed (regno %d)"), regno);

  for (t = ops->beneath; t != NULL; t = t->beneath)
    if (t->to_store_registers != NULL)
      {
	t->to_store_registers (t, regcache, regno);
	return;
      }

  noprocess ();
}

/* The to_prepare_to_store method of target record-btrace.  */

static void
record_btrace_prepare_to_store (struct target_ops *ops,
				struct regcache *regcache)
{
  struct target_ops *t;

  if (record_btrace_is_replaying ())
    return;

  for (t = ops->beneath; t != NULL; t = t->beneath)
    if (t->to_prepare_to_store != NULL)
      {
	t->to_prepare_to_store (t, regcache);
	return;
      }
}

/* Implement stop_reason method for record_btrace_frame_unwind.  */

static enum unwind_stop_reason
record_btrace_frame_unwind_stop_reason (struct frame_info *this_frame,
					void **this_cache)
{
  return UNWIND_UNAVAILABLE;
}

/* Implement this_id method for record_btrace_frame_unwind.  */

static void
record_btrace_frame_this_id (struct frame_info *this_frame, void **this_cache,
			     struct frame_id *this_id)
{
  /* Leave there the outer_frame_id value.  */
}

/* Implement prev_register method for record_btrace_frame_unwind.  */

static struct value *
record_btrace_frame_prev_register (struct frame_info *this_frame,
				   void **this_cache,
				   int regnum)
{
  throw_error (NOT_AVAILABLE_ERROR,
              _("Registers are not available in btrace record history"));
}

/* Implement sniffer method for record_btrace_frame_unwind.  */

static int
record_btrace_frame_sniffer (const struct frame_unwind *self,
			     struct frame_info *this_frame,
			     void **this_cache)
{
  struct thread_info *tp;
  struct btrace_thread_info *btinfo;
  struct btrace_insn_iterator *replay;

  /* This doesn't seem right.  Yet, I don't see how I could get from a frame
     to its thread.  */
  tp = find_thread_ptid (inferior_ptid);
  if (tp == NULL)
    return 0;

  return btrace_is_replaying (tp);
}

/* btrace recording does not store previous memory content, neither the stack
   frames content.  Any unwinding would return errorneous results as the stack
   contents no longer matches the changed PC value restored from history.
   Therefore this unwinder reports any possibly unwound registers as
   <unavailable>.  */

static const struct frame_unwind record_btrace_frame_unwind =
{
  NORMAL_FRAME,
  record_btrace_frame_unwind_stop_reason,
  record_btrace_frame_this_id,
  record_btrace_frame_prev_register,
  NULL,
  record_btrace_frame_sniffer
};

/* The to_resume method of target record-btrace.  */

static void
record_btrace_resume (struct target_ops *ops, ptid_t ptid, int step,
		      enum gdb_signal signal)
{
  struct thread_info *tp;
  struct target_ops *t;

  if (record_btrace_is_replaying ())
    error (_("You can't do this from here.  Do 'record goto end', first."));

  for (t = ops->beneath; t != NULL; t = t->beneath)
    if (t->to_resume != NULL)
      break;

  if (t == NULL)
    error (_("Cannot find target for stepping."));

  t->to_resume (t, ptid, step, signal);
}

/* The to_wait method of target record-btrace.  */

static ptid_t
record_btrace_wait (struct target_ops *ops, ptid_t ptid,
		    struct target_waitstatus *status, int options)
{
  struct target_ops *t;

  for (t = ops->beneath; t != NULL; t = t->beneath)
    if (t->to_wait != NULL)
      break;

  if (t == NULL)
    error (_("Cannot find target for stepping."));

  return t->to_wait (t, ptid, status, options);
}

/* Initialize the record-btrace target ops.  */

static void
init_record_btrace_ops (void)
{
  struct target_ops *ops;

  ops = &record_btrace_ops;
  ops->to_shortname = "record-btrace";
  ops->to_longname = "Branch tracing target";
  ops->to_doc = "Collect control-flow trace and provide the execution history.";
  ops->to_open = record_btrace_open;
  ops->to_close = record_btrace_close;
  ops->to_detach = record_detach;
  ops->to_disconnect = record_disconnect;
  ops->to_mourn_inferior = record_mourn_inferior;
  ops->to_kill = record_kill;
  ops->to_create_inferior = find_default_create_inferior;
  ops->to_stop_recording = record_btrace_stop_recording;
  ops->to_info_record = record_btrace_info;
  ops->to_insn_history = record_btrace_insn_history;
  ops->to_insn_history_from = record_btrace_insn_history_from;
  ops->to_insn_history_range = record_btrace_insn_history_range;
  ops->to_call_history = record_btrace_call_history;
  ops->to_call_history_from = record_btrace_call_history_from;
  ops->to_call_history_range = record_btrace_call_history_range;
  ops->to_record_is_replaying = record_btrace_is_replaying;
  ops->to_xfer_partial = record_btrace_xfer_partial;
  ops->to_fetch_registers = record_btrace_fetch_registers;
  ops->to_store_registers = record_btrace_store_registers;
  ops->to_prepare_to_store = record_btrace_prepare_to_store;
  ops->to_get_unwinder = &record_btrace_frame_unwind;
  ops->to_resume = record_btrace_resume;
  ops->to_wait = record_btrace_wait;
  ops->to_stratum = record_stratum;
  ops->to_magic = OPS_MAGIC;
}

/* Alias for "target record".  */

static void
cmd_record_btrace_start (char *args, int from_tty)
{
  if (args != NULL && *args != 0)
    error (_("Invalid argument."));

  execute_command ("target record-btrace", from_tty);
}

void _initialize_record_btrace (void);

/* Initialize btrace commands.  */

void
_initialize_record_btrace (void)
{
  add_cmd ("btrace", class_obscure, cmd_record_btrace_start,
	   _("Start branch trace recording."),
	   &record_cmdlist);
  add_alias_cmd ("b", "btrace", class_obscure, 1, &record_cmdlist);

  init_record_btrace_ops ();
  add_target (&record_btrace_ops);
}
