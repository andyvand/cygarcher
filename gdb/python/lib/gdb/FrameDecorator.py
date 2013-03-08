# Copyright (C) 2013 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import gdb

class FrameDecorator(object):
    """Basic implementation of a Frame Decorator"""

    """ This base frame decorator decorates a frame or another frame
    decorator, and provides convenience methods.  If this object is
    wrapping a frame decorator, defer to that wrapped object's method
    if it has one.  This allows for frame decorators that have
    sub-classed FrameDecorators, but also wrap other frame decorators
    on the same frame to correctly execute.

    E.g

    If the result of frame filters running means we have one gdb.Frame
    wrapped by multiple frame decorators, all sub-classed from
    FrameDecorator, the resulting hierarchy will be:

    Decorator1
      -- (wraps) Decorator2
        -- (wraps) FrameDecorator
          -- (wraps) gdb.Frame

    In this case we have two frame decorators, both of which are
    sub-classed from FrameDecorator.  If Decorator1 just overrides the
    'function' method, then all of the other methods are carried out
    by the super-class FrameDecorator.  But Decorator2 may have
    overriden other methods, so FrameDecorator will look at the
    'base' parameter and defer to that class's methods.  And so on,
    down the chain."""

    # 'base' can refer to a gdb.Frame or another frame decorator.  In
    # the latter case, the child class will have called the super
    # method and base will be an object conforming to the Frame Filter
    # class.
    def __init__(self, base):
        self.base = base

    @staticmethod
    def _is_limited_frame(frame):
        """Internal utility to determine if the frame is special or
        limited."""
        sal = frame.find_sal()

        if (not sal.symtab or not sal.symtab.filename
            or frame == gdb.DUMMY_FRAME
            or frame == gdb.SIGTRAMP_FRAME):

            return True

        return False

    def elided(self):
        """Return any elided frames that this class might be
        wrapping, or None."""
        if hasattr(self.base, "elided"):
            return self.base.elided()

        return None

    def function(self):
        """ Return the name of the frame's function, first determining
        if it is a special frame.  If not, try to determine filename
        from GDB's frame internal function API.  Finally, if a name
        cannot be determined return the address."""

        if not isinstance(self.base, gdb.Frame):
            if hasattr(self.base, "function"):
                return self.base.function()

        frame = self.inferior_frame()

        if frame.type() == gdb.DUMMY_FRAME:
            return "<function called from gdb>"
        elif frame.type() == gdb.SIGTRAMP_FRAME:
            return "<signal handler called>"

        func = frame.function()
        sal = frame.find_sal()
        pc = frame.pc()

        if func == None:
            unknown =  format(" 0x%08x in" % pc)
            return unknown

        return str(func)

    def address(self):
        """ Return the address of the frame's pc"""

        if hasattr(self.base, "address"):
            return self.base.address()

        frame = self.inferior_frame()
        return frame.pc()

    def filename(self):
        """ Return the filename associated with this frame, detecting
        and returning the appropriate library name is this is a shared
        library."""

        if hasattr(self.base, "filename"):
            return self.base.filename()

        frame = self.inferior_frame()
        sal = frame.find_sal()
        if (not sal.symtab or not sal.symtab.filename):
            pc = frame.pc()
            return gdb.solib_name(pc)
        else:
            return sal.symtab.filename

    def frame_args(self):
        """ Return an iterator of frame arguments for this frame, if
        any.  The iterator contains objects conforming with the
        Symbol/Value interface.  If there are no frame arguments, or
        if this frame is deemed to be a special case, return None."""

        if hasattr(self.base, "frame_args"):
            return self.base.frame_args()

        frame = self.inferior_frame()
        if self._is_limited_frame(frame):
            return None

        args = FrameVars(frame)
        return args.fetch_frame_args()

    def frame_locals(self):
        """ Return an iterator of local variables for this frame, if
        any.  The iterator contains objects conforming with the
        Symbol/Value interface.  If there are no frame locals, or if
        this frame is deemed to be a special case, return None."""

        if hasattr(self.base, "frame_locals"):
            return self.base.frame_locals()

        frame = self.inferior_frame()
        if self._is_limited_frame(frame):
            return None

        args = FrameVars(frame)
        return args.fetch_frame_locals()

    def line(self):
        """ Return line number information associated with the frame's
        pc.  If symbol table/line information does not exist, or if
        this frame is deemed to be a special case, return None"""

        if hasattr(self.base, "line"):
            return self.base.line()

        frame = self.inferior_frame()
        if self._is_limited_frame(frame):
            return None

        sal = frame.find_sal()
        if (sal):
            return sal.line
        else:
            return None

    def inferior_frame(self):
        """ Return the gdb.Frame underpinning this frame decorator."""

        # If 'base' is a frame decorator, we want to call its inferior
        # frame method.  If 'base' is a gdb.Frame, just return that.
        if hasattr(self.base, "inferior_frame"):
            return self.base.inferior_frame()
        return self.base

class SymValueWrapper(object):
    """A container class conforming to the Symbol/Value interface
    which holds frame locals or frame arguments."""
    def __init__(self, symbol, value):
        self.sym = symbol
        self.val = value

    def value(self):
        """ Return the value associated with this symbol, or None"""
        return self.val

    def symbol(self):
        """ Return the symbol, or Python text, associated with this
        symbol, or None"""
        return self.sym

class FrameVars(object):

    """Utility class to fetch and store frame local variables, or
    frame arguments."""

    def __init__(self,frame):
        self.frame = frame

    @staticmethod
    def fetch_b(sym):
        """ Local utility method to determine if according to Symbol
        type whether it should be included in the iterator.  Not all
        symbols are fetched, and only symbols that return
        True from this method should be fetched."""

        # SYM may be a string instead of a symbol in the case of
        # synthetic local arguments or locals.  If that is the case,
        # always fetch.
        if isinstance(sym, basestring):
            return True

        sym_type = sym.addr_class

        return {
            gdb.SYMBOL_LOC_STATIC: True,
            gdb.SYMBOL_LOC_REGISTER: True,
            gdb.SYMBOL_LOC_ARG: True,
            gdb.SYMBOL_LOC_REF_ARG: True,
            gdb.SYMBOL_LOC_LOCAL: True,
	    gdb.SYMBOL_LOC_REGPARM_ADDR: True,
	    gdb.SYMBOL_LOC_COMPUTED: True
          }.get(sym_type, False)

    def fetch_frame_locals(self):
        """Public utility method to fetch frame local variables for
        the stored frame.  Frame arguments are not fetched.  If there
        are no frame local variables, return an empty list."""
        lvars = []
        try:
            block = self.frame.block()
        except:
            return None

        for sym in block:
            if sym.is_argument:
                continue;
            if self.fetch_b(sym):
                lvars.append(SymValueWrapper(sym, None))

        return lvars

    def fetch_frame_args(self):
        """Public utility method to fetch frame arguments for the
        stored frame.  Frame arguments are the only type fetched.  If
        there are no frame argument variables, return an empty list."""

        args = []
        try:
            block = self.frame.block()
        except:
            return None

        for sym in block:
            if not sym.is_argument:
                continue;
            args.append(SymValueWrapper(sym,None))

        return args

    def get_value(self, sym, block):
        """Public utility method to fetch a value from a symbol."""
        if len(sym.linkage_name):
            nsym, is_field_of_this = gdb.lookup_symbol(sym.linkage_name, block)
            if nsym != None:
                if nsym.addr_class != gdb.SYMBOL_LOC_REGISTER:
                    sym = nsym

        try:
            val = sym.value(self.frame)

        except RuntimeError, text:
            val = text
        if val == None:
            val = "???"

        return val
