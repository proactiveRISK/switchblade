# Copyright (c) 2010, PROACTIVE RISK - http://www.proactiverisk.com
#
# This file is part of HTTP DoS Tool.
#
# HTTP Dos Tool is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# Foobar is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# HTTP DoS Tool.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys

# libevent location
libevent_loc = ARGUMENTS.get('libevent')
if not libevent_loc:
  if sys.platform == 'win32':
    libevent_loc = '../../local'
  else:
    libevent_loc = '..'
libevent_loc = '#' + libevent_loc

# Build env

if sys.platform == 'win32':
  env = Environment(tools=['mingw'],
          LINKFLAGS=['-Wl,--enable-auto-import'],
          LIBPATH=[os.path.join(libevent_loc, 'lib')],
          CPPPATH=[os.path.join(libevent_loc, 'include')],
          CPPDEFINES=['PLAT_WIN32']
          )
else:
  env = Environment(
          LIBPATH=[os.path.join(libevent_loc, 'lib')],
          CPPPATH=[os.path.join(libevent_loc, 'include')],
          CPPDEFINES=['PLAT_LINUX'])

variant_dir = 'build'
VariantDir(variant_dir, '.', duplicate=0)
Default(variant_dir)
Export('env')

SConscript(variant_dir + '/src/SConscript')

# vim: set ft=python :
