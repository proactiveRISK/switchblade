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

deps_loc = ARGUMENTS.get('deps')
if not deps_loc:
  deps_loc = '../deps'
deps_loc = '#' + deps_loc

# Build env

cflags = ''

if sys.platform == 'win32':
  env = Environment(tools=['mingw'],
          LINKFLAGS=['-Wl,--enable-auto-import'],
          LIBPATH=[os.path.join(deps_loc, 'lib')],
          CPPPATH=[os.path.join(deps_loc, 'include')],
          CPPDEFINES=['PLAT_WIN32'],
          CFLAGS=cflags)
else:
  env = Environment(
          LIBPATH=[os.path.join(deps_loc, 'lib')],
          CPPPATH=[os.path.join(deps_loc, 'include')],
          CPPDEFINES=['PLAT_LINUX'],
          CFLAGS=cflags)

variant_dir = 'build'
VariantDir(variant_dir, '.', duplicate=0)
Default(variant_dir)
Export('env')

SConscript(variant_dir + '/src/SConscript')

# vim: set ft=python :
