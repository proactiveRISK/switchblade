#!/bin/bash

set -e

rm -fr SwitchBlade dist

cp ../build/src/http_dos_cli.exe .

python setup.py py2exe

gtk_dir="/c/Program Files/Gtk+"
gtk_locale_dir="/c/Program Files/Gtk+/share/locale"

if [ ! -d "${gtk_dir}" ]; then
  gtk_dir="/c/Program Files/GIMP 2/32"
  gtk_locale_dir="/c/Program Files/GIMP 2/share/locale"
fi

# py2exe misses intl.dll
cp "${gtk_dir}/bin/intl.dll" dist/

# copy themes and locale
mkdir -p "dist/share/themes/Default" "dist/share/locale"
#cp -r "${gtk_dir}/share/themes/Default" dist/share/themes
cp -r "${gtk_dir}/share/themes/MS-Windows/" dist/share/themes/Default
cp -r "${gtk_locale_dir}/en_GB"   dist/share/locale
cp -r "${gtk_locale_dir}/en_CA"   dist/share/locale

VERSION=$(cat VERSION)

mv dist SwitchBlade 
zip -r -9 SwitchBlade${VERSION}.zip SwitchBlade/

