mk_proxy_dll
============

A tool to create a "proxy dll", intercepting call between two binary modules.

Usage:

mk_proxy_dll <input_lib.dll> <output.c>

Let's say you have an executable binary "program.exe" using some DLL "library.dll".
You want to intercept the calls between both. The idea is to generate a DLL, say "librarZ.dll", having the same interface than "library.dll".
The "librarZ.dll" module will then delegate all the calls to the "library.dll" module.
Then, modify the binary program.exe (with an hex editor) to replace the string "library.dll" with "librarZ.dll".
Thus, "program.exe" will load your freshly created impersonator DLL instead.

mk_proxy_dll library.dll librarZ.dll

gcc librarZ.c -shared -o librarZ.dll

hexer program.exe



