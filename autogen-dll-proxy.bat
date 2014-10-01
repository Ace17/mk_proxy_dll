echo "***** Initializing Visual Studio 2005 environment *****"
CALL "C:\Program Files\Microsoft Visual Studio 8\VC\vcvarsall.bat" x86

echo.
echo "***** Setting directory and copying files *****"
%~d0
cd %~dp0
mkdir output
cd output
copy %1 %~n1_original%~x1

echo.
echo "***** Generating source for proxy DLL *****"
.\bin\make_proxy_dll.exe %~n1_original%~x1 proxy_%~n1.cpp

echo.
echo "***** Compiling the new dll *****"
cl -o %~nx1 proxy_%~n1.cpp /link /DLL /DEF:"proxy_%~n1.cpp.def"

echo.
echo "***** Look at the output directory for your files *****"
pause
