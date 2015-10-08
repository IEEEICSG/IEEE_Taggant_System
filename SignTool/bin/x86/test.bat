copy /Y testo.exe test.exe
SignTool test.exe license.pem -t:pe
copy /Y test.exe test1.exe
SignTool test.exe license.pem -t:pe
copy /Y test.exe test2.exe
SignTool test.exe license.pem -t:pe
copy /Y test.exe test3.exe

copy /Y testo.js test.js
SignTool test.js license.pem -t:js
copy /Y test.js test1.js
SignTool test.js license.pem -t:js
copy /Y test.js test2.js
SignTool test.js license.pem -t:js
copy /Y test.js test3.js

copy /Y testo.txt test.txt
SignTool test.txt license.pem -t:txt
copy /Y test.txt test1.txt
SignTool test.txt license.pem -t:txt
copy /Y test.txt test2.txt
SignTool test.txt license.pem -t:txt
copy /Y test.txt test3.txt

copy /Y testo.bin test.bin
SignTool test.bin license.pem -t:bin
copy /Y test.bin test1.bin
SignTool test.bin license.pem -t:bin
copy /Y test.bin test2.bin
SignTool test.bin license.pem -t:bin
copy /Y test.bin test3.bin


