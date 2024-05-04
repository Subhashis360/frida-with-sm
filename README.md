frida-with-sm WELCOME here

What is frida ?
Frida is a dynamic instrumentation toolkit. It is mainly created for testers, developers and reverse engineering enthusiasts. For mobile app security

how to use ? 

First connect the mobile / your virtual device with Computer

Method 1 > 
Frida server >>
1 . download frida server from Github ( arm 64 for mine yours can be diff )
2 . extract > rename > give permisson > send to > root directory > cd /data/local/tmp
3. now start the server ( ./frida )
4. go to my python script run it > it will give you option to select the pakage name installed in mobile > select a pakage name and frida will start
5. Extra > You can add as many js file you want in python script just add more names of the js files with comma in array
6. Take Your keys || data >> in logs

Method 2 > 
Frida Inject >>
1 . download frida inject from Github ( arm 64 for mine yours can be diff )
2 . extract > rename > give permisson > send to > root directory > cd /data/local/tmp
3 . Now send the js files also in the directory 
4 . normal command > ./fridai -f pakage.name -s crypto.js
5 . multiple js command > cat crypto.js AntiDebug.js antiroot.js > master_script.js && ./fridai -f com.cashfox.rewardapp -s master_script.js
6 . save ouput > cat crypto.js AntiDebug.js antiroot.js > master_script.js && ./fridai -f com.cashfox.rewardapp -s master_script.js 2>&1 | tee sm.txt
7 . Done Now > cat sm.txt ( to see logs )

Useful adb commands >

cmd connect adb > adb shell 
cmd adb superuser > su
cmd change directory > cd /data/local/tmp
cmd send some file from pc > adb push /jsfiles/crypto.js /data/local/tmp
cmd download some file from pc > adb pull /data/local/tmp/sm.txt .
