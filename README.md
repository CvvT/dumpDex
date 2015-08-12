# dumpDex

Source: dump.py
modified the var 'addr'(cookie) in this file and run as python script in IDA for some information of the dex file loaded in memory.
You can use zjdroid to figure out the value of the cookie.

经过一个星期的分析才总算明白xx聚的实现原理，又折腾了将近一个礼拜写了个工具来脱壳。
result/
  文件下是测试apk以及dump出来的dex文件
考虑到知识产权问题这里就不直接贴代码了，简单说下脱壳工具实现原理：
  可以参考zjdroid的实现，对内存直接进行dump，但是由于加固后dex文件并不是在内存中连续存放的，但依然满足dex的文件格式（通过将代码段移动到其他地方并将偏移量进行修改）。这里可以参考我的另一个项目DexParse，我把他移植到可在IDA上运行，那么即使在内存中并不连续存放也可以dump出来啦～
  
欢迎感兴趣的小伙伴一起来学习交流
546052909@qq.com
