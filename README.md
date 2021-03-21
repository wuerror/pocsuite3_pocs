# http_request_smuggling_script
http请求走私检测的脚本
## 原理与攻击面

[协议层的攻击——HTTP请求走私](https://paper.seebug.org/1048/)
[一篇文章带你读懂http请求走私](http://blog.zeddyu.info/2019/12/05/HTTP-Smuggling/)
seebug这篇中提到的几篇blackhat议题建议都看看
### 检测脚本的实现
blackhat上提出的通过延时的方法，具体就不介绍了，上面提到的文章都有讲。
检测demo主要来自freebuf上斗象智能平台的文章。在此基础上我做了一些修改，但核心检测逻辑是没变的。
[流量夹带(HTTP Request Smuggling) 检测方案的实现](https://www.freebuf.com/news/231050.html)
## 吐槽
这漏洞检测出来了，想利用感觉也蛮困难的。
