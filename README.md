# 一些pocsuite3的脚本
目前只有3个。。。
## shiziyuCMS_sqli
纯练手，详情见佩奇Wiki。
试了几个，能拿到表名，拿不到数据。也不能直接写文件getshell.我太菜了
## drupal7_geddon2
针对7.x < 7.58版本的drupalgeddon2 exp，pocsuite3自带的poc是针对的8.x版本。阅读msf对应模块和已经公开的ruby版exp后写了这个，
略去了判断版本的步骤，未对命令执行结果做清洗————待优化，也可能不想写了。
verify、attack模式正常，--shell模式还无法使用(没接到)。
但是内置了一个写webshell的函数： --attack --command ws即可，修改shell内容可通过--shell_content 写入
## http_request_smuggling_script
pocsuite3格式的http请求走私检测的脚本
### 原理与攻击面

[协议层的攻击——HTTP请求走私](https://paper.seebug.org/1048/)

[一篇文章带你读懂http请求走私](http://blog.zeddyu.info/2019/12/05/HTTP-Smuggling/)

seebug这篇中提到的几篇blackhat议题建议都看看
#### 检测脚本的实现
blackhat上提出的通过延时的方法，具体就不介绍了，上面提到的文章都有讲。
检测demo主要来自freebuf上斗象智能平台的文章。在此基础上我做了一些修改，但核心检测逻辑是没变的。
[流量夹带(HTTP Request Smuggling) 检测方案的实现](https://www.freebuf.com/news/231050.html)
#### 吐槽
这漏洞检测出来了，想利用感觉也蛮困难的。
