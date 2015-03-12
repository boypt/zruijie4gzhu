# 信春哥，不掉线 #

> 本项目已经停止多年，无法保证程序可用，源码在仓库中，仅供研究，欢迎Fork。

> 本项目为 **稳定** 使用目前广州大学大学城校区的校园网的锐捷协议而兼容，但并不限于广州大学使用。

> 同时在此感谢[广州大学惠风和畅](http://bbs.gzhu.edu.cn)网络版版主小赖的辛勤工作，还有经常给校园网的设备放假，留时间给童鞋们复习功课的网管们。

# 导航 #
  * UserManual  用户手册
  * DeveloperDocument 开发者手册，获取、编译源代码
  * [程序下载](http://code.google.com/p/zruijie4gzhu/downloads/list)

# 更新 #
  * 0.8.5发布，安装脚本引入gksu、zenity，可以通过纯图形化操作完成安装。
  * 0.8.0不输入密码参数后可从stdin读入密码，脚本内通过管道传送，避免在进程表同时显示帐号密码
  * 0.7.0版去除pthread库依赖；
  * 0.6.1版支持在MacOS/BSD系列的系统内编译运行，[r86](https://code.google.com/p/zruijie4gzhu/source/detail?r=86)
  * Linux 0.6 兼容第一次网管封杀版协议；
  * Linux 启动脚本：可自动记录服务器信息日志；
  * WIN 0.4 修正BUG：在User用户权限下运行无法保存用户数据
  * WIN 0.3 修正BUG：当系统存在多个网卡时无法获取MAC地址
  * WIN 0.2 修正BUG：当网卡设备变化导致自动连接失常（临时取消自动登录）；
  * WIN 0.1 Win版本首个版本发布，供同学们测试；
  * WIN 开始Win版本的zRuijie4GZHU开发，首个可用测试版本[r37](https://code.google.com/p/zruijie4gzhu/source/detail?r=37)
  * 0.5 改善协议兼容性［正确获取success\_key］；继续改善runruijie脚本；
  * 0.4 改善安装脚本在Ubuntu下的兼容性；修改使用pcap的API获取网卡IP信息。
  * 0.3 改善启动脚本，通过libnotify在桌面显示认证过程信息。
  * 0.2 完善代码结构，引入启动、安装脚本
  * 0.1 实现不掉线的认证

# 理念 #
> zRuijie延续了作者依次开发了[神州数码](http://code.google.com/p/zdcclient/)、[联想](http://code.google.com/p/zlevoclient/)的802.1x客户端所使用的框架，基于[K.I.S.S的开发理念](http://zh.wikipedia.org/wiki/KISS%E5%8E%9F%E5%88%99)，不要求要求用户处理过多不必要的操作和概念。

### 联系作者 ###
  * ![http://zruijie4gzhu.googlecode.com/files/mail.png](http://zruijie4gzhu.googlecode.com/files/mail.png) **Mail and Gtalk**
  * [Twitter @BOYPT](http://twitter.com/BOYPT)
  * [Blog](http://apt-blog.net/)