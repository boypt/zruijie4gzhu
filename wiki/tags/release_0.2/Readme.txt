zRuijie4GZHU用户手册

    zRuijie4GZHU是基于pcap库的跨平台（暂限Unix系列）锐捷兼容客户端，为目前广州大学大学城校区的校园网接入协议而兼容，但不限于广州大学使用，可能兼容其他部署了锐捷的环境。 

程序

    zRuijie4GZHU包含核心程序以及用户脚本，不建议分离，但用户可自由配置。 

    * 核心程序：zruijie
    * 安装脚本：install
    * 运行脚本：runruijie 

安装

    在安装前，请用户先编辑运行脚本文件runruijie，将其中的username和password分别修改成您的帐号和密码并保存。 

    安装需要root权限，这通常使用sudo或者su -c实现 

    sudo ./install 

    安装程序会复制核心程序zruijie以及用户脚本runruijie到系统目录/usr/bin，并设置相关文件，如果用户希望安装到其他目录，请修改install安装脚本中第二行INSTALL_PATH变量。 

    成功执行安装将看到####Installation Done.####的提示。 

运行

    如果用户配置的帐号信息无误并且安装成功，那么用户只需要运行runruijie，即可看到有关的认证成功的信息，并能顺利上网了。 

    可以通过桌面的启动器运行runruijie，或把把｀runruijie｀加入到比如GNOME的“系统->首选项->会话“当中，以便每次登录系统即可自动认证上网。 

    唯一需要注意的是，如果出现账户信息出错、欠费等情况，程序会给出提示，而且这期间有约10秒的session终结期，当然用户可以Ctrl + C马上终结程序，但是在session终结之前再次进行任何认证，都不能成功的。 

终止

    用户执行一次｀runruijie -l｀，即可成功离线。 

编译：

    用户可通过svn获得最新的开发代码：

        svn checkout http://zruijie4gzhu.googlecode.com/svn/trunk/ zruijie4gzhu

    或者从项目主页下载版本代码包并自行解压。 

        http://code.google.com/p/zruijie4gzhu/downloads/list

    编译需要libpcap库，一般Linux发行版里面安装libpcap包即可，在ubuntu中，需要libpcap-dev：

        sudo apt-get install libpcap-dev

    从命令行进入源代码目录，运行make，应该很快就能生成zruijie，当然前提是系统中安装了gcc等编译环境，这里不再累赘。 

    代码包内包含安装脚本和运行脚本，完成编译后即可安装。 

Another PT Work.

GMail GTalk: pentie@gmail.com

项目主页： http://code.google.com/p/zruijie4gzhu/

Blog: http://apt-blog.co.cc

Twitter: https://twitter.com/BOYPT

Facebook: http://www.facebook.com/boypt

2009-07-07 于广州大学城 
