zRuijie4GZHU用户手册

    zRuijie4GZHU是基于pcap库的跨平台（暂限Unix系列）锐捷兼容客户端，为目前广州大学大学城校区的校园网接入协议而兼容，但不限于广州大学使用，可能兼容其他部署了锐捷的环境。 

快速安装与使用步骤
    
    1.下载适合的二进制包；
    2.解压;
    3.修改runruijie，填入用户名密码（替换原来的user、pass）
    4.运行sudo ./install
    5.运行runruijie，上网。

    如果有出错或需要自己定制安装位置等，请读下面的文字。

    若想在每次登录看到服务器发来的信息，需要安装notify-send；［请看以下“运行”一节］
    服务器信息会按日期记录在~/.ruijielog文件中。

程序

    zRuijie4GZHU包含核心程序以及用户脚本，不建议分离，但用户可自由配置。 

    * 核心程序：zruijie
    * 安装脚本：install
    * 运行脚本：runruijie 

安装

    在安装前，请用户先编辑运行脚本文件runruijie，将其中的username和password分别修改成您的帐号和密码并保存。 

    安装需要root权限，这通常使用sudo或者su -c实现 

    sudo ./install 

    安装程序会复制核心程序zruijie以及用户脚本runruijie到系统目录/usr/bin，并设置相关文件，如果用户希望安装到其他目录，只需要在install后给出目的目录，如sudo ./install /usr/local/bin，但请保证目的目录在系统PATH环境变量内。 

    成功执行安装将看到####Installation Done.####的提示。 

运行

    如果用户配置的帐号信息无误并且安装成功，那么用户只需要运行runruijie，即可看到有关的认证成功的信息。 

    如果系统内安装有libnotify的工具，运行脚本时会出现如图的提示(Ubuntu中的效果，如果没有，请安装sudo apt-get install libnotify-bin):[没有安装libnotify-bin虽然不能显示，但并不影响认证。]

    可以通过桌面的启动器运行runruijie，或把把runruijie加入到比如GNOME的“系统->首选项->启动程序“当中，以便每次登录系统即可自动认证上网。 

    唯一需要注意的是，如果出现账户信息出错、欠费等情况，程序会给出终止提示，此时有约10秒的session终结期，当然用户可以Ctrl + C马上终结程序，但是在session终结之前再次进行任何认证，都不能成功的。 

终止

    用户执行一次`runruijie -l`，即可成功离线。 

编译：

    用户可通过svn获得最新的开发代码：

        svn checkout http://zruijie4gzhu.googlecode.com/svn/trunk/ zruijie4gzhu

    或者从项目主页下载版本代码包并自行解压。 

        http://code.google.com/p/zruijie4gzhu/downloads/list

    编译需要libpcap库（默认使用/usr/lib/libpcap.a静态库，若不存在或者需要动态链接，请修改Makefile），一般Linux发行版里面安装libpcap包即可，在ubuntu中，需要libpcap-dev：

        sudo apt-get install libpcap-dev

    从命令行进入源代码目录，运行make，应该很快就能生成zruijie，当然前提是系统中安装了gcc等编译环境，这里不再累赘。 

    make install也可完成安装，这根运行install效果基本一样，同样有make uninstall以供卸载。再次提醒安装前先修改runruijie文件内的账户信息。 

    MacOS / BSD 用户编译：

    Mac用户首先要安装gcc，需要从http://connect.apple.com/下载安装Xcode Tools，具体请查阅Apple Dev的信息。然后下载libpcap的源代码，http://www.tcpdump.org/release/libpcap-1.0.0.tar.gz，解压后分别运行
    ./configure
    make 
    sudo make install

    最后在本程序的源代码目录运行

    make -f Makefile.bsd

    即可生成可运行程序。安装运行参考上文Linux部分。

其他

    当用户使用的认证网卡不是默认的第一个网卡（如eth0）时，可使用runruijie --dev eth1这样的参数方式启动程序，或者修改runruijie文件内ARGS=""，加入自定义的参数。 

    如果发现不能完成认证，请留意认证过程的提示：

    ##### zRuijie for GZHU ver. 0.5 ######
    Device:     eth0   <- 此处是否是合适的网卡设备

    程序还有其他的配置选项，如果设置客户端版本号等，但这些参数只是在默认不能认证是才使用的参数，具体请查看--help的内容。 



Another PT Work.

GMail GTalk: pentie@gmail.com

项目主页： http://code.google.com/p/zruijie4gzhu/

Blog: http://apt-blog.net

Twitter: https://twitter.com/BOYPT

2009-07-07 于广州大学城 
