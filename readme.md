DNSMaper
======

域传送检测/子域名枚举/Banner检测/生成地图

DNS Zone Transfer Test/SubDomain BruteForce/Banner Version Detect/Generate Map

### DNSMaper
DNSMaper拥有与众多子域名枚举工具相似的功能,诸如域传送漏洞检测,子域名枚举,IP地址获取

改进后增加服务器WEBServer版本探测,网站标题获取,经纬度获取与GoogleMap生成的功能.

代码在枚举子域名部分没有重复造轮,借鉴subdomain-bruteforcer项目代码

因代码使用发布仓促,仅在MacOS&Python2.7测试,Win环境请修改部分代码.

其他项目请见:

[http://le4f.net/proj.md](http://le4f.net/proj.md)

### 文件说明

```
.
├── dnsmaper.py(核心代码)
├── dnsmapper.png(演示截图)
├── db
│   ├── GeoLite2-City.mmdb(调用GEOIP获取经纬度等信息)
│   ├── resolvers.db(DNS解析服务器列表[可修改])
│   ├── subs.db(子域名字典[可修改])
├── log
│   ├── xxx.log(扫描结果的log文本)
│   └── xxx.html(扫描结果的GoogleMap页面)
└── readme.md(项目说明)
```

### 使用帮助

请使用Python dnsmaper.py -h查看参数

```
 ____  _   _ ____  __  __
|  _ \| \ | / ___||  \/  | __ _ _ __   ___ _ __
| | | |  \| \___ \| |\/| |/ _` | '_ \ / _ \ '__|
| |_| | |\  |___) | |  | | (_| | |_) |  __/ |
|____/|_| \_|____/|_|  |_|\__,_| .__/ \___|_|
                               |_|
 =# Author: le4f.net
 =# Mail  : le4f#xdsec.org

Usage: dnsmaper.py [options] target

Options:
  -h, --help            show this help message and exit
  -c THREAD_COUNT, --thread_count=THREAD_COUNT
                        [optional]number of lookup theads,default=17
  -s SUBS, --subs=SUBS  (optional)list of subdomains,  default='./db/subs.db'
  -r RESOLVERS, --resolvers=RESOLVERS
                        (optional)list of DNS
                        resolvers,default='./db/resolvers.db'
```

### 演示图片

测试如
```
python dnsmaper.py whitehouse.gov
```

![https://raw.githubusercontent.com/le4f/dnsmaper/master/dnsmapper.png](https://raw.githubusercontent.com/le4f/dnsmaper/master/dnsmapper.png)

### 项目参考

DNS枚举
[https://github.com/TheRook/subbrute](https://github.com/TheRook/subbrute)

GoogleMap生成
[https://x0day.me/](http://x0day.me/)


### Author

[le4f](http://le4f.net/)
