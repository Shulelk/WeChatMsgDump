## WeChatMsgDump

WeChatMsgDump 是一个用 Go 编写的动态获取微信数据库密钥并解密数据库文件的小工具。

### 基本功能

flag 均为可选。

```
Usage of WeChatMsgDump.exe:
  -dbfile
        Put WeChat Files db file to tmp dir
  -dumpKey
        only dump key
  -key string
        wx sqlite key
  -wxdir string
        WeChat Files dir, like: C:\WeChat Files\wxid_xxxxxxxxxxxx
```

### 使用例子

![WindowsTerminal_3mcr3LN0r5](https://chevereto.1i6w31fen9.top/images/2025/01/15/WindowsTerminal_3mcr3LN0r5.png)

![7zFM_KvJsT6SzQa](https://chevereto.1i6w31fen9.top/images/2025/01/15/7zFM_KvJsT6SzQa.png)

可将 db.zip 解压，并使用相关数据库管理工具进行打开分析。例如 Firfox 中的 SQLite Manager 插件。

![firefox_JYt4zDMZX9](https://chevereto.1i6w31fen9.top/images/2025/01/15/firefox_JYt4zDMZX9.png)

### 数据库相关表信息

MicroMsg.db 保存了一些联系人信息。

例如执行如下 SQL 语句即可获得联系人的微信号，备注，微信名的信息。

```SQL 
select UserName,Alias,Remark,NickName from Contact
```

MSG*.db 主要保存了聊天记录信息。其中 `IsSender=1` 字段代表为本人发送消息。例如查询某个联系人的聊天记录：

```SQL 
SELECT * from MSG where StrTalker = f'{MicroMsg.Contact.UserName}' ORDER BY CreateTime DESC limit 10
```

其它表介绍：https://github.com/LC044/WeChatMsg/blob/master/doc/%E6%95%B0%E6%8D%AE%E5%BA%93%E4%BB%8B%E7%BB%8D.md

### 参考

https://github.com/LC044/WeChatMsg/

https://github.com/SpenserCai/GoWxDump/
