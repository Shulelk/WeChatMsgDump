package main

import (
	"WeChatMsgDump/util"
	"flag"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)

func main() {
	dumpKey := flag.Bool("dumpKey", false, "only dump key")
	sqliteKey := flag.String("key", "", "wx sqlite key")
	wxdir := flag.String("wxdir", "", "WeChat Files dir, like: C:\\WeChat Files\\wxid_xxxxxxxxxxxx")
	dbFile := flag.Bool("dbfile", false, "Put WeChat Files db file to tmp dir")
	flag.Parse()

	// 离线
	if *dbFile && *sqliteKey != "" {
		err := util.DecryptDb(*sqliteKey)
		if err != nil {
			log.Fatalf("DecryptDb error: %v", err)
		}
		return
	}

	var wechatProcessHandle windows.Handle

	if *sqliteKey == "" {
		process, err := util.GetWeChatProcess()
		if err != nil {
			log.Fatalf("GetWeChatProcess error: %v", err)
		}

		wechatProcessHandle, err = windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, process.ProcessID)
		if err != nil {
			log.Fatalf("OpenProcess error: %v", err)
		}

		module, err := util.GetWeChatWinModule(process)
		if err != nil {
			log.Fatalf("GetWeChatWinModule error: %v", err)
		}

		version, err := util.GetVersion(module)
		if err != nil {
			log.Printf("GetVersion error: %v", err)
		} else {
			log.Printf("WeChat Version: %v", version)
		}

		var moduleInfo windows.ModuleInfo
		err = windows.GetModuleInformation(wechatProcessHandle, module.ModuleHandle, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))
		if err != nil {
			log.Fatalf("GetModuleInformation error: %v", err)
		}

		bits, err := util.GetPEBits(wechatProcessHandle, moduleInfo.BaseOfDll)
		if err != nil {
			log.Fatalf("GetPEBits error: %v", err)
		}

		keyBytes := []byte("-----BEGIN PUBLIC KEY-----\n")
		publicKeyList, err := util.PatternScanAll(wechatProcessHandle, keyBytes)
		if err != nil {
			log.Fatalf("PatternScanAll error: %v", err)
		}
		if len(publicKeyList) == 0 {
			log.Fatalf("Failed to find PUBLIC KEY")
		}

		keyAddr, err := util.GetKeyAddr(wechatProcessHandle, moduleInfo.BaseOfDll, moduleInfo.SizeOfImage, bits, publicKeyList)
		if keyAddr == nil || err != nil {
			log.Fatalf("GetKeyAddr error: %v", err)
		}

		*sqliteKey = util.ReadKey(wechatProcessHandle, keyAddr, bits)
		if *sqliteKey == "" {
			log.Fatalf("Failed to find key")
		} else {
			log.Printf("sqlite key:%s\n", *sqliteKey)
		}
	}

	if *dumpKey {
		return
	}

	if *wxdir == "" && wechatProcessHandle != 0 {
		wxid := util.GetInfoWxid(wechatProcessHandle)
		log.Printf("WeChat User: %s", wxid)
		*wxdir = util.GetInfoFilePath(wxid)
		log.Printf("WeChat Info Dir: %s", *wxdir)
	}

	if *wxdir != "" && *sqliteKey != "" {
		util.DecryptCmd(*wxdir, *sqliteKey)
	} else {
		flag.PrintDefaults()
	}

}
