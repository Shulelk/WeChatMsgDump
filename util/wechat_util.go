package util

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

type SystemInfo struct {
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	GetSystemInfo = kernel32.NewProc("GetSystemInfo")
)

func GetWeChatProcess() (windows.ProcessEntry32, error) {
	var process windows.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return process, err
	}
	defer windows.CloseHandle(snapshot)
	for {
		err = windows.Process32Next(snapshot, &process)
		if err != nil {
			return process, err
		}
		if windows.UTF16ToString(process.ExeFile[:]) == "WeChat.exe" {
			return process, nil
		}
	}
}

func GetWeChatWinModule(process windows.ProcessEntry32) (windows.ModuleEntry32, error) {
	var module windows.ModuleEntry32
	module.Size = uint32(unsafe.Sizeof(module))
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, process.ProcessID)
	if err != nil {
		return module, err
	}
	defer windows.CloseHandle(snapshot)
	for {
		err = windows.Module32Next(snapshot, &module)
		if err != nil {
			return module, err
		}
		if windows.UTF16ToString(module.Module[:]) == "WeChatWin.dll" {
			return module, nil
		}
	}
}

func GetPEBits(processHandle windows.Handle, dllBase uintptr) (int, error) {
	// 读取 e_lfanew 字段（PE 文件头的偏移量）
	var eLfanew uint32
	err := windows.ReadProcessMemory(processHandle, dllBase+60, (*byte)(unsafe.Pointer(&eLfanew)), unsafe.Sizeof(eLfanew), nil)
	if err != nil {
		return 0, fmt.Errorf("read e_lfanew error: %v", err)
	}

	// 计算 SizeOfOptionalHeader 的地址
	address := dllBase + uintptr(eLfanew) + 4 + 16

	// 读取 SizeOfOptionalHeader 字段
	var sizeOfOptionalHeader uint16
	err = windows.ReadProcessMemory(processHandle, address, (*byte)(unsafe.Pointer(&sizeOfOptionalHeader)), unsafe.Sizeof(sizeOfOptionalHeader), nil)
	if err != nil {
		return 0, fmt.Errorf("read SizeOfOptionalHeader error: %v", err)
	}

	if sizeOfOptionalHeader == 0xF0 {
		return 64, nil
	}
	return 32, nil
}

func PatternScanAll(processHandle windows.Handle, pattern []byte) ([]uintptr, error) {
	var addresses []uintptr

	var systemInfo SystemInfo
	GetSystemInfo.Call(uintptr(unsafe.Pointer(&systemInfo)))

	// 遍历内存区域
	var baseAddress uintptr
	for baseAddress < systemInfo.lpMaximumApplicationAddress {
		var memoryBasicInfo windows.MemoryBasicInformation
		err := windows.VirtualQueryEx(processHandle, baseAddress, &memoryBasicInfo, unsafe.Sizeof(memoryBasicInfo))
		if err != nil {
			return nil, err
		}

		if memoryBasicInfo.Protect&windows.PAGE_READONLY != 0 || memoryBasicInfo.Protect&windows.PAGE_READWRITE != 0 {
			buffer := make([]byte, memoryBasicInfo.RegionSize)
			var bytesRead uintptr
			err := windows.ReadProcessMemory(processHandle, baseAddress, &buffer[0], uintptr(len(buffer)), &bytesRead)
			if err != nil {
				baseAddress += memoryBasicInfo.RegionSize
				continue
			}

			// 在内存区域中搜索模式
			for offset := 0; offset <= len(buffer)-len(pattern); offset++ {
				if bytes.Equal(buffer[offset:offset+len(pattern)], pattern) {
					addresses = append(addresses, baseAddress+uintptr(offset))
				}
			}
		}

		baseAddress += memoryBasicInfo.RegionSize
	}

	return addresses, nil
}

func GetKeyAddr(processHandle windows.Handle, dllBase uintptr, sizeOfImage uint32, bits int, publicKeyList []uintptr) ([]uintptr, error) {
	var keyAddr []uintptr

	buffer := make([]byte, sizeOfImage)
	err := windows.ReadProcessMemory(processHandle, dllBase, &buffer[0], uintptr(sizeOfImage), nil)
	if err != nil {
		return nil, fmt.Errorf("read WeChatWin.dll error: %v", err)
	}

	byteLen := 4
	if bits == 64 {
		byteLen = 8
	}

	for _, publicKeyAddr := range publicKeyList {
		keyBytes := make([]byte, byteLen)
		for i := 0; i < byteLen; i++ {
			keyBytes[i] = byte(publicKeyAddr >> (i * 8))
		}

		offsets := SearchMemory(buffer, keyBytes)
		if len(offsets) == 0 {
			continue
		}

		for _, offset := range offsets {
			keyAddr = append(keyAddr, dllBase+offset)
		}
	}

	if len(keyAddr) == 0 {
		return nil, nil
	}

	return keyAddr, nil
}

func SearchMemory(parent []byte, child []byte) []uintptr {
	var offsets []uintptr
	index := 0

	for {
		foundIndex := bytes.Index(parent[index:], child)
		if foundIndex == -1 {
			break
		}

		// 计算实际偏移量
		actualOffset := index + foundIndex
		offsets = append(offsets, uintptr(actualOffset))

		// 更新 index，继续查找
		index = actualOffset + 1
	}

	return offsets
}

func ReadKey(processHandle windows.Handle, keyAddr []uintptr, bits int) string {
	keyLenOffset := uintptr(0x8c)
	if bits == 64 {
		keyLenOffset = 0xd0
	}

	for _, addr := range keyAddr {
		keyLen := make([]byte, 1)
		var bytesRead uintptr
		err := windows.ReadProcessMemory(processHandle, addr-keyLenOffset, &keyLen[0], 1, &bytesRead)
		if err != nil {
			continue
		}
		if keyLen[0] == 0 {
			continue
		}
		var keyAddrBuf []byte
		if bits == 32 {
			keyAddrBuf = make([]byte, 4)
		} else {
			keyAddrBuf = make([]byte, 8)
		}
		offset := uintptr(0x90)
		if bits == 64 {
			offset = 0xd8
		}
		err = windows.ReadProcessMemory(processHandle, addr-offset, &keyAddrBuf[0], uintptr(len(keyAddrBuf)), &bytesRead)
		if err != nil {
			continue
		}

		// 将 keyAddrBuf 转换为 uintptr
		var keyPtr uintptr
		if bits == 32 {
			keyPtr = uintptr(keyAddrBuf[0]) | uintptr(keyAddrBuf[1])<<8 | uintptr(keyAddrBuf[2])<<16 | uintptr(keyAddrBuf[3])<<24
		} else {
			keyPtr = uintptr(keyAddrBuf[0]) | uintptr(keyAddrBuf[1])<<8 | uintptr(keyAddrBuf[2])<<16 | uintptr(keyAddrBuf[3])<<24 |
				uintptr(keyAddrBuf[4])<<32 | uintptr(keyAddrBuf[5])<<40 | uintptr(keyAddrBuf[6])<<48 | uintptr(keyAddrBuf[7])<<56
		}

		key := make([]byte, keyLen[0])
		err = windows.ReadProcessMemory(processHandle, keyPtr, &key[0], uintptr(len(key)), &bytesRead)
		if err != nil {
			continue
		}

		keyHex := hex.EncodeToString(key)
		if CheckKey(keyHex) {
			return keyHex
		}
	}

	return ""
}

func CheckKey(key string) bool {
	if key == "" || len(key) != 64 {
		return false
	}
	return true
}

func GetInfoFilePath(wxid string) string {
	if wxid == "" {
		return ""
	}

	var wDir string
	isWDir := false

	// 尝试从注册表获取 WeChat 文件保存路径
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Tencent\WeChat`, registry.READ)
	if err == nil {
		value, _, err := key.GetStringValue("FileSavePath")
		if err == nil {
			wDir = value
			isWDir = true
		}
		key.Close()
	}

	// 如果注册表没有找到路径，尝试从配置文件读取
	if !isWDir {
		userProfile := os.Getenv("USERPROFILE")
		path3ebffe94 := filepath.Join(userProfile, "AppData", "Roaming", "Tencent", "WeChat", "All Users", "config", "3ebffe94.ini")
		content, err := os.ReadFile(path3ebffe94)
		if err == nil {
			wDir = string(content)
			isWDir = true
		} else {
			wDir = "MyDocument:"
		}
	}

	// 如果路径是 "MyDocument:"，尝试从注册表获取文档路径
	if wDir == "MyDocument:" {
		key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, registry.READ)
		if err == nil {
			documentsPath, _, err := key.GetStringValue("Personal")
			if err == nil {
				documentsPaths := strings.Split(documentsPath, "\\")
				if strings.Contains(documentsPaths[0], "%") {
					envVar := strings.Trim(documentsPaths[0], "%")
					envValue := os.Getenv(envVar)
					wDir = filepath.Join(envValue, filepath.Join(documentsPaths[1:]...))
				} else {
					wDir = documentsPath
				}
			}
			key.Close()
		} else {
			profile := os.Getenv("USERPROFILE")
			wDir = filepath.Join(profile, "Documents")
		}
	}

	msgDir := filepath.Join(wDir, "WeChat Files")
	filePath := filepath.Join(msgDir, wxid)

	if _, err := os.Stat(filePath); err == nil {
		return filePath
	}

	return ""
}

func ScanPatternPage(handle windows.Handle, address uintptr, pattern []byte, returnMultiple bool, checkMemoryProtection bool) (uintptr, interface{}, error) {
	var mbi windows.MemoryBasicInformation
	err := windows.VirtualQueryEx(handle, address, &mbi, unsafe.Sizeof(mbi))
	if err != nil {
		return 0, nil, err
	}

	nextRegion := mbi.BaseAddress + mbi.RegionSize

	var havePermissionToScanMemoryPage bool
	if checkMemoryProtection {
		allowedProtections := []uint32{
			windows.PAGE_EXECUTE,
			windows.PAGE_EXECUTE_READ,
			windows.PAGE_EXECUTE_READWRITE,
			windows.PAGE_READWRITE,
			windows.PAGE_READONLY,
		}

		havePermissionToScanMemoryPage = false
		for _, protection := range allowedProtections {
			if mbi.Protect == protection {
				havePermissionToScanMemoryPage = true
				break
			}
		}
	} else {
		havePermissionToScanMemoryPage = true
	}

	if mbi.State != windows.MEM_COMMIT || !havePermissionToScanMemoryPage {
		return nextRegion, nil, nil
	}

	pageBytes := make([]byte, mbi.RegionSize-(address-mbi.BaseAddress))
	var bytesRead uintptr
	err = windows.ReadProcessMemory(handle, address, &pageBytes[0], uintptr(len(pageBytes)), &bytesRead)
	if err != nil {
		return nextRegion, nil, err
	}

	var found interface{}
	if !returnMultiple {
		// 查找第一个匹配项
		re := regexp.MustCompile(string(pattern))
		match := re.FindIndex(pageBytes)
		if match != nil {
			found = address + uintptr(match[0])
		}
	} else {
		// 查找所有匹配项
		var foundAddresses []uintptr
		re := regexp.MustCompile(string(pattern))
		matches := re.FindAllIndex(pageBytes, -1)
		for _, match := range matches {
			foundAddresses = append(foundAddresses, address+uintptr(match[0]))
		}
		found = foundAddresses
	}

	return nextRegion, found, nil
}

func SearchMemoryForWxid(handle windows.Handle, pattern []byte, returnMultiple bool, findNum int) ([]uintptr, error) {
	var nextRegion uintptr
	var found []uintptr

	// 设置用户空间的内存限制
	userSpaceLimit := uintptr(0x7FFFFFFF0000)
	if uintptr(unsafe.Sizeof(uintptr(0))) <= 4 {
		userSpaceLimit = 0x7fff0000
	}

	for nextRegion < userSpaceLimit {
		nextRegion1, pageFound, err := ScanPatternPage(handle, nextRegion, pattern, returnMultiple, true)
		nextRegion = nextRegion1
		if err != nil {
			return nil, fmt.Errorf("ScanPatternPage error: %v", err)
		}

		if !returnMultiple && pageFound != nil {
			return []uintptr{pageFound.(uintptr)}, nil
		}

		if pageFound != nil {
			switch v := pageFound.(type) {
			case []uintptr:
				found = append(found, v...)
			case uintptr:
				found = append(found, v)
			}
		}

		if len(found) > findNum {
			break
		}
	}

	return found, nil
}

func GetInfoWxid(hProcess windows.Handle) string {
	addrs, err := SearchMemoryForWxid(hProcess, []byte(`\\Msg\\FTSContact`), true, 100)
	if err != nil {
		return ""
	}

	var wxids []string
	for _, addr := range addrs {
		array := make([]byte, 80)
		err := windows.ReadProcessMemory(hProcess, addr-30, &array[0], uintptr(len(array)), nil)
		if err != nil {
			return ""
		}

		array = bytes.Split(array, []byte("\\Msg"))[0]
		parts := bytes.Split(array, []byte("\\"))
		if len(parts) > 0 {
			wxids = append(wxids, string(parts[len(parts)-1]))
		}
	}

	if len(wxids) == 0 {
		return ""
	}

	counts := make(map[string]int)
	for _, wxid := range wxids {
		counts[wxid]++
	}

	// 查找出现最多的 wxid
	var maxWxid string
	var maxCount int
	for wxid, count := range counts {
		if count > maxCount {
			maxWxid = wxid
			maxCount = count
		}
	}

	return maxWxid
}

func GetVersion(module windows.ModuleEntry32) (string, error) {
	image, imgErr := windows.LoadLibraryEx(windows.UTF16ToString(module.ExePath[:]), 0, windows.LOAD_LIBRARY_AS_DATAFILE)
	if imgErr != nil {
		return "", fmt.Errorf("LoadLibraryEx error: %v", imgErr)
	}
	resInfo, infoErr := windows.FindResource(image, windows.ResourceID(1), windows.RT_VERSION)
	if infoErr != nil {
		return "", fmt.Errorf("FindResource error: %v", infoErr)
	}
	resData, dataErr := windows.LoadResourceData(image, resInfo)
	if dataErr != nil {
		return "", fmt.Errorf("LoadResourceData error: %v", dataErr)
	}
	var info *windows.VS_FIXEDFILEINFO
	size := uint32(unsafe.Sizeof(*info))
	err := windows.VerQueryValue(unsafe.Pointer(&resData[0]), `\`, unsafe.Pointer(&info), &size)
	if err != nil {
		return "", fmt.Errorf("VerQueryValue error: %v", err)
	}
	// 从低位到高位，分别为主版本号、次版本号、修订号、编译号
	version := fmt.Sprintf("%d.%d.%d.%d", info.FileVersionMS>>16, info.FileVersionMS&0xffff, info.FileVersionLS>>16, info.FileVersionLS&0xffff)
	return version, nil
}
