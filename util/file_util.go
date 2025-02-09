package util

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	SQLITE_FILE_HEADER = "SQLite format 3\x00"
	KEY_SIZE           = 32
	DEFAULT_PAGESIZE   = 4096
	DEFAULT_ITER       = 64000
)

var CurrentPath = func() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return ""
	}
	return dir
}()

func DecryptCmd(wxid, sqliteKey string) {
	var err error
	err = CopyMsgDb(filepath.Join(wxid, "Msg", "Multi"))
	if err != nil {
		log.Fatalf("CopyMsgDb error: %v", err)
	}
	err = CopyMsgDb(filepath.Join(wxid, "Msg"))
	if err != nil {
		log.Fatalf("CopyMicroMsgDb error: %v", err)
	}
	// 解密tmp目录下的所有.db文件，解密后的文件放在 decrypted 目录下
	err = DecryptDb(sqliteKey)
	if err != nil {
		log.Fatalf("DecryptDb error: %v", err)
	}

	// 清理缓存目录
	err = os.RemoveAll(CurrentPath + "\\tmp")
	if err != nil {
		log.Printf("RemoveAll error: %v\n", err)
	}
	err = CompressFolder(CurrentPath+"\\decrypted", "db.zip")
	if err != nil {
		log.Printf("CompressFolder error: %v\n", err)
	} else {
		log.Println("Decrypt success: Decrypted files are in db.zip")
	}
	err = os.RemoveAll(CurrentPath + "\\decrypted")
	if err != nil {
		log.Printf("RemoveAll error: %v\n", err)
	}
}

func CopyMsgDb(dataDir string) error {
	// 判断目录是否存在
	_, err := os.Stat(dataDir)
	if err != nil {
		return err
	}
	// 判断运行目录是否存在tmp目录没有则创建
	_, err = os.Stat(CurrentPath + "\\tmp")
	if err != nil {
		err = os.Mkdir(CurrentPath+"\\tmp", os.ModePerm)
		if err != nil {
			return err
		}
	}
	// 正则匹配，将所有MSG数字.db文件拷贝到tmp目录，不扫描子目录
	err = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if ok, _ := filepath.Match("MSG*.db", info.Name()); ok {
			err = CopyFile(path, CurrentPath+"\\tmp\\"+info.Name())
			if err != nil {
				return err
			}
		}
		// 复制MicroMsg.db到tmp目录
		if ok, _ := filepath.Match("MicroMsg.db", info.Name()); ok {
			err = CopyFile(path, CurrentPath+"\\tmp\\"+info.Name())
			if err != nil {
				return err
			}
		}
		// 语音消息
		if ok, _ := filepath.Match("MediaMSG*.db", info.Name()); ok {
			err = CopyFile(path, CurrentPath+"\\tmp\\"+info.Name())
			if err != nil {
				return err
			}
		}
		// 朋友圈数据
		if ok, _ := filepath.Match("Sns.db", info.Name()); ok {
			err = CopyFile(path, CurrentPath+"\\tmp\\"+info.Name())
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 如果不存在decrypted目录则创建
	_, err = os.Stat(CurrentPath + "\\decrypted")
	if err != nil {
		err = os.Mkdir(CurrentPath+"\\decrypted", os.ModePerm)
		if err != nil {
			return err
		}
	}

	return nil
}

func DecryptDb(key string) error {
	// 判断tmp目录是否存在
	_, err := os.Stat(CurrentPath + "\\tmp")
	if err != nil {
		return fmt.Errorf("please put db files in tmp dir")
	}
	// 判断decrypted目录是否存在
	_, err = os.Stat(CurrentPath + "\\decrypted")
	if err != nil {
		return err
	}
	// 正则匹配，将所有MSG数字.db文件解密到decrypted目录，不扫描子目录
	err = filepath.Walk(CurrentPath+"\\tmp", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if ok, _ := filepath.Match("*.db", info.Name()); ok {
			err = Decrypt(key, path, CurrentPath+"\\decrypted\\"+info.Name())
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func Decrypt(key string, filePath string, decryptedPath string) error {
	password, err := hex.DecodeString(strings.Replace(key, " ", "", -1))
	if err != nil {
		return err
	}
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	blist, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	salt := blist[:16]
	byteKey := pbkdf2.Key(password, salt, DEFAULT_ITER, KEY_SIZE, sha1.New)
	first := blist[16:DEFAULT_PAGESIZE]
	mac_salt := make([]byte, 16)
	for i := 0; i < 16; i++ {
		mac_salt[i] = salt[i] ^ 58
	}
	mac_key := pbkdf2.Key(byteKey, mac_salt, 2, KEY_SIZE, sha1.New)
	hash_mac := hmac.New(sha1.New, mac_key)
	hash_mac.Write(first[:len(first)-32])
	hash_mac.Write([]byte{1, 0, 0, 0})
	if !bytes.Equal(hash_mac.Sum(nil), first[len(first)-32:len(first)-12]) {
		log.Fatalf("sqlite Key Wrong.")
	}

	// 将python代码：blist = [blist[i:i + DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)] 转成go语言
	newblist := make([][]byte, 0)
	for i := DEFAULT_PAGESIZE; i < len(blist); i += DEFAULT_PAGESIZE {
		newblist = append(newblist, blist[i:i+DEFAULT_PAGESIZE])
	}

	// 将文件写入decryptePath
	deFile, err := os.OpenFile(decryptedPath, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer deFile.Close()
	deFile.Write([]byte(SQLITE_FILE_HEADER))
	t, err := aes.NewCipher(byteKey)
	if err != nil {
		return err
	}
	iv := first[len(first)-48 : len(first)-32]
	blockMode := cipher.NewCBCDecrypter(t, iv)
	decrypted := make([]byte, len(first)-48)
	blockMode.CryptBlocks(decrypted, first[:len(first)-48])
	deFile.Write(decrypted)
	deFile.Write(first[len(first)-48:])

	for _, i := range newblist {
		t, err := aes.NewCipher(byteKey)
		if err != nil {
			return err
		}
		blockMode := cipher.NewCBCDecrypter(t, i[len(i)-48:len(i)-32])
		decrypted := make([]byte, len(i)-48)
		blockMode.CryptBlocks(decrypted, i[:len(i)-48])
		deFile.Write(decrypted)
		deFile.Write(i[len(i)-48:])
	}
	return nil
}

func CopyFile(src, dst string) error {
	// 判断源文件是否存在
	_, err := os.Stat(src)
	if err != nil {
		return err
	}
	// 读取源文件
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	// 创建目标文件
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	// 拷贝文件
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}
	return nil
}

func CompressFolder(source, target string) error {
	// 创建目标 ZIP 文件
	zipFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// 创建 ZIP 写入器
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// 遍历文件夹
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 创建 ZIP 文件头
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// 设置文件头中的文件名
		header.Name, err = filepath.Rel(source, path)
		if err != nil {
			return err
		}

		// 如果是目录，需要在 ZIP 文件中创建一个目录条目
		if info.IsDir() {
			header.Name += "/"
		} else {
			// 设置文件压缩方法
			header.Method = zip.Deflate
		}

		// 写入文件头
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		// 如果是文件，将文件内容写入 ZIP 文件
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}
		}

		return nil
	})
}
