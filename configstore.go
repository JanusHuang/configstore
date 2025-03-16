package configstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
)

type ConfigStore[T any] struct {
	filename string
	key      string
	mu       sync.Mutex
}

// 为函数添加泛型约束，这里使用空接口作为通用约束，表示可以是任意类型
func NewConfigStore[T any](filename string, key string) (*ConfigStore[T], error) {
	// 检查 key 的长度是否符合要求
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key length must be 16 or 24 or 32")
	}

	if !fileExists(filename) {
		// 文件不存在，创建一个新的文件
		err := createFile(filename)
		if err != nil {
			return nil, err
		}
	}

	return &ConfigStore[T]{filename: filename, key: key}, nil
}

func (cs *ConfigStore[T]) LoadConfigOrDefault(defaultConfig T) (T, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// 读取文件内容
	fileData, err := readFile(cs.filename)
	if err != nil {
		return defaultConfig, err
	}

	// 提取 IV 和加密数据
	if len(fileData) < aes.BlockSize {
		return defaultConfig, errors.New("invalid encrypted data")
	}
	iv := fileData[:aes.BlockSize]
	ciphertext := fileData[aes.BlockSize:]

	// 解密文件内容
	decryptedData, err := decryptAES(ciphertext, []byte(cs.key), iv)
	if err != nil {
		return defaultConfig, err
	}

	// 将解密后的数据解析为配置对象
	var config T
	err = json.Unmarshal(decryptedData, &config)
	if err != nil {
		return defaultConfig, err
	}

	return config, nil
}

func (cs *ConfigStore[T]) SaveConfig(config T) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// 将配置转换为字节切片
	configData, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// 加密配置数据
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	encryptedData, err := encryptAES(configData, []byte(cs.key), iv)
	if err != nil {
		return err
	}

	// 将 IV 和加密数据写入文件
	encryptedData = append(iv, encryptedData...)
	return writeFile(cs.filename, encryptedData)
}

func createFile(filename string) error {
	// 创建一个新的文件
	_, err := os.Create(filename)
	if err != nil {
		return err
	}
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func readFile(s string) ([]byte, error) {
	// 打开文件
	file, err := os.Open(s)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := fileInfo.Size()

	// 读取文件内容
	fileData := make([]byte, fileSize)
	_, err = file.Read(fileData)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return fileData, nil
}

func writeFile(s string, encryptedData []byte) error {
	// 打开文件
	file, err := os.OpenFile(s, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// 将加密数据写入文件
	_, err = file.Write(encryptedData)
	if err != nil {
		return err
	}
	return nil
}

// 填充数据以满足 AES 块大小
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// 去除填充数据
func pkcs7UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

// 加密数据
func encryptAES(data []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	data = pkcs7Padding(data, blockSize)
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)
	return ciphertext, nil
}

// 解密数据
func decryptAES(data []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// blockSize := block.BlockSize()
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)
	plaintext = pkcs7UnPadding(plaintext)
	return plaintext, nil
}
