package configstore

import (
	"testing"
)

type myConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func TestNewConfigStore(t *testing.T) {
	// 测试用例1：正常创建ConfigStore对象
	filename := "./myconfig.data"
	key := "0123456789abcdef0123456789abcdef"
	cs, err := NewConfigStore[myConfig](filename, key)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if cs.filename != filename {
		t.Errorf("Expected filename to be %s, but got: %s", filename, cs.filename)
	}
	if cs.key != key {
		t.Errorf("Expected key to be %s, but got: %s", key, cs.key)
	}
}

func TestSaveConfig(t *testing.T) {
	// 测试用例2：保存配置
	filename := "./myconfig.data"
	key := "0123456789abcdef0123456789abcdef"
	cs, err := NewConfigStore[myConfig](filename, key)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	config := myConfig{Username: "testuser", Password: "testpass"}
	err = cs.SaveConfig(config)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	loadConfig, err := cs.LoadConfigOrDefault(myConfig{})
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if loadConfig.Username != config.Username {
		t.Errorf("Expected username to be %s, but got: %s", config.Username, loadConfig.Username)
	}
	if loadConfig.Password != config.Password {
		t.Errorf("Expected password to be %s, but got: %s", config.Password, loadConfig.Password)
	}
}
