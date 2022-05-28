package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"os"
)

var Config *Conf

type Conf struct {
	Addr             string `json:"addr"`
	User             string `json:"user"`
	SSHDirPath       string `json:"ssh_dir_path"`
	Password         string `json:"password"`
	PrivateKey       string `json:"private_key"`
	CommandChainPath string `json:"command_chain_path"`

	Commands []string
}

func ReadConfig(path string) (*Conf, error) {
	config := new(Conf)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(config.CommandChainPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var cmds []string
	for scanner.Scan() {
		cmds = append(cmds, scanner.Text())
	}
	config.Commands = cmds
	return config, nil
}

func init() {
	configPath := "./conf.json"
	Config, _ = ReadConfig(configPath)
}
