package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/karimra/gnmic/collector"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/ssh/terminal"
)

var ErrNoTargetsFound = errors.New("no targets found")

func (c *Config) GetTargets() (map[string]*collector.TargetConfig, error) {
	defGrpcPort := c.FileConfig.GetString("port")
	// case address is defined in .Address
	if len(c.Address) > 0 {
		if c.Username == "" {
			defUsername, err := readUsername()
			if err != nil {
				return nil, err
			}
			c.Username = defUsername
		}
		if c.Password == "" {
			defPassword, err := readPassword()
			if err != nil {
				return nil, err
			}
			c.Password = defPassword
		}
		for _, addr := range c.Address {
			tc := new(collector.TargetConfig)
			if !strings.HasPrefix(addr, "unix://") {
				_, _, err := net.SplitHostPort(addr)
				if err != nil {
					if strings.Contains(err.Error(), "missing port in address") ||
						strings.Contains(err.Error(), "too many colons in address") {
						addr = net.JoinHostPort(addr, defGrpcPort)
					} else {
						c.logger.Printf("error parsing address '%s': %v", addr, err)
						return nil, fmt.Errorf("error parsing address '%s': %v", addr, err)
					}
				}
			}
			tc.Address = addr
			c.setTargetConfigDefaults(tc)
			c.Targets[tc.Name] = tc
		}
		if c.Debug {
			c.logger.Printf("targets: %v", c.Targets)
		}
		return c.Targets, nil
	}
	// case targets is defined in config file
	targetsInt := c.FileConfig.Get("targets")
	targetsMap := make(map[string]interface{})
	switch targetsInt := targetsInt.(type) {
	case string:
		for _, addr := range strings.Split(targetsInt, " ") {
			targetsMap[addr] = nil
		}
	case map[string]interface{}:
		targetsMap = targetsInt
	case nil:
		return nil, ErrNoTargetsFound
	default:
		return nil, fmt.Errorf("unexpected targets format, got: %T", targetsInt)
	}
	if len(targetsMap) == 0 {
		return nil, ErrNoTargetsFound
	}

	newTargetsConfig := make(map[string]*collector.TargetConfig)
	for addr, t := range targetsMap {
		if !strings.HasPrefix(addr, "unix://") {
			_, _, err := net.SplitHostPort(addr)
			if err != nil {
				if strings.Contains(err.Error(), "missing port in address") ||
					strings.Contains(err.Error(), "too many colons in address") {
					addr = net.JoinHostPort(addr, defGrpcPort)
				} else {
					c.logger.Printf("error parsing address '%s': %v", addr, err)
					return nil, fmt.Errorf("error parsing address '%s': %v", addr, err)
				}
			}
		}
		tc := new(collector.TargetConfig)
		switch t := t.(type) {
		case map[string]interface{}:
			decoder, err := mapstructure.NewDecoder(
				&mapstructure.DecoderConfig{
					DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
					Result:     tc,
				},
			)
			if err != nil {
				return nil, err
			}
			err = decoder.Decode(t)
			if err != nil {
				return nil, err
			}
		case nil:
		default:
			return nil, fmt.Errorf("unexpected targets format, got a %T", t)
		}
		tc.Address = addr
		c.setTargetConfigDefaults(tc)
		if c.Debug {
			c.logger.Printf("read target config: %s", tc)
		}
		newTargetsConfig[tc.Name] = tc
	}
	c.Targets = newTargetsConfig

	subNames := c.FileConfig.GetStringSlice("subscribe-name")
	if len(subNames) == 0 {
		if c.Debug {
			c.logger.Printf("targets: %v", c.Targets)
		}
		return c.Targets, nil
	}
	for n := range c.Targets {
		c.Targets[n].Subscriptions = subNames
	}
	if c.Debug {
		c.logger.Printf("targets: %v", c.Targets)
	}
	return c.Targets, nil
}

func readUsername() (string, error) {
	var username string
	fmt.Print("username: ")
	_, err := fmt.Scan(&username)
	if err != nil {
		return "", err
	}
	return username, nil
}
func readPassword() (string, error) {
	fmt.Print("password: ")
	pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(pass), nil
}

func (c *Config) setTargetConfigDefaults(tc *collector.TargetConfig) {
	if tc.Name == "" {
		tc.Name = tc.Address
	}
	if tc.Username == nil {
		tc.Username = &c.Username
	}
	if tc.Password == nil {
		tc.Password = &c.Password
	}
	if tc.Timeout == 0 {
		tc.Timeout = c.Timeout
	}
	if tc.Insecure == nil {
		tc.Insecure = &c.Insecure
	}
	if tc.SkipVerify == nil {
		tc.SkipVerify = &c.SkipVerify
	}
	if tc.Insecure != nil && !*tc.Insecure {
		if tc.TLSCA == nil {
			if c.TLSCa != "" {
				tc.TLSCA = &c.TLSCa
			}
		}
		if tc.TLSCert == nil {
			tc.TLSCert = &c.TLSCert
		}
		if tc.TLSKey == nil {
			tc.TLSKey = &c.TLSKey
		}
	}
	if tc.RetryTimer == 0 {
		tc.RetryTimer = c.Retry
	}
	if tc.TLSVersion == "" {
		tc.TLSVersion = c.TLSVersion
	}
	if tc.TLSMinVersion == "" {
		tc.TLSMinVersion = c.TLSMinVersion
	}
	if tc.TLSMaxVersion == "" {
		tc.TLSMaxVersion = c.TLSMaxVersion
	}
}

func (c *Config) TargetsList() []*collector.TargetConfig {
	targetsMap, err := c.GetTargets()
	if err != nil {
		return nil
	}
	targets := make([]*collector.TargetConfig, 0, len(targetsMap))
	for _, tc := range targetsMap {
		targets = append(targets, tc)
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Name < targets[j].Name
	})
	return targets
}
