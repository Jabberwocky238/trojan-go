package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/statistic"
	"github.com/p4gefau1t/trojan-go/statistic/memory"
)

// HTTP 认证请求结构
type AuthRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   int    `json:"tx"`
}

// HTTP 认证响应结构
type AuthResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// HTTPUser 结构，继承memory.User的功能
type HTTPUser struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent      uint64
	recv      uint64
	lastSent  uint64
	lastRecv  uint64
	sendSpeed uint64
	recvSpeed uint64

	hash        string
	ipTable     sync.Map
	ipNum       int32
	maxIPNum    int
	limiterLock sync.RWMutex
	sendLimiter *rate.Limiter
	recvLimiter *rate.Limiter
	ctx         context.Context
	cancel      context.CancelFunc
}

// HTTP 认证器结构
type Authenticator struct {
	*memory.Authenticator
	apiURL     string
	timeout    time.Duration
	httpClient *http.Client
	ctx        context.Context
}

// HTTPUser 实现 statistic.User 接口
func (u *HTTPUser) Close() error {
	u.ResetTraffic()
	u.cancel()
	return nil
}

func (u *HTTPUser) AddIP(ip string) bool {
	if u.maxIPNum <= 0 {
		return true
	}
	_, found := u.ipTable.Load(ip)
	if found {
		return true
	}
	if int(u.ipNum)+1 > u.maxIPNum {
		return false
	}
	u.ipTable.Store(ip, true)
	atomic.AddInt32(&u.ipNum, 1)
	return true
}

func (u *HTTPUser) DelIP(ip string) bool {
	if u.maxIPNum <= 0 {
		return true
	}
	_, found := u.ipTable.Load(ip)
	if !found {
		return false
	}
	u.ipTable.Delete(ip)
	atomic.AddInt32(&u.ipNum, -1)
	return true
}

func (u *HTTPUser) GetIP() int {
	return int(u.ipNum)
}

func (u *HTTPUser) SetIPLimit(n int) {
	u.maxIPNum = n
}

func (u *HTTPUser) GetIPLimit() int {
	return u.maxIPNum
}

func (u *HTTPUser) AddTraffic(sent, recv int) {
	u.limiterLock.RLock()
	defer u.limiterLock.RUnlock()

	if u.sendLimiter != nil && sent >= 0 {
		u.sendLimiter.WaitN(u.ctx, sent)
	} else if u.recvLimiter != nil && recv >= 0 {
		u.recvLimiter.WaitN(u.ctx, recv)
	}
	atomic.AddUint64(&u.sent, uint64(sent))
	atomic.AddUint64(&u.recv, uint64(recv))
}

func (u *HTTPUser) SetSpeedLimit(send, recv int) {
	u.limiterLock.Lock()
	defer u.limiterLock.Unlock()

	if send <= 0 {
		u.sendLimiter = nil
	} else {
		u.sendLimiter = rate.NewLimiter(rate.Limit(send), send*2)
	}
	if recv <= 0 {
		u.recvLimiter = nil
	} else {
		u.recvLimiter = rate.NewLimiter(rate.Limit(recv), recv*2)
	}
}

func (u *HTTPUser) GetSpeedLimit() (send, recv int) {
	u.limiterLock.RLock()
	defer u.limiterLock.RUnlock()

	if u.sendLimiter != nil {
		send = int(u.sendLimiter.Limit())
	}
	if u.recvLimiter != nil {
		recv = int(u.recvLimiter.Limit())
	}
	return
}

func (u *HTTPUser) Hash() string {
	return u.hash
}

func (u *HTTPUser) SetTraffic(send, recv uint64) {
	atomic.StoreUint64(&u.sent, send)
	atomic.StoreUint64(&u.recv, recv)
}

func (u *HTTPUser) GetTraffic() (uint64, uint64) {
	return atomic.LoadUint64(&u.sent), atomic.LoadUint64(&u.recv)
}

func (u *HTTPUser) ResetTraffic() (uint64, uint64) {
	sent := atomic.SwapUint64(&u.sent, 0)
	recv := atomic.SwapUint64(&u.recv, 0)
	atomic.StoreUint64(&u.lastSent, 0)
	atomic.StoreUint64(&u.lastRecv, 0)
	return sent, recv
}

func (u *HTTPUser) SpeedUpdater() {
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			sent, recv := u.GetTraffic()
			atomic.StoreUint64(&u.sendSpeed, sent-u.lastSent)
			atomic.StoreUint64(&u.recvSpeed, recv-u.lastRecv)
			atomic.StoreUint64(&u.lastSent, sent)
			atomic.StoreUint64(&u.lastRecv, recv)
		}
	}
}

func (u *HTTPUser) GetSpeed() (uint64, uint64) {
	return atomic.LoadUint64(&u.sendSpeed), atomic.LoadUint64(&u.recvSpeed)
}

// 创建 HTTP 客户端
func (a *Authenticator) createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: a.timeout,
	}
}

// 发送 HTTP 认证请求
func (a *Authenticator) sendAuthRequest(ip, password string) (bool, error) {
	authReq := AuthRequest{
		Addr: ip,
		Auth: password,
		Tx:   0,
	}

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return false, common.NewError("failed to marshal auth request").Base(err)
	}

	// 打印请求日志
	log.Infof("发送HTTP认证请求到 %s，IP: %s", a.apiURL, ip)
	log.Debugf("HTTP认证请求数据: %s", string(jsonData))

	req, err := http.NewRequestWithContext(a.ctx, "POST", a.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, common.NewError("failed to create HTTP request").Base(err)
	}

	req.Header.Set("Content-Type", "application/json")

	// 发送HTTP请求
	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Errorf("HTTP认证请求失败: %v", err)
		return false, common.NewError("HTTP auth request failed").Base(err)
	}
	defer resp.Body.Close()

	// 打印响应状态码
	log.Infof("HTTP认证响应状态码: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		log.Errorf("HTTP认证返回错误状态码: %d", resp.StatusCode)
		return false, common.NewError(fmt.Sprintf("HTTP auth returned status %d", resp.StatusCode))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		log.Errorf("解析HTTP认证响应失败: %v", err)
		return false, common.NewError("failed to decode auth response").Base(err)
	}

	// 打印响应内容
	log.Infof("HTTP认证响应: ok=%t", authResp.OK)
	if authResp.Error != "" {
		log.Errorf("HTTP认证错误: %s", authResp.Error)
		return false, common.NewError("auth error: " + authResp.Error)
	}

	if authResp.OK {
		log.Infof("HTTP认证成功，IP: %s", ip)
	} else {
		log.Warnf("HTTP认证失败，IP: %s", ip)
	}

	return authResp.OK, nil
}

// 重写AuthUser方法，添加HTTP认证逻辑
func (a *Authenticator) AuthUser(hash string) (bool, statistic.User) {
	// 首先检查内存中是否有用户
	valid, user := a.Authenticator.AuthUser(hash)
	if valid {
		return true, user
	}
	return false, nil
}

// 重写AddUser方法，创建HTTPUser而不是memory.User
func (a *Authenticator) AddUser(hash string) error {
	// 检查用户是否已存在
	valid, _ := a.Authenticator.AuthUser(hash)
	if valid {
		return common.NewError("user " + hash + " already exists")
	}

	// 将用户添加到内存认证器中
	return a.Authenticator.AddUser(hash)
}

// 验证用户连接（主要认证方法）
func (a *Authenticator) ValidateConnection(ip, password string) (bool, error) {
	log.Infof("开始验证用户连接，IP: %s", ip)

	// 发送 HTTP 认证请求
	valid, err := a.sendAuthRequest(ip, password)
	if err != nil {
		log.Errorf("HTTP认证请求出错，IP: %s, 错误: %v", ip, err)
		return false, err
	}

	// 如果认证通过，将用户添加到缓存
	if valid {
		hash := common.SHA224String(password)
		log.Debugf("认证成功，用户哈希: %s", hash)

		// 检查用户是否已存在，如果不存在则添加
		exists, _ := a.AuthUser(hash)
		if !exists {
			if err := a.AddUser(hash); err != nil {
				log.Errorf("添加用户到缓存失败: %v", err)
			} else {
				log.Infof("用户已添加到缓存，哈希: %s", hash)
			}
		} else {
			log.Debugf("用户已存在于缓存中，哈希: %s", hash)
		}
	} else {
		log.Warnf("认证失败，IP: %s", ip)
	}

	return valid, nil
}

// 创建新的 HTTP 认证器
func NewAuthenticator(ctx context.Context) (statistic.Authenticator, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	if !cfg.HTTP.Enabled {
		return nil, common.NewError("HTTP authenticator is not enabled")
	}

	if cfg.HTTP.APIURL == "" {
		return nil, common.NewError("HTTP API URL is required")
	}

	timeout := time.Duration(cfg.HTTP.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	// 创建内存认证器作为基础
	memoryAuth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		return nil, err
	}

	auth := &Authenticator{
		Authenticator: memoryAuth.(*memory.Authenticator),
		apiURL:        cfg.HTTP.APIURL,
		timeout:       timeout,
		ctx:           ctx,
	}

	auth.httpClient = auth.createHTTPClient()

	log.Infof("HTTP认证器已创建，API URL: %s", auth.apiURL)
	log.Debug("HTTP authenticator created")
	return auth, nil
}

func init() {
	statistic.RegisterAuthenticatorCreator(Name, NewAuthenticator)
}
