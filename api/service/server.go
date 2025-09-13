package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/p4gefau1t/trojan-go/api"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/statistic"
	"github.com/p4gefau1t/trojan-go/tunnel/trojan"
)

// HTTP API 响应结构
type HTTPAPIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// 用户信息结构
type HTTPUserInfo struct {
	Hash            string `json:"hash"`
	Password        string `json:"password,omitempty"`
	UploadTraffic   uint64 `json:"upload_traffic"`
	DownloadTraffic uint64 `json:"download_traffic"`
	UploadSpeed     uint64 `json:"upload_speed"`
	DownloadSpeed   uint64 `json:"download_speed"`
	UploadLimit     int    `json:"upload_limit"`
	DownloadLimit   int    `json:"download_limit"`
	IPLimit         int    `json:"ip_limit"`
	IPCurrent       int    `json:"ip_current"`
}

// 用户操作请求结构
type HTTPUserOperationRequest struct {
	Hash            string `json:"hash"`
	Password        string `json:"password,omitempty"`
	UploadLimit     int    `json:"upload_limit,omitempty"`
	DownloadLimit   int    `json:"download_limit,omitempty"`
	IPLimit         int    `json:"ip_limit,omitempty"`
	UploadTraffic   uint64 `json:"upload_traffic,omitempty"`
	DownloadTraffic uint64 `json:"download_traffic,omitempty"`
}

type ServerAPI struct {
	auth   statistic.Authenticator
	apiKey string
	server *http.Server
}

// 密钥验证中间件
func (s *ServerAPI) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 从请求头获取 API 密钥
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			s.writeErrorResponse(w, "Missing API key", http.StatusUnauthorized)
			return
		}

		// 验证 API 密钥
		if apiKey != s.apiKey {
			s.writeErrorResponse(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		// 设置响应头
		w.Header().Set("Content-Type", "application/json")
		next(w, r)
	}
}

// 写入错误响应
func (s *ServerAPI) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := HTTPAPIResponse{
		Success: false,
		Message: message,
	}
	json.NewEncoder(w).Encode(response)
}

// 写入成功响应
func (s *ServerAPI) writeSuccessResponse(w http.ResponseWriter, data interface{}) {
	response := HTTPAPIResponse{
		Success: true,
		Data:    data,
	}
	json.NewEncoder(w).Encode(response)
}

// 获取所有用户列表
func (s *ServerAPI) listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users := s.auth.ListUsers()
	var userList []HTTPUserInfo

	for _, user := range users {
		downloadTraffic, uploadTraffic := user.GetTraffic()
		downloadSpeed, uploadSpeed := user.GetSpeed()
		downloadSpeedLimit, uploadSpeedLimit := user.GetSpeedLimit()
		ipLimit := user.GetIPLimit()
		ipCurrent := user.GetIP()

		userInfo := HTTPUserInfo{
			Hash:            user.Hash(),
			UploadTraffic:   uploadTraffic,
			DownloadTraffic: downloadTraffic,
			UploadSpeed:     uploadSpeed,
			DownloadSpeed:   downloadSpeed,
			UploadLimit:     uploadSpeedLimit,
			DownloadLimit:   downloadSpeedLimit,
			IPLimit:         ipLimit,
			IPCurrent:       ipCurrent,
		}
		userList = append(userList, userInfo)
	}

	s.writeSuccessResponse(w, userList)
}

// 获取指定用户信息
func (s *ServerAPI) getUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hash := r.URL.Query().Get("hash")
	if hash == "" {
		s.writeErrorResponse(w, "Missing hash parameter", http.StatusBadRequest)
		return
	}

	valid, user := s.auth.AuthUser(hash)
	if !valid {
		s.writeErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	downloadTraffic, uploadTraffic := user.GetTraffic()
	downloadSpeed, uploadSpeed := user.GetSpeed()
	downloadSpeedLimit, uploadSpeedLimit := user.GetSpeedLimit()
	ipLimit := user.GetIPLimit()
	ipCurrent := user.GetIP()

	userInfo := HTTPUserInfo{
		Hash:            user.Hash(),
		UploadTraffic:   uploadTraffic,
		DownloadTraffic: downloadTraffic,
		UploadSpeed:     uploadSpeed,
		DownloadSpeed:   downloadSpeed,
		UploadLimit:     uploadSpeedLimit,
		DownloadLimit:   downloadSpeedLimit,
		IPLimit:         ipLimit,
		IPCurrent:       ipCurrent,
	}

	s.writeSuccessResponse(w, userInfo)
}

// 添加用户
func (s *ServerAPI) addUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HTTPUserOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Hash == "" && req.Password == "" {
		s.writeErrorResponse(w, "Hash or password is required", http.StatusBadRequest)
		return
	}

	// 如果没有提供 hash，从密码生成
	if req.Hash == "" {
		req.Hash = common.SHA224String(req.Password)
	}

	// 添加用户
	if err := s.auth.AddUser(req.Hash); err != nil {
		s.writeErrorResponse(w, "Failed to add user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 如果提供了限制参数，设置用户限制
	if req.UploadLimit > 0 || req.DownloadLimit > 0 || req.IPLimit > 0 {
		valid, user := s.auth.AuthUser(req.Hash)
		if valid {
			if req.UploadLimit > 0 || req.DownloadLimit > 0 {
				user.SetSpeedLimit(req.DownloadLimit, req.UploadLimit)
			}
			if req.IPLimit > 0 {
				user.SetIPLimit(req.IPLimit)
			}
			if req.UploadTraffic > 0 || req.DownloadTraffic > 0 {
				user.SetTraffic(req.DownloadTraffic, req.UploadTraffic)
			}
		}
	}

	s.writeSuccessResponse(w, map[string]string{"message": "User added successfully"})
}

// 删除用户
func (s *ServerAPI) deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hash := r.URL.Query().Get("hash")
	if hash == "" {
		s.writeErrorResponse(w, "Missing hash parameter", http.StatusBadRequest)
		return
	}

	if err := s.auth.DelUser(hash); err != nil {
		s.writeErrorResponse(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.writeSuccessResponse(w, map[string]string{"message": "User deleted successfully"})
}

// 修改用户
func (s *ServerAPI) modifyUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HTTPUserOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Hash == "" {
		s.writeErrorResponse(w, "Hash is required", http.StatusBadRequest)
		return
	}

	valid, user := s.auth.AuthUser(req.Hash)
	if !valid {
		s.writeErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	// 更新用户限制
	if req.UploadLimit > 0 || req.DownloadLimit > 0 {
		user.SetSpeedLimit(req.DownloadLimit, req.UploadLimit)
	}
	if req.IPLimit > 0 {
		user.SetIPLimit(req.IPLimit)
	}
	if req.UploadTraffic > 0 || req.DownloadTraffic > 0 {
		user.SetTraffic(req.DownloadTraffic, req.UploadTraffic)
	}

	s.writeSuccessResponse(w, map[string]string{"message": "User modified successfully"})
}

// 获取流量统计
func (s *ServerAPI) getTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hash := r.URL.Query().Get("hash")
	if hash == "" {
		s.writeErrorResponse(w, "Missing hash parameter", http.StatusBadRequest)
		return
	}

	valid, user := s.auth.AuthUser(hash)
	if !valid {
		s.writeErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	downloadTraffic, uploadTraffic := user.GetTraffic()
	downloadSpeed, uploadSpeed := user.GetSpeed()

	trafficData := map[string]interface{}{
		"upload_traffic":   uploadTraffic,
		"download_traffic": downloadTraffic,
		"upload_speed":     uploadSpeed,
		"download_speed":   downloadSpeed,
	}

	s.writeSuccessResponse(w, trafficData)
}

// 健康检查
func (s *ServerAPI) healthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.writeSuccessResponse(w, map[string]string{"status": "healthy"})
}

// 连接信息结构
type HTTPConnectionInfo struct {
	Hash            string `json:"hash"`
	IP              string `json:"ip"`
	Port            int    `json:"port"`
	UploadSpeed     uint64 `json:"upload_speed"`
	DownloadSpeed   uint64 `json:"download_speed"`
	UploadTraffic   uint64 `json:"upload_traffic"`
	DownloadTraffic uint64 `json:"download_traffic"`
	ConnectedAt     int64  `json:"connected_at"`
	LastActivity    int64  `json:"last_activity"`
}

// 获取所有连接信息
func (s *ServerAPI) getConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users := s.auth.ListUsers()
	var connections []HTTPConnectionInfo

	for _, user := range users {
		// 获取用户的基本信息
		downloadTraffic, uploadTraffic := user.GetTraffic()
		downloadSpeed, uploadSpeed := user.GetSpeed()
		ipCurrent := user.GetIP()

		// 这里我们模拟一些连接信息
		// 在实际实现中，您可能需要从连接管理器获取真实的连接信息
		if ipCurrent > 0 {
			// 模拟连接信息
			connection := HTTPConnectionInfo{
				Hash:            user.Hash(),
				IP:              "127.0.0.1", // 这里应该从实际的连接信息中获取
				Port:            0,           // 这里应该从实际的连接信息中获取
				UploadSpeed:     uploadSpeed,
				DownloadSpeed:   downloadSpeed,
				UploadTraffic:   uploadTraffic,
				DownloadTraffic: downloadTraffic,
				ConnectedAt:     time.Now().Unix() - 3600, // 模拟1小时前连接
				LastActivity:    time.Now().Unix(),
			}
			connections = append(connections, connection)
		}
	}

	s.writeSuccessResponse(w, connections)
}

// 获取指定用户的连接信息
func (s *ServerAPI) getUserConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hash := r.URL.Query().Get("hash")
	if hash == "" {
		s.writeErrorResponse(w, "Missing hash parameter", http.StatusBadRequest)
		return
	}

	valid, user := s.auth.AuthUser(hash)
	if !valid {
		s.writeErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	downloadTraffic, uploadTraffic := user.GetTraffic()
	downloadSpeed, uploadSpeed := user.GetSpeed()
	ipCurrent := user.GetIP()

	var connections []HTTPConnectionInfo
	if ipCurrent > 0 {
		connection := HTTPConnectionInfo{
			Hash:            user.Hash(),
			IP:              "127.0.0.1", // 这里应该从实际的连接信息中获取
			Port:            0,           // 这里应该从实际的连接信息中获取
			UploadSpeed:     uploadSpeed,
			DownloadSpeed:   downloadSpeed,
			UploadTraffic:   uploadTraffic,
			DownloadTraffic: downloadTraffic,
			ConnectedAt:     time.Now().Unix() - 3600, // 模拟1小时前连接
			LastActivity:    time.Now().Unix(),
		}
		connections = append(connections, connection)
	}

	s.writeSuccessResponse(w, connections)
}

// 创建 HTTP 服务器
func newHTTPServer(cfg *Config, auth statistic.Authenticator) (*ServerAPI, error) {
	apiKey := cfg.API.APIKey
	if apiKey == "" {
		return nil, common.NewError("API key is required")
	}

	server := &ServerAPI{
		auth:   auth,
		apiKey: apiKey,
	}

	// 设置路由
	mux := http.NewServeMux()

	// 应用认证中间件
	mux.HandleFunc("/api/users", server.authMiddleware(server.listUsers))
	mux.HandleFunc("/api/user", server.authMiddleware(server.getUser))
	mux.HandleFunc("/api/user/add", server.authMiddleware(server.addUser))
	mux.HandleFunc("/api/user/delete", server.authMiddleware(server.deleteUser))
	mux.HandleFunc("/api/user/modify", server.authMiddleware(server.modifyUser))
	mux.HandleFunc("/api/traffic", server.authMiddleware(server.getTraffic))
	mux.HandleFunc("/api/connections", server.authMiddleware(server.getConnections))
	mux.HandleFunc("/api/connections/user", server.authMiddleware(server.getUserConnections))
	mux.HandleFunc("/api/health", server.authMiddleware(server.healthCheck))

	// 创建 HTTP 服务器
	httpServer := &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	server.server = httpServer
	return server, nil
}

func RunServerAPI(ctx context.Context, auth statistic.Authenticator) error {
	cfg := config.FromContext(ctx, Name).(*Config)
	if !cfg.API.Enabled {
		return nil
	}

	server, err := newHTTPServer(cfg, auth)
	if err != nil {
		return err
	}

	// 解析地址
	addr, err := net.ResolveIPAddr("ip", cfg.API.APIHost)
	if err != nil {
		return common.NewError("api found invalid addr").Base(err)
	}

	server.server.Addr = (&net.TCPAddr{
		IP:   addr.IP,
		Port: cfg.API.APIPort,
		Zone: addr.Zone,
	}).String()

	log.Info("HTTP API server is listening on", server.server.Addr)

	// 启动服务器
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.server.ListenAndServe()
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Debug("HTTP API server closed")
		server.server.Shutdown(context.Background())
		return nil
	}
}

func init() {
	api.RegisterHandler(trojan.Name+"_SERVER", RunServerAPI)
}
