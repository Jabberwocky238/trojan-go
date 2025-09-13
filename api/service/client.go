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

type ClientAPI struct {
	auth   statistic.Authenticator
	apiKey string
	server *http.Server
}

// 密钥验证中间件
func (s *ClientAPI) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
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
func (s *ClientAPI) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := HTTPAPIResponse{
		Success: false,
		Message: message,
	}
	json.NewEncoder(w).Encode(response)
}

// 写入成功响应
func (s *ClientAPI) writeSuccessResponse(w http.ResponseWriter, data interface{}) {
	response := HTTPAPIResponse{
		Success: true,
		Data:    data,
	}
	json.NewEncoder(w).Encode(response)
}

// 获取流量统计
func (s *ClientAPI) getTraffic(w http.ResponseWriter, r *http.Request) {
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
func (s *ClientAPI) healthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.writeSuccessResponse(w, map[string]string{"status": "healthy"})
}

// 连接信息结构
type ConnectionInfo struct {
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

// 获取连接信息
func (s *ClientAPI) getConnections(w http.ResponseWriter, r *http.Request) {
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

	var connections []ConnectionInfo
	if ipCurrent > 0 {
		connection := ConnectionInfo{
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

func RunClientAPI(ctx context.Context, auth statistic.Authenticator) error {
	cfg := config.FromContext(ctx, Name).(*Config)
	if !cfg.API.Enabled {
		return nil
	}

	apiKey := cfg.API.APIKey
	if apiKey == "" {
		return common.NewError("API key is required")
	}

	service := &ClientAPI{
		auth:   auth,
		apiKey: apiKey,
	}

	// 设置路由
	mux := http.NewServeMux()

	// 应用认证中间件
	mux.HandleFunc("/api/traffic", service.authMiddleware(service.getTraffic))
	mux.HandleFunc("/api/connections", service.authMiddleware(service.getConnections))
	mux.HandleFunc("/api/health", service.authMiddleware(service.healthCheck))

	// 创建 HTTP 服务器
	httpServer := &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	service.server = httpServer

	// 解析地址
	addr, err := net.ResolveIPAddr("ip", cfg.API.APIHost)
	if err != nil {
		return common.NewError("api found invalid addr").Base(err)
	}

	service.server.Addr = (&net.TCPAddr{
		IP:   addr.IP,
		Port: cfg.API.APIPort,
		Zone: addr.Zone,
	}).String()

	log.Info("HTTP client API server is listening on", service.server.Addr)

	// 启动服务器
	errChan := make(chan error, 1)
	go func() {
		errChan <- service.server.ListenAndServe()
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Debug("HTTP client API server closed")
		service.server.Shutdown(context.Background())
		return nil
	}
}

func init() {
	api.RegisterHandler(trojan.Name+"_CLIENT", RunClientAPI)
}
