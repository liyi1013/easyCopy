package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const VERSION = "0.260212.4"

type ClipboardItem struct {
	ID      int    `json:"id"`
	Content string `json:"content"`
	Pinned  bool   `json:"pinned"`
}

type ClipboardManager struct {
	items  []ClipboardItem
	nextID int
	mu     sync.RWMutex
}

func NewClipboardManager() *ClipboardManager {
	return &ClipboardManager{
		items:  make([]ClipboardItem, 0),
		nextID: 1,
	}
}

func (cm *ClipboardManager) AddItem(content string) (ClipboardItem, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 检查是否已存在相同内容
	for i, item := range cm.items {
		if item.Content == content {
			// 如果已置顶，保持不动，直接返回
			if item.Pinned {
				return item, true
			}
			// 从原位置移除
			cm.items = append(cm.items[:i], cm.items[i+1:]...)
			// 插入到最前面（显示时会排在置顶项之后）
			cm.items = append([]ClipboardItem{item}, cm.items...)
			return item, true
		}
	}

	item := ClipboardItem{
		ID:      cm.nextID,
		Content: content,
		Pinned:  false,
	}
	cm.nextID++
	cm.items = append([]ClipboardItem{item}, cm.items...)
	return item, false
}

func (cm *ClipboardManager) GetItems() []ClipboardItem {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	pinnedItems := []ClipboardItem{}
	normalItems := []ClipboardItem{}

	for _, item := range cm.items {
		if item.Pinned {
			pinnedItems = append(pinnedItems, item)
		} else {
			normalItems = append(normalItems, item)
		}
	}

	return append(pinnedItems, normalItems...)
}

func (cm *ClipboardManager) DeleteItem(id int) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i, item := range cm.items {
		if item.ID == id {
			cm.items = append(cm.items[:i], cm.items[i+1:]...)
			return true
		}
	}
	return false
}

func (cm *ClipboardManager) TogglePin(id int) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i, item := range cm.items {
		if item.ID == id {
			cm.items[i].Pinned = !cm.items[i].Pinned
			return true
		}
	}
	return false
}

// getDataFilePath 返回与可执行文件同目录下的数据文件路径
func getDataFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		// 回退到当前工作目录
		return "clipboard_data.txt"
	}
	return filepath.Join(filepath.Dir(exe), "clipboard_data.txt")
}

// SaveToFile 将所有条目以 base64 编码写入文本文件
// 格式: 每行一条记录, "id|pinned|base64(content)"
func (cm *ClipboardManager) SaveToFile() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var lines []string
	for _, item := range cm.items {
		encoded := base64.StdEncoding.EncodeToString([]byte(item.Content))
		line := fmt.Sprintf("%d|%t|%s", item.ID, item.Pinned, encoded)
		lines = append(lines, line)
	}

	data := strings.Join(lines, "\n")
	return os.WriteFile(getDataFilePath(), []byte(data), 0644)
}

// LoadFromFile 从文本文件读取 base64 编码的条目并恢复列表
func (cm *ClipboardManager) LoadFromFile() error {
	data, err := os.ReadFile(getDataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在，跳过
		}
		return err
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	maxID := 0
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			log.Printf("跳过格式错误的行: %s", line)
			continue
		}

		id, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Printf("跳过 ID 解析失败的行: %s", line)
			continue
		}

		pinned, err := strconv.ParseBool(parts[1])
		if err != nil {
			log.Printf("跳过 pinned 解析失败的行: %s", line)
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			log.Printf("跳过 base64 解码失败的行: %s", line)
			continue
		}

		cm.items = append(cm.items, ClipboardItem{
			ID:      id,
			Content: string(decoded),
			Pinned:  pinned,
		})

		if id > maxID {
			maxID = id
		}
	}

	cm.nextID = maxID + 1
	log.Printf("从文件加载了 %d 条记录", len(cm.items))
	return nil
}

var clipboardManager = NewClipboardManager()

// generateSelfSignedCert 在内存中生成自签名 TLS 证书
func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Clipboard Manager"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}, nil
}

func main() {
	log.Printf("剪贴板管理器版本: %s\n", VERSION)
	// 启动时从文件加载历史数据
	if err := clipboardManager.LoadFromFile(); err != nil {
		log.Printf("加载历史数据失败: %v", err)
	}

	http.HandleFunc("/", serveHTML)
	http.HandleFunc("/api/items", handleItems)
	http.HandleFunc("/api/add", handleAdd)
	http.HandleFunc("/api/delete", handleDelete)
	http.HandleFunc("/api/toggle-pin", handleTogglePin)

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("生成自签名证书失败: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      ":8084",
		TLSConfig: tlsConfig,
	}

	log.Println("服务器启动在 https://localhost:8084")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func serveHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlContent))
}

func handleItems(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clipboardManager.GetItems())
}

func handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	item, existed := clipboardManager.AddItem(req.Content)
	clipboardManager.SaveToFile()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      item.ID,
		"content": item.Content,
		"pinned":  item.Pinned,
		"existed": existed,
	})
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	success := clipboardManager.DeleteItem(req.ID)
	if success {
		clipboardManager.SaveToFile()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": success})
}

func handleTogglePin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	success := clipboardManager.TogglePin(req.ID)
	if success {
		clipboardManager.SaveToFile()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": success})
}

const htmlContent = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>剪贴板管理器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            color: white; text-align: center; margin-bottom: 30px;
            font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .paste-box {
            background: white; border-radius: 12px; padding: 30px;
            margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .controls-row {
            display: flex; justify-content: space-between; align-items: center;
            flex-wrap: wrap; gap: 15px;
        }
        .paste-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 15px 40px; font-size: 18px;
            border-radius: 8px; cursor: pointer; transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        .paste-btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6); }
        .paste-btn:active { transform: translateY(0); }
        .auto-refresh-control {
            display: flex; align-items: center; gap: 10px;
            background: #f8f9fa; padding: 10px 20px; border-radius: 8px;
        }
        .switch {
            position: relative; display: inline-block;
            width: 50px; height: 24px;
        }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute; cursor: pointer; top: 0; left: 0;
            right: 0; bottom: 0; background-color: #ccc;
            transition: .4s; border-radius: 24px;
        }
        .slider:before {
            position: absolute; content: ""; height: 18px; width: 18px;
            left: 3px; bottom: 3px; background-color: white;
            transition: .4s; border-radius: 50%;
        }
        input:checked + .slider { background-color: #28a745; }
        input:checked + .slider:before { transform: translateX(26px); }
        .refresh-label {
            font-size: 14px; color: #333; font-weight: 500;
            display: flex; align-items: center; gap: 5px;
        }
        .refresh-indicator {
            display: none; color: #28a745; font-size: 12px;
            animation: pulse 2s infinite;
        }
        .refresh-indicator.active { display: inline; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .columns-wrapper {
            display: flex; gap: 20px; align-items: flex-start;
        }
        .column {
            flex: 1; min-width: 0;
        }
        .list-container {
            background: white; border-radius: 12px; padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .list-title { font-size: 1.3em; margin-bottom: 15px; color: #333; display: flex; align-items: center; gap: 8px; }
        .list-title .count-badge {
            font-size: 0.65em; background: #6c757d; color: white;
            padding: 2px 10px; border-radius: 12px; font-weight: normal;
        }
        .list-container.pinned-container .list-title .count-badge { background: #ffc107; color: #856404; }
        .clipboard-list { list-style: none; }
        .clipboard-item {
            background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px;
            padding: 15px; margin-bottom: 10px; display: flex;
            justify-content: space-between; align-items: center;
            transition: all 0.3s ease; position: relative;
        }
        .clipboard-item.pinned { background: #fff3cd; border-color: #ffc107; }
        .clipboard-item:hover { background: #e9ecef; transform: translateX(5px); }
        .clipboard-item.pinned:hover { background: #ffe69c; }
        .item-content {
            flex: 1; margin-right: 15px; word-break: break-all;
            color: #333; position: relative; transition: max-height 0.3s ease;
        }
        .item-content.truncated {
            max-height: 3em; overflow: hidden; cursor: pointer;
        }
        .item-content.truncated::after {
            content: '...'; position: absolute; bottom: 0; right: 0;
            background: inherit; padding-left: 5px;
        }
        .item-content.expanded { max-height: none; }
        .item-content.expanded::after { display: none; }
        .pin-badge {
            position: absolute; top: 5px; left: 5px;
            background: #ffc107; color: #856404;
            padding: 2px 8px; border-radius: 4px;
            font-size: 12px; font-weight: bold;
        }
        .button-group { display: flex; gap: 8px; }
        .action-btn {
            color: white; border: none; padding: 8px 16px;
            border-radius: 6px; cursor: pointer; transition: all 0.3s ease;
            white-space: nowrap; font-size: 14px;
        }
        .copy-btn { background: #28a745; }
        .copy-btn:hover { background: #218838; transform: scale(1.05); }
        .pin-btn { background: #ffc107; color: #856404; }
        .pin-btn:hover { background: #e0a800; transform: scale(1.05); }
        .pin-btn.pinned { background: #856404; color: white; }
        .delete-btn { background: #dc3545; }
        .delete-btn:hover { background: #c82333; transform: scale(1.05); }
        .action-btn:active { transform: scale(0.95); }
        .empty-message {
            text-align: center; color: #6c757d;
            padding: 40px; font-size: 1.1em;
        }
        .notification {
            position: fixed; top: 20px; right: 20px;
            background: #28a745; color: white; padding: 15px 25px;
            border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            opacity: 0; transform: translateY(-20px);
            transition: all 0.3s ease; z-index: 1000;
        }
        .notification.show { opacity: 1; transform: translateY(0); }
        .modal {
            display: none; position: fixed; top: 0; left: 0;
            width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5);
            z-index: 2000; justify-content: center; align-items: center;
        }
        .modal.show { display: flex; }
        .modal-content {
            background: white; padding: 30px; border-radius: 12px;
            max-width: 400px; text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .modal-title { font-size: 1.5em; margin-bottom: 15px; color: #333; }
        .modal-text { color: #666; margin-bottom: 25px; }
        .modal-buttons { display: flex; gap: 10px; justify-content: center; }
        .modal-btn {
            padding: 10px 30px; border: none; border-radius: 6px;
            cursor: pointer; font-size: 16px; transition: all 0.3s ease;
        }
        .modal-btn-confirm { background: #dc3545; color: white; }
        .modal-btn-confirm:hover { background: #c82333; }
        .modal-btn-cancel { background: #6c757d; color: white; }
        .modal-btn-cancel:hover { background: #5a6268; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 剪贴板管理器</h1>
        <div class="paste-box">
            <div class="controls-row">
                <button class="paste-btn" onclick="pasteFromClipboard()">📌 粘贴剪贴板内容</button>
                <div class="auto-refresh-control">
                    <span class="refresh-label">
                        🔄 自动刷新
                        <span class="refresh-indicator" id="refreshIndicator">●</span>
                    </span>
                    <label class="switch">
                        <input type="checkbox" id="autoRefreshToggle" onchange="toggleAutoRefresh()">
                        <span class="slider"></span>
                    </label>
                </div>
            </div>
        </div>
        <div class="columns-wrapper">
            <div class="column">
                <div class="list-container">
                    <h2 class="list-title">📄 历史记录 <span class="count-badge" id="normalCount">0</span></h2>
                    <ul id="normalList" class="clipboard-list">
                        <li class="empty-message">暂无内容</li>
                    </ul>
                </div>
            </div>
            <div class="column">
                <div class="list-container pinned-container">
                    <h2 class="list-title">📌 置顶内容 <span class="count-badge" id="pinnedCount">0</span></h2>
                    <ul id="pinnedList" class="clipboard-list">
                        <li class="empty-message">暂无置顶</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    <div id="notification" class="notification"></div>
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <h3 class="modal-title">确认删除</h3>
            <p class="modal-text">确定要删除这条记录吗？</p>
            <div class="modal-buttons">
                <button class="modal-btn modal-btn-confirm" onclick="confirmDelete()">确认删除</button>
                <button class="modal-btn modal-btn-cancel" onclick="cancelDelete()">取消</button>
            </div>
        </div>
    </div>
    <script>
        let deleteItemId = null;
        const TRUNCATE_LENGTH = 1000;
        const REFRESH_INTERVAL = 2000;
        let autoRefreshEnabled = false;
        let refreshTimer = null;
        
        function showNotification(m) {
            const n = document.getElementById('notification');
            n.textContent = m; n.classList.add('show');
            setTimeout(() => n.classList.remove('show'), 2000);
        }
        function showDeleteModal(id) {
            deleteItemId = id;
            document.getElementById('deleteModal').classList.add('show');
        }
        function cancelDelete() {
            deleteItemId = null;
            document.getElementById('deleteModal').classList.remove('show');
        }
        async function confirmDelete() {
            if (!deleteItemId) return;
            try {
                const r = await fetch('/api/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({id: deleteItemId})
                });
                showNotification(r.ok ? '✅ 已删除' : '❌ 删除失败');
                if (r.ok) loadItems();
            } catch(e) { showNotification('❌ 删除失败'); }
            cancelDelete();
        }
        async function pasteFromClipboard() {
            try {
                const t = await navigator.clipboard.readText();
                if (!t || !t.trim()) { showNotification('⚠️ 剪贴板为空'); return; }
                const r = await fetch('/api/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({content: t})
                });
                if (r.ok) {
                    const data = await r.json();
                    showNotification(data.existed ? '📌 已存在，已移至最前' : '✅ 已添加到列表');
                    loadItems();
                } else {
                    showNotification('❌ 添加失败');
                }
            } catch(e) { showNotification('❌ 无法读取剪贴板'); }
        }
        async function copyToClipboard(t) {
            try {
                await navigator.clipboard.writeText(t);
                showNotification('✅ 已复制到剪贴板');
            } catch(e) { showNotification('❌ 复制失败'); }
        }
        async function togglePin(id) {
            try {
                const r = await fetch('/api/toggle-pin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({id: id})
                });
                if (r.ok) loadItems(); else showNotification('❌ 操作失败');
            } catch(e) { showNotification('❌ 操作失败'); }
        }
        function toggleExpand(el) {
            el.classList.toggle('truncated');
            el.classList.toggle('expanded');
        }
        function toggleAutoRefresh() {
            autoRefreshEnabled = document.getElementById('autoRefreshToggle').checked;
            const indicator = document.getElementById('refreshIndicator');
            
            if (autoRefreshEnabled) {
                indicator.classList.add('active');
                startAutoRefresh();
            } else {
                indicator.classList.remove('active');
                stopAutoRefresh();
            }
        }
        function startAutoRefresh() {
            if (refreshTimer) clearInterval(refreshTimer);
            refreshTimer = setInterval(() => {
                loadItems(true);
            }, REFRESH_INTERVAL);
        }
        function stopAutoRefresh() {
            if (refreshTimer) {
                clearInterval(refreshTimer);
                refreshTimer = null;
            }
        }
        function createItemElement(item) {
            const li = document.createElement('li');
            li.className = 'clipboard-item' + (item.pinned ? ' pinned' : '');
            const contentDiv = document.createElement('div');
            contentDiv.className = 'item-content';
            if (item.content.length > TRUNCATE_LENGTH) {
                contentDiv.classList.add('truncated');
                contentDiv.onclick = () => toggleExpand(contentDiv);
            }
            contentDiv.textContent = item.content;
            const btnGroup = document.createElement('div');
            btnGroup.className = 'button-group';
            const copyBtn = document.createElement('button');
            copyBtn.className = 'action-btn copy-btn';
            copyBtn.textContent = '复制';
            copyBtn.onclick = () => copyToClipboard(item.content);
            const pinBtn = document.createElement('button');
            pinBtn.className = 'action-btn pin-btn' + (item.pinned ? ' pinned' : '');
            pinBtn.textContent = item.pinned ? '取消置顶' : '置顶';
            pinBtn.onclick = () => togglePin(item.id);
            const delBtn = document.createElement('button');
            delBtn.className = 'action-btn delete-btn';
            delBtn.textContent = '删除';
            delBtn.onclick = () => showDeleteModal(item.id);
            btnGroup.appendChild(copyBtn);
            btnGroup.appendChild(pinBtn);
            btnGroup.appendChild(delBtn);
            li.appendChild(contentDiv);
            li.appendChild(btnGroup);
            return li;
        }
        async function loadItems(silent = false) {
            try {
                const r = await fetch('/api/items');
                const items = await r.json();
                const normalList = document.getElementById('normalList');
                const pinnedList = document.getElementById('pinnedList');
                const normalItems = (items || []).filter(i => !i.pinned);
                const pinnedItems = (items || []).filter(i => i.pinned);
                document.getElementById('normalCount').textContent = normalItems.length;
                document.getElementById('pinnedCount').textContent = pinnedItems.length;
                if (normalItems.length === 0) {
                    normalList.innerHTML = '<li class="empty-message">暂无内容</li>';
                } else {
                    normalList.innerHTML = '';
                    normalItems.forEach(item => normalList.appendChild(createItemElement(item)));
                }
                if (pinnedItems.length === 0) {
                    pinnedList.innerHTML = '<li class="empty-message">暂无置顶</li>';
                } else {
                    pinnedList.innerHTML = '';
                    pinnedItems.forEach(item => pinnedList.appendChild(createItemElement(item)));
                }
            } catch(e) { console.error('加载失败:', e); }
        }
        loadItems();
    </script>
</body>
</html>`
