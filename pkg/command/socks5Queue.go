package command

import "sync"

type Socks5Queue struct {
	mutex  sync.Mutex
	Queues map[string]map[string]chan string
}

var VarSocks5Queue = &Socks5Queue{Queues: make(map[string]map[string]chan string)}

func (q *Socks5Queue) Add(uid string, dataMd5, rawData string) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if q.Queues[uid] == nil {
		q.Queues[uid] = make(map[string]chan string)
	}
	if _, exists := q.Queues[uid][dataMd5]; !exists {
		q.Queues[uid][dataMd5] = make(chan string, 1)
	}
	select {
	case <-q.Queues[uid][dataMd5]: // 清空旧数据
	default: // 若通道为空，继续发送
	}

	// 发送最新的 pids 数据
	q.Queues[uid][dataMd5] <- rawData
}

func (q *Socks5Queue) GetOrCreateQueue(uid string, dataMd5 string) chan string {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if q.Queues[uid] == nil {
		q.Queues[uid] = make(map[string]chan string)
	}
	if _, exists := q.Queues[uid][dataMd5]; !exists {
		q.Queues[uid][dataMd5] = make(chan string, 1) // 带缓冲区的通道，防止阻塞
	}
	return q.Queues[uid][dataMd5]
}
