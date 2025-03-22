package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ConnectionStatus represents the status of the WebSocket connection.
type ConnectionStatus string

const (
	StatusClosed     ConnectionStatus = "CLOSED"
	StatusConnecting ConnectionStatus = "CONNECTING"
	StatusOpen       ConnectionStatus = "OPEN"
)

// ChannelStatus represents the status of a channel.
type ChannelStatus string

const (
	ChannelStatusClosed  ChannelStatus = "CLOSED"
	ChannelStatusJoining ChannelStatus = "JOINING"
	ChannelStatusJoined  ChannelStatus = "JOINED"
	ChannelStatusLeaving ChannelStatus = "LEAVING"
	ChannelStatusError   ChannelStatus = "ERROR"
)

type GetAccessToken func() (string, error)

type ClientOptions struct {
	ConnectionTimeout  time.Duration
	HeartbeatInterval  time.Duration
	Headers            map[string]string
	Params             map[string]string
	AccessToken        GetAccessToken
	Transport          WebSocketTransport
	Logger             Logger
	ReconnectAfterMs   func(tries int) time.Duration
	HeartbeatTimeoutMs int
}

type ChannelOptions struct {
	Config               map[string]interface{}
	Params               map[string]string
	RetryAfterMs         func(tries int) time.Duration
	RetryJoinUntil       time.Duration
	BroadcastEndpointURL string
	PresenceEndpointURL  string
}

type Message struct {
	Event   string                 `json:"event"`
	Topic   string                 `json:"topic"`
	Payload map[string]interface{} `json:"payload"`
	Ref     string                 `json:"ref,omitempty"`
	JoinRef string                 `json:"join_ref,omitempty"`
}

type PresenceState map[string]map[string]interface{}

type PresenceDiff struct {
	Joins  map[string]map[string]interface{} `json:"joins"`
	Leaves map[string]map[string]interface{} `json:"leaves"`
}

type BroadcastParams struct {
	Type    string      `json:"type"`
	Event   string      `json:"event"`
	Payload interface{} `json:"payload"`
}

type SubscribeParams struct {
	PostgresChanges []PostgresChange `json:"postgres_changes,omitempty"`
	Broadcast       BroadcastConfig  `json:"broadcast,omitempty"`
	Presence        PresenceConfig   `json:"presence,omitempty"`
}

type PostgresChange struct {
	Event   string   `json:"event"`
	Schema  string   `json:"schema"`
	Table   string   `json:"table"`
	Filter  string   `json:"filter,omitempty"`
	Columns []string `json:"columns,omitempty"`
}

type BroadcastConfig struct {
	Self   bool     `json:"self"`
	Ack    bool     `json:"ack"`
	Events []string `json:"events"`
}

type PresenceConfig struct {
	Key string `json:"key"`
}

type Push struct {
	Event   string
	Topic   string
	Payload map[string]interface{}
	Ref     string
	JoinRef string
}

type WebSocketTransport interface {
	Connect(url string, params map[string]string, headers map[string]string) error
	Disconnect(code int, reason string) error
	Send(data []byte) error
	OnOpen(callback func()) error
	OnClose(callback func(code int, reason string)) error
	OnError(callback func(err error)) error
	OnMessage(callback func(data []byte)) error
}

type Logger interface {
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
}

type EventHandler func(message Message)

type PusherEvent struct {
	Channel string      `json:"channel"`
	Event   string      `json:"event"`
	Data    interface{} `json:"data"`
}

type RealtimePostgresChangesPayload struct {
	Commit  string                 `json:"commit_timestamp"`
	Errors  []string               `json:"errors"`
	Schema  string                 `json:"schema"`
	Table   string                 `json:"table"`
	Type    string                 `json:"type"`
	Old     map[string]interface{} `json:"old,omitempty"`
	New     map[string]interface{} `json:"new,omitempty"`
	Columns []ColumnData           `json:"columns,omitempty"`
}

type ColumnData struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	DataType string `json:"data_type"`
}

type DefaultLogger struct{}

func (l *DefaultLogger) Debug(args ...interface{}) {
	fmt.Println("DEBUG:", args)
}

func (l *DefaultLogger) Info(args ...interface{}) {
	fmt.Println("INFO:", args)
}

func (l *DefaultLogger) Warn(args ...interface{}) {
	fmt.Println("WARN:", args)
}

func (l *DefaultLogger) Error(args ...interface{}) {
	fmt.Println("ERROR:", args)
}

type GorillaWebSocketTransport struct {
	conn        *websocket.Conn
	onOpen      func()
	onClose     func(code int, reason string)
	onError     func(err error)
	onMessage   func(data []byte)
	mu          sync.Mutex
	initialized bool
	done        chan struct{}
}

func NewGorillaWebSocketTransport() *GorillaWebSocketTransport {
	return &GorillaWebSocketTransport{
		done: make(chan struct{}),
	}
}

func (t *GorillaWebSocketTransport) Connect(wsURL string, params map[string]string, headers map[string]string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		return errors.New("connection already established")
	}

	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	header := http.Header{}
	for k, v := range headers {
		header.Set(k, v)
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	t.conn = conn
	t.initialized = true
	t.done = make(chan struct{})

	go t.readPump()

	if t.onOpen != nil {
		t.onOpen()
	}

	return nil
}

func (t *GorillaWebSocketTransport) Disconnect(code int, reason string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return errors.New("not connected")
	}

	close(t.done)

	err := t.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(time.Second),
	)
	if err != nil {
		t.conn.Close()
		t.conn = nil
		t.initialized = false
		return fmt.Errorf("failed to send close message: %w", err)
	}

	err = t.conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	t.conn = nil
	t.initialized = false
	return nil
}

func (t *GorillaWebSocketTransport) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return errors.New("not connected")
	}

	return t.conn.WriteMessage(websocket.TextMessage, data)
}

func (t *GorillaWebSocketTransport) OnOpen(callback func()) error {
	t.onOpen = callback
	if t.initialized && t.conn != nil && callback != nil {
		callback()
	}
	return nil
}

func (t *GorillaWebSocketTransport) OnClose(callback func(code int, reason string)) error {
	t.onClose = callback
	return nil
}

func (t *GorillaWebSocketTransport) OnError(callback func(err error)) error {
	t.onError = callback
	return nil
}

func (t *GorillaWebSocketTransport) OnMessage(callback func(data []byte)) error {
	t.onMessage = callback
	return nil
}

func (t *GorillaWebSocketTransport) readPump() {
	defer func() {
		if t.onClose != nil {
			t.onClose(websocket.CloseNormalClosure, "connection closed")
		}
	}()

	for {
		select {
		case <-t.done:
			return
		default:
			_, message, err := t.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(
					err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseAbnormalClosure,
				) && t.onError != nil {
					t.onError(err)
				}
				return
			}

			if t.onMessage != nil {
				t.onMessage(message)
			}
		}
	}
}

type Client struct {
	url              string
	options          *ClientOptions
	channels         map[string]*Channel
	channelsMu       sync.RWMutex
	status           ConnectionStatus
	accessToken      string
	transport        WebSocketTransport
	ref              int
	refMu            sync.Mutex
	heartbeatTimer   *time.Timer
	reconnectTimer   *time.Timer
	reconnectTries   int
	callbacksMu      sync.RWMutex
	callbacks        map[string]func(Message)
	heartbeatsMu     sync.Mutex
	pendingHeartbeat string
	closeMu          sync.Mutex
	closed           bool
}

func NewClient(url string, options *ClientOptions) *Client {
	if options == nil {
		options = &ClientOptions{
			ConnectionTimeout:  10 * time.Second,
			HeartbeatInterval:  30 * time.Second,
			Headers:            make(map[string]string),
			Params:             make(map[string]string),
			HeartbeatTimeoutMs: 10000,
		}
	}

	if options.ReconnectAfterMs == nil {
		options.ReconnectAfterMs = func(tries int) time.Duration {
			return time.Duration(min(max(tries, 1), 10)) * time.Second
		}
	}

	if options.Logger == nil {
		options.Logger = &DefaultLogger{}
	}

	var transport WebSocketTransport
	if options.Transport != nil {
		transport = options.Transport
	} else {
		transport = NewGorillaWebSocketTransport()
	}

	client := &Client{
		url:       url,
		options:   options,
		channels:  make(map[string]*Channel),
		status:    StatusClosed,
		transport: transport,
		ref:       0,
		callbacks: make(map[string]func(Message)),
	}

	transport.OnOpen(func() {
		client.onConnectionOpen()
	})

	transport.OnClose(func(code int, reason string) {
		client.onConnectionClose(code, reason)
	})

	transport.OnError(func(err error) {
		client.options.Logger.Error("Transport error:", err)
		client.onConnectionError(err)
	})

	transport.OnMessage(func(data []byte) {
		client.onConnectionMessage(data)
	})

	return client
}

func NewChannel(name string, client *Client, options *ChannelOptions) *Channel {
	if options == nil {
		options = &ChannelOptions{
			Config: make(map[string]interface{}),
		}
	}

	return &Channel{
		name:            name,
		client:          client,
		options:         options,
		status:          ChannelStatusClosed,
		handlers:        make(map[string][]EventHandler),
		presenceState:   make(PresenceState),
		pushBuffer:      make([]*Push, 0),
		subscribeParams: &SubscribeParams{},
	}
}

func (c *Client) Channel(name string, opts *ChannelOptions) *Channel {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()

	if channel, ok := c.channels[name]; ok {
		return channel
	}

	channel := NewChannel(name, c, opts)
	c.channels[name] = channel
	return channel
}

func (c *Client) GetChannels() []*Channel {
	c.channelsMu.RLock()
	defer c.channelsMu.RUnlock()
	channels := make([]*Channel, 0, len(c.channels))
	for _, channel := range c.channels {
		channels = append(channels, channel)
	}
	return channels
}

func (c *Client) RemoveChannel(channel *Channel) (string, error) {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()

	if _, ok := c.channels[channel.name]; !ok {
		return "", errors.New("channel not found")
	}

	if channel.status == ChannelStatusJoined {
		if err := channel.Unsubscribe(); err != nil {
			return "", err
		}
	}

	delete(c.channels, channel.name)
	return "ok", nil
}

func (c *Client) RemoveAllChannels() ([]string, error) {
	channels := c.GetChannels()
	results := make([]string, len(channels))

	for i, channel := range channels {
		result, err := c.RemoveChannel(channel)
		if err != nil {
			results[i] = "error"
		} else {
			results[i] = result
		}
	}

	return results, nil
}

func (c *Client) SetAuth(token string) {
	c.accessToken = token
}

func (c *Client) GetAccessToken() (string, error) {
	if c.accessToken != "" {
		return c.accessToken, nil
	}

	if c.options.AccessToken != nil {
		return c.options.AccessToken()
	}

	return "", nil
}

func (c *Client) Connect() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return errors.New("client has been closed")
	}
	c.closeMu.Unlock()

	if c.status == StatusOpen {
		return nil
	}

	c.status = StatusConnecting

	token, err := c.GetAccessToken()
	if err != nil {
		c.status = StatusClosed
		return fmt.Errorf("failed to get access token: %w", err)
	}

	params := make(map[string]string)
	for k, v := range c.options.Params {
		params[k] = v
	}
	if token != "" {
		params["token"] = token
	}

	err = c.transport.Connect(c.url, params, c.options.Headers)
	if err != nil {
		c.status = StatusClosed
		return fmt.Errorf("failed to connect: %w", err)
	}

	return nil
}

func (c *Client) connect() error {
	return c.Connect()
}

func (c *Client) Disconnect() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	c.closed = true

	if c.heartbeatTimer != nil {
		c.heartbeatTimer.Stop()
		c.heartbeatTimer = nil
	}

	if c.reconnectTimer != nil {
		c.reconnectTimer.Stop()
		c.reconnectTimer = nil
	}

	_, err := c.RemoveAllChannels()
	if err != nil {
		c.options.Logger.Error("Error removing channels:", err)
	}

	if c.status == StatusOpen || c.status == StatusConnecting {
		err := c.transport.Disconnect(websocket.CloseNormalClosure, "client disconnect")
		if err != nil {
			return fmt.Errorf("failed to disconnect: %w", err)
		}
	}

	c.status = StatusClosed
	return nil
}

func (c *Client) Status() ConnectionStatus {
	return c.status
}

func (c *Client) IsConnected() bool {
	return c.status == StatusOpen
}

func (c *Client) nextRef() string {
	c.refMu.Lock()
	defer c.refMu.Unlock()

	c.ref++
	return fmt.Sprintf("%d", c.ref)
}

func (c *Client) onConnectionOpen() {
	c.options.Logger.Debug("Connection established")
	c.status = StatusOpen
	c.reconnectTries = 0

	c.startHeartbeatTimer()

	channels := c.GetChannels()
	for _, channel := range channels {
		if channel.status == ChannelStatusJoined || channel.status == ChannelStatusJoining {
			channel.join()
		}
	}
}

func (c *Client) onConnectionClose(code int, reason string) {
	c.options.Logger.Debug("Connection closed:", code, reason)
	prevStatus := c.status
	c.status = StatusClosed

	if c.heartbeatTimer != nil {
		c.heartbeatTimer.Stop()
		c.heartbeatTimer = nil
	}

	c.closeMu.Lock()
	isClosed := c.closed
	c.closeMu.Unlock()

	if isClosed {
		return
	}

	channels := c.GetChannels()
	for _, channel := range channels {
		if channel.status == ChannelStatusJoined {
			channel.status = ChannelStatusClosed
		}
	}

	if prevStatus == StatusOpen {
		c.reconnect()
	}
}

func (c *Client) onConnectionError(err error) {
	c.options.Logger.Error("Connection error:", err)
	c.status = StatusClosed

	c.reconnect()
}

func (c *Client) onConnectionMessage(data []byte) {
	var msg Message
	err := json.Unmarshal(data, &msg)
	if err != nil {
		c.options.Logger.Error("Failed to unmarshal message:", err)
		return
	}

	c.options.Logger.Debug("Received message:", msg.Event, msg.Topic, msg.Ref)

	c.heartbeatsMu.Lock()
	isHeartbeatResponse := msg.Ref == c.pendingHeartbeat
	if isHeartbeatResponse {
		c.pendingHeartbeat = ""
	}
	c.heartbeatsMu.Unlock()

	if isHeartbeatResponse {
		c.options.Logger.Debug("Received heartbeat response")
		return
	}

	c.callbacksMu.RLock()
	callback, exists := c.callbacks[msg.Ref]
	c.callbacksMu.RUnlock()

	if exists {
		callback(msg)
		c.callbacksMu.Lock()
		delete(c.callbacks, msg.Ref)
		c.callbacksMu.Unlock()
	}

	c.channelsMu.RLock()
	channel, exists := c.channels[msg.Topic]
	c.channelsMu.RUnlock()

	if exists {
		channel.on(msg)
	}
}

func (c *Client) reconnect() {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return
	}
	c.closeMu.Unlock()

	if c.reconnectTimer != nil {
		return
	}

	c.reconnectTries++
	delay := c.options.ReconnectAfterMs(c.reconnectTries)

	c.options.Logger.Info("Reconnecting in", delay)

	c.reconnectTimer = time.AfterFunc(delay, func() {
		c.reconnectTimer = nil
		c.options.Logger.Info("Attempting to reconnect...")
		err := c.Connect()
		if err != nil {
			c.options.Logger.Error("Failed to reconnect:", err)
			c.reconnect()
		}
	})
}

func (c *Client) sendHeartbeat() {
	if c.status != StatusOpen {
		return
	}

	ref := c.nextRef()
	msg := Message{
		Event:   "heartbeat",
		Topic:   "phoenix",
		Payload: map[string]interface{}{},
		Ref:     ref,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		c.options.Logger.Error("Failed to marshal heartbeat message:", err)
		return
	}

	c.heartbeatsMu.Lock()
	c.pendingHeartbeat = ref
	c.heartbeatsMu.Unlock()

	c.options.Logger.Debug("Sending heartbeat")
	err = c.transport.Send(jsonData)
	if err != nil {
		c.options.Logger.Error("Failed to send heartbeat:", err)
		c.onConnectionError(err)
		return
	}

	if c.options.HeartbeatTimeoutMs > 0 {
		time.AfterFunc(time.Duration(c.options.HeartbeatTimeoutMs)*time.Millisecond, func() {
			c.heartbeatsMu.Lock()
			defer c.heartbeatsMu.Unlock()
			if c.pendingHeartbeat == ref {
				c.options.Logger.Warn("Heartbeat timeout")
				c.pendingHeartbeat = ""
				c.onConnectionError(errors.New("heartbeat timeout"))
			}
		})
	}
}

func (c *Client) startHeartbeatTimer() {
	if c.heartbeatTimer != nil {
		c.heartbeatTimer.Stop()
	}

	if c.options.HeartbeatInterval > 0 {
		c.heartbeatTimer = time.AfterFunc(c.options.HeartbeatInterval, func() {
			c.sendHeartbeat()
			c.startHeartbeatTimer()
		})
	}
}

func (c *Client) registerCallback(ref string, callback func(Message)) {
	c.callbacksMu.Lock()
	defer c.callbacksMu.Unlock()
	c.callbacks[ref] = callback
}

func (c *Client) makeRef(event string, topic string, payload map[string]interface{}) (string, error) {
	ref := c.nextRef()
	msg := Message{
		Event:   event,
		Topic:   topic,
		Payload: payload,
		Ref:     ref,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message: %w", err)
	}

	err = c.transport.Send(jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to send message: %w", err)
	}

	return ref, nil
}

type Channel struct {
	name            string
	client          *Client
	options         *ChannelOptions
	status          ChannelStatus
	handlers        map[string][]EventHandler
	presenceState   PresenceState
	joinPush        *Push
	rejoinTimer     *time.Timer
	pushBuffer      []*Push
	subscribeParams *SubscribeParams
	joinRef         string
	handlersMu      sync.RWMutex
	presenceStateMu sync.RWMutex
	pushBufferMu    sync.Mutex
}

func (c *Channel) Subscribe(callback EventHandler) error {
	return c.SubscribeToEvent("*", callback)
}

func (c *Channel) SubscribeToEvent(event string, callback EventHandler) error {
	if c.status != ChannelStatusJoined {
		if err := c.join(); err != nil {
			return err
		}
	}

	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()

	if c.handlers == nil {
		c.handlers = make(map[string][]EventHandler)
	}

	c.handlers[event] = append(c.handlers[event], callback)
	return nil
}

func (c *Channel) Unsubscribe() error {
	if c.status != ChannelStatusJoined {
		return nil
	}

	c.status = ChannelStatusLeaving

	_, err := c.client.makeRef("phx_leave", c.name, map[string]interface{}{})
	if err != nil {
		return err
	}

	c.handlersMu.Lock()
	c.handlers = make(map[string][]EventHandler)
	c.handlersMu.Unlock()

	c.presenceStateMu.Lock()
	c.presenceState = make(PresenceState)
	c.presenceStateMu.Unlock()

	if c.rejoinTimer != nil {
		c.rejoinTimer.Stop()
		c.rejoinTimer = nil
	}

	c.status = ChannelStatusClosed
	return nil
}

func (c *Channel) join() error {
	if c.status == ChannelStatusJoined || c.status == ChannelStatusJoining {
		return nil
	}

	if c.client.status != StatusOpen {
		if err := c.client.connect(); err != nil {
			return err
		}
	}

	c.status = ChannelStatusJoining

	joinPayload := map[string]interface{}{
		"config": c.options.Config,
	}

	if c.options.Params != nil {
		for k, v := range c.options.Params {
			joinPayload[k] = v
		}
	}

	if len(c.subscribeParams.PostgresChanges) > 0 ||
		len(c.subscribeParams.Broadcast.Events) > 0 ||
		c.subscribeParams.Presence.Key != "" {
		jsonBytes, err := json.Marshal(c.subscribeParams)
		if err == nil {
			var asMap map[string]interface{}
			if err := json.Unmarshal(jsonBytes, &asMap); err == nil {
				for k, v := range asMap {
					joinPayload[k] = v
				}
			}
		}
	}

	c.joinPush = &Push{
		Event:   "phx_join",
		Topic:   c.name,
		Payload: joinPayload,
	}

	ref, err := c.client.makeRef("phx_join", c.name, joinPayload)
	if err != nil {
		c.status = ChannelStatusError
		return err
	}

	c.joinRef = ref

	c.client.registerCallback(ref, func(message Message) {
		if status, ok := message.Payload["status"].(string); ok {
			if status == "ok" {
				c.status = ChannelStatusJoined

				c.pushBufferMu.Lock()
				for _, push := range c.pushBuffer {
					c.pushMessage(push)
				}
				c.pushBuffer = make([]*Push, 0)
				c.pushBufferMu.Unlock()
			} else {
				c.status = ChannelStatusError
			}
		}
	})

	return nil
}

func (c *Channel) on(message Message) {
	if message.Event == "presence_state" {
		var state PresenceState
		if jsonBytes, err := json.Marshal(message.Payload); err == nil {
			if err := json.Unmarshal(jsonBytes, &state); err == nil {
				c.presenceStateMu.Lock()
				c.presenceState = state
				c.presenceStateMu.Unlock()
			}
		}
	} else if message.Event == "presence_diff" {
		var diff PresenceDiff
		if jsonBytes, err := json.Marshal(message.Payload); err == nil {
			if err := json.Unmarshal(jsonBytes, &diff); err == nil {
				c.presenceStateMu.Lock()
				for key, presence := range diff.Joins {
					c.presenceState[key] = presence
				}
				for key := range diff.Leaves {
					delete(c.presenceState, key)
				}
				c.presenceStateMu.Unlock()
			}
		}
	}

	c.handlersMu.RLock()
	defer c.handlersMu.RUnlock()

	if handlers, ok := c.handlers[message.Event]; ok {
		for _, handler := range handlers {
			handler(message)
		}
	}

	if handlers, ok := c.handlers["*"]; ok {
		for _, handler := range handlers {
			handler(message)
		}
	}
}

func (c *Channel) Broadcast(event string, payload interface{}) error {
	if c.status != ChannelStatusJoined {
		return errors.New("channel not joined")
	}

	payloadMap := make(map[string]interface{})
	if jsonBytes, err := json.Marshal(payload); err == nil {
		if err := json.Unmarshal(jsonBytes, &payloadMap); err != nil {
			payloadMap = map[string]interface{}{
				"data": payload,
			}
		}
	} else {
		payloadMap = map[string]interface{}{
			"data": payload,
		}
	}

	_, err := c.client.makeRef(event, c.name, payloadMap)
	return err
}

func (c *Channel) Track(payload interface{}) error {
	if c.status != ChannelStatusJoined {
		return errors.New("channel not joined")
	}

	payloadMap := make(map[string]interface{})
	if jsonBytes, err := json.Marshal(payload); err == nil {
		if err := json.Unmarshal(jsonBytes, &payloadMap); err != nil {
			payloadMap = map[string]interface{}{
				"data": payload,
			}
		}
	} else {
		payloadMap = map[string]interface{}{
			"data": payload,
		}
	}

	_, err := c.client.makeRef("presence_track", c.name, payloadMap)
	return err
}

func (c *Channel) Untrack() error {
	if c.status != ChannelStatusJoined {
		return errors.New("channel not joined")
	}

	_, err := c.client.makeRef("presence_untrack", c.name, map[string]interface{}{})
	return err
}

func (c *Channel) GetPresenceState() PresenceState {
	c.presenceStateMu.RLock()
	defer c.presenceStateMu.RUnlock()

	stateCopy := make(PresenceState)
	for k, v := range c.presenceState {
		stateCopy[k] = v
	}

	return stateCopy
}

func (c *Channel) SubscribeToPostgresChanges(changes []PostgresChange) *Channel {
	c.subscribeParams.PostgresChanges = append(c.subscribeParams.PostgresChanges, changes...)
	return c
}

func (c *Channel) SubscribeToBroadcast(events []string, opts BroadcastConfig) *Channel {
	c.subscribeParams.Broadcast.Events = append(c.subscribeParams.Broadcast.Events, events...)
	c.subscribeParams.Broadcast.Self = opts.Self
	c.subscribeParams.Broadcast.Ack = opts.Ack
	return c
}

func (c *Channel) SubscribeToPresence(key string) *Channel {
	c.subscribeParams.Presence.Key = key
	return c
}

func (c *Channel) pushMessage(push *Push) error {
	if c.status != ChannelStatusJoined && push.Event != "phx_join" {
		c.pushBufferMu.Lock()
		c.pushBuffer = append(c.pushBuffer, push)
		c.pushBufferMu.Unlock()
		return nil
	}

	ref, err := c.client.makeRef(push.Event, push.Topic, push.Payload)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	if push.Event == "phx_join" {
		c.joinRef = ref
	}

	return nil
}

func (c *Channel) Status() ChannelStatus {
	return c.status
}

func (c *Channel) Name() string {
	return c.name
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
