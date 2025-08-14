import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * Custom hook for WebSocket connection with automatic reconnection
 * @param {string} url - WebSocket URL
 * @param {object} options - Configuration options
 */
const useWebSocket = (url, options = {}) => {
  const {
    onOpen = () => {},
    onMessage = () => {},
    onClose = () => {},
    onError = () => {},
    shouldReconnect = true,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5
  } = options;

  const [socket, setSocket] = useState(null);
  const [lastMessage, setLastMessage] = useState(null);
  const [readyState, setReadyState] = useState(0); // 0: CONNECTING, 1: OPEN, 2: CLOSING, 3: CLOSED
  const [isConnected, setIsConnected] = useState(false);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);

  const reconnectTimeoutRef = useRef(null);
  const shouldReconnectRef = useRef(shouldReconnect);

  // Update shouldReconnect ref when prop changes
  useEffect(() => {
    shouldReconnectRef.current = shouldReconnect;
  }, [shouldReconnect]);

  const connect = useCallback(() => {
    if (!url) return;

    try {
      console.log(`[WebSocket] Connecting to: ${url}`);
      const ws = new WebSocket(url);

      ws.onopen = (event) => {
        console.log('[WebSocket] Connected successfully');
        setSocket(ws);
        setReadyState(1);
        setIsConnected(true);
        setReconnectAttempts(0);
        onOpen(event);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
          onMessage(data, event);
        } catch (error) {
          console.error('[WebSocket] Failed to parse message:', error);
          setLastMessage(event.data);
          onMessage(event.data, event);
        }
      };

      ws.onclose = (event) => {
        console.log('[WebSocket] Connection closed:', event.code, event.reason);
        setSocket(null);
        setReadyState(3);
        setIsConnected(false);
        onClose(event);

        // Attempt reconnection
        if (shouldReconnectRef.current && reconnectAttempts < maxReconnectAttempts) {
          console.log(`[WebSocket] Attempting reconnection in ${reconnectInterval}ms (attempt ${reconnectAttempts + 1}/${maxReconnectAttempts})`);
          reconnectTimeoutRef.current = setTimeout(() => {
            setReconnectAttempts(prev => prev + 1);
            connect();
          }, reconnectInterval);
        }
      };

      ws.onerror = (event) => {
        console.error('[WebSocket] Connection error:', event);
        setReadyState(3);
        setIsConnected(false);
        onError(event);
      };

      // Update readyState to CONNECTING
      setReadyState(0);

    } catch (error) {
      console.error('[WebSocket] Failed to create connection:', error);
      onError(error);
    }
  }, [url, onOpen, onMessage, onClose, onError, reconnectInterval, maxReconnectAttempts, reconnectAttempts]);

  // Send message through WebSocket
  const sendMessage = useCallback((message) => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      try {
        const messageString = typeof message === 'string' ? message : JSON.stringify(message);
        socket.send(messageString);
        return true;
      } catch (error) {
        console.error('[WebSocket] Failed to send message:', error);
        return false;
      }
    } else {
      console.warn('[WebSocket] Cannot send message: socket not connected');
      return false;
    }
  }, [socket]);

  // Send JSON message
  const sendJsonMessage = useCallback((message) => {
    return sendMessage(JSON.stringify(message));
  }, [sendMessage]);

  // Manually close connection
  const disconnect = useCallback(() => {
    shouldReconnectRef.current = false;
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (socket) {
      socket.close();
    }
  }, [socket]);

  // Manually reconnect
  const reconnect = useCallback(() => {
    disconnect();
    shouldReconnectRef.current = true;
    setReconnectAttempts(0);
    setTimeout(connect, 100);
  }, [disconnect, connect]);

  // Initialize connection
  useEffect(() => {
    connect();
    
    return () => {
      shouldReconnectRef.current = false;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (socket) {
        socket.close();
      }
    };
  }, [url]); // Only reconnect when URL changes

  return {
    socket,
    lastMessage,
    readyState,
    isConnected,
    reconnectAttempts,
    sendMessage,
    sendJsonMessage,
    disconnect,
    reconnect
  };
};

export default useWebSocket;
