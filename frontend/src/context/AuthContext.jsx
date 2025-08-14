import { createContext, useState, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';
import axios from '../utils/axiosConfig';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Token is handled by axios interceptors in axiosConfig.js

  // Load user from token
  useEffect(() => {
    const loadUser = async () => {
      if (!token) {
        setLoading(false);
        return;
      }

      try {
        // Check if token is expired
        const decoded = jwtDecode(token);
        const currentTime = Date.now() / 1000;
        
        if (decoded.exp < currentTime) {
          // Token expired, logout
          logout();
          setLoading(false);
          return;
        }

        // Token valid, get user data
        const res = await axios.get('/auth/me');
        setUser(res.data);
        setLoading(false);
      } catch (err) {
        console.error('Error loading user:', err);
        logout();
        setLoading(false);
      }
    };

    loadUser();
  }, [token]);

  // Login user
  const login = async (username, password) => {
    try {
      setError(null);
      const res = await axios.post('/auth/login', { username, password });
      
      // Save token to localStorage and state
      localStorage.setItem('token', res.data.token);
      setToken(res.data.token);
      
      // Set user
      setUser(res.data.user);
      
      return res.data.user;
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
      throw err;
    }
  };

  // Logout user
  const logout = () => {
    // Remove token from localStorage
    localStorage.removeItem('token');
    
    // Reset state
    setToken(null);
    setUser(null);
    // Auth header will be handled by axios interceptors
  };

  // Check if user is admin
  const isAdmin = () => {
    return user?.role === 'admin';
  };

  // Check if user is red team
  const isRedTeam = () => {
    return user?.role === 'red_team' || user?.role === 'admin';
  };

  // Check if user is blue team
  const isBlueTeam = () => {
    return user?.role === 'blue_team' || user?.role === 'admin';
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        user,
        loading,
        error,
        login,
        logout,
        isAdmin,
        isRedTeam,
        isBlueTeam,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};