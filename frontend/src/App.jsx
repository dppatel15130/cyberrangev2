import { useState, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap/dist/js/bootstrap.bundle.min.js';
import './App.css';
import './utils/axiosConfig'; // Import axios config

// Components
import Navbar from './components/layout/Navbar';
import Footer from './components/layout/Footer';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Labs from './pages/Labs';
import LabDetails from './pages/LabDetails';
import LabSession from './pages/LabSession';
import AdminDashboard from './pages/admin/AdminDashboard';
import ManageUsers from './pages/admin/ManageUsers';
import ManageLabs from './pages/admin/ManageLabs';
import CreateLab from './pages/admin/CreateLab';
import EditLab from './pages/admin/EditLab';
import CreateUser from './pages/admin/CreateUser';
import WebLabForm from './pages/admin/WebLabForm';
import WebLabView from './pages/WebLabView';

// Cyber-Warfare Pages
import MatchLobby from './pages/cyberwar/MatchLobby';
import TeamDetail from './pages/cyberwar/TeamDetail';
import MatchView from './pages/cyberwar/MatchView';
import Scoreboard from './pages/cyberwar/Scoreboard';
import CyberwarAdminDashboard from './pages/cyberwar/AdminDashboard';
import Teams from './pages/cyberwar/Teams';
import NewTeam from './pages/cyberwar/NewTeam';
import Leaderboard from './pages/cyberwar/Leaderboard';
import Analytics from './pages/cyberwar/Analytics';

// Context is provided in main.jsx

// Utils
import PrivateRoute from './utils/PrivateRoute';
import AdminRoute from './utils/AdminRoute';

function App() {
  return (
    <div className="app-container d-flex flex-column min-vh-100">
      <Navbar />
      <main className="flex-grow-1">
            <Routes>
              {/* Public Routes */}
              <Route path="/login" element={<Login />} />
              <Route path="/" element={<Navigate to="/login" replace />} />
              
              {/* Protected Routes */}
              <Route path="/dashboard" element={
                <PrivateRoute>
                  <Dashboard />
                </PrivateRoute>
              } />
              
              <Route path="/labs" element={
                <PrivateRoute>
                  <Labs />
                </PrivateRoute>
              } />
              
              <Route path="/labs/:labId" element={
                <PrivateRoute>
                  <LabDetails />
                </PrivateRoute>
              } />
              
              <Route path="/labs/:labId/session/:vmId" element={
                <PrivateRoute>
                  <LabSession />
                </PrivateRoute>
              } />
              
              <Route path="/weblabs/:labId" element={
                <PrivateRoute>
                  <WebLabView />
                </PrivateRoute>
              } />
              
              <Route path="/labs/web/:labId" element={
                <PrivateRoute>
                  <WebLabView />
                </PrivateRoute>
              } />
              
              {/* Admin Routes */}
              <Route path="/admin" element={
                <AdminRoute>
                  <AdminDashboard />
                </AdminRoute>
              } />
              
              <Route path="/admin/users" element={
                <AdminRoute>
                  <ManageUsers />
                </AdminRoute>
              } />
              
              <Route path="/admin/labs" element={
                <AdminRoute>
                  <ManageLabs />
                </AdminRoute>
              } />
              
              <Route path="/admin/labs/create" element={
                <AdminRoute>
                  <CreateLab />
                </AdminRoute>
              } />
              
              <Route path="/admin/labs/edit/:labId" element={
                <AdminRoute>
                  <EditLab />
                </AdminRoute>
              } />
              
              <Route path="/admin/weblabs/new" element={
                <AdminRoute>
                  <WebLabForm />
                </AdminRoute>
              } />
              
              <Route path="/admin/weblabs/edit/:labId" element={
                <AdminRoute>
                  <WebLabForm editMode={true} />
                </AdminRoute>
              } />
              
              <Route path="/admin/users/create" element={
                <AdminRoute>
                  <CreateUser />
                </AdminRoute>
              } />

              {/* Cyber-Warfare Routes */}
              <Route path="/cyberwar/lobby" element={
                <PrivateRoute>
                  <MatchLobby />
                </PrivateRoute>
              } />
              
              <Route path="/cyberwar/teams/:teamId" element={
                <PrivateRoute>
                  <TeamDetail />
                </PrivateRoute>
              } />
              
              <Route path="/cyberwar/match/:matchId" element={
                <PrivateRoute>
                  <MatchView />
                </PrivateRoute>
              } />
              
              <Route path="/cyberwar/match/:matchId/spectate" element={
                <PrivateRoute>
                  <MatchView />
                </PrivateRoute>
              } />
              
              <Route path="/cyberwar/match/:matchId/scoreboard" element={
                <PrivateRoute>
                  <Scoreboard />
                </PrivateRoute>
              } />
              
              {/* Additional Cyber-Warfare Routes */}
              <Route path="/cyberwar/teams" element={
                <PrivateRoute>
                  <Teams />
                </PrivateRoute>
              } />
              
              <Route path="/cyberwar/teams/new" element={
                <PrivateRoute>
                  <NewTeam />
                </PrivateRoute>
              } />
              
              <Route path="/cyberwar/leaderboard" element={
                <PrivateRoute>
                  <Leaderboard />
                </PrivateRoute>
              } />
              
              <Route path="/cyberwar/analytics" element={
                <PrivateRoute>
                  <Analytics />
                </PrivateRoute>
              } />
              
              {/* Cyber-Warfare Admin Routes */}
              <Route path="/cyberwar/admin" element={
                <AdminRoute>
                  <CyberwarAdminDashboard />
                </AdminRoute>
              } />

              {/* Catch-all route for unmatched paths */}
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </main>
      <Footer />
    </div>
  )
}

export default App