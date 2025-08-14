import { useContext } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Navbar as BootstrapNavbar, Nav, NavDropdown, Container, Button } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faUser, 
  faSignOutAlt, 
  faShieldAlt, 
  faFlask, 
  faUsers, 
  faFire, 
  faTrophy, 
  faCogs,
  faChartLine,
  faHome 
} from '@fortawesome/free-solid-svg-icons';
import { AuthContext } from '../../context/AuthContext';

const Navbar = () => {
  const { user, logout, isAdmin } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const handleNavigation = (path) => {
    navigate(path);
  };

  return (
    <BootstrapNavbar variant="dark" expand="lg" className="mb-4">
      <Container>
        <BootstrapNavbar.Brand as={Link} to={user ? '/dashboard' : '/login'} className="neon-pulse">
          <FontAwesomeIcon icon={faShieldAlt} className="me-2" />
          <span className="glitch" data-text="Cyber Range Platform">Cyber Range Platform</span>
        </BootstrapNavbar.Brand>
        
        <BootstrapNavbar.Toggle aria-controls="basic-navbar-nav" />
        
        <BootstrapNavbar.Collapse id="basic-navbar-nav">
          <Nav className="ms-auto">
            {user ? (
              <>
                {/* Admin Links */}
                {isAdmin() && (
                  <NavDropdown 
                    title={
                      <span>
                        <FontAwesomeIcon icon={faCogs} className="me-1" />
                        Admin
                      </span>
                    } 
                    id="admin-dropdown"
                  >
                    <NavDropdown.Item onClick={() => handleNavigation('/admin')}>
                      <FontAwesomeIcon icon={faShieldAlt} className="me-2" />
                      Dashboard
                    </NavDropdown.Item>
                    <NavDropdown.Item onClick={() => handleNavigation('/admin/users')}>
                      <FontAwesomeIcon icon={faUsers} className="me-2" />
                      Manage Users
                    </NavDropdown.Item>
                    <NavDropdown.Item onClick={() => handleNavigation('/admin/labs')}>
                      <FontAwesomeIcon icon={faFlask} className="me-2" />
                      Manage Labs
                    </NavDropdown.Item>
                    <NavDropdown.Divider />
                    <NavDropdown.Item onClick={() => handleNavigation('/cyberwar/admin')}>
                      <FontAwesomeIcon icon={faFire} className="me-2" />
                      Cyber-Warfare Admin
                    </NavDropdown.Item>
                  </NavDropdown>
                )}
                
                {/* User Links */}
                <Nav.Link as={Link} to="/dashboard">
                  <FontAwesomeIcon icon={faHome} className="me-1" />
                  Dashboard
                </Nav.Link>
                
                <Nav.Link as={Link} to="/labs">
                  <FontAwesomeIcon icon={faFlask} className="me-1" />
                  Labs
                </Nav.Link>
                
                {/* Cyber-Warfare Dropdown */}
                <NavDropdown 
                  title={
                    <span>
                      <FontAwesomeIcon icon={faFire} className="me-1" />
                      Cyber-Warfare
                    </span>
                  } 
                  id="cyberwar-dropdown"
                >
                  <NavDropdown.Item onClick={() => handleNavigation('/cyberwar/lobby')}>
                    <FontAwesomeIcon icon={faUsers} className="me-2" />
                    Match Lobby
                  </NavDropdown.Item>
                  <NavDropdown.Item onClick={() => handleNavigation('/cyberwar/teams')}>
                    <FontAwesomeIcon icon={faUsers} className="me-2" />
                    My Teams
                  </NavDropdown.Item>
                  <NavDropdown.Item onClick={() => handleNavigation('/cyberwar/leaderboard')}>
                    <FontAwesomeIcon icon={faTrophy} className="me-2" />
                    Leaderboard
                  </NavDropdown.Item>
                  <NavDropdown.Divider />
                  <NavDropdown.Item onClick={() => handleNavigation('/cyberwar/analytics')}>
                    <FontAwesomeIcon icon={faChartLine} className="me-2" />
                    Analytics
                  </NavDropdown.Item>
                </NavDropdown>
                
                {/* User Info & Logout */}
                <Nav.Item className="d-flex align-items-center ms-3">
                  <span className="text-light me-3">
                    <FontAwesomeIcon icon={faUser} className="me-1" />
                    {user.username} ({user.role.replace('_', ' ')})
                  </span>
                  <Button variant="outline-light" size="sm" onClick={handleLogout}>
                    <FontAwesomeIcon icon={faSignOutAlt} className="me-1" />
                    Logout
                  </Button>
                </Nav.Item>
              </>
            ) : (
              <Nav.Link as={Link} to="/login">Login</Nav.Link>
            )}
          </Nav>
        </BootstrapNavbar.Collapse>
      </Container>
    </BootstrapNavbar>
  );
};

export default Navbar;