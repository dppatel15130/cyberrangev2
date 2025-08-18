import { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Container, 
  Row, 
  Col, 
  Card, 
  Button, 
  Badge, 
  Alert, 
  Spinner,
  Modal,
  Form,
  ListGroup,
  Tab,
  Tabs,
  Table,
  ProgressBar,
  Dropdown,
  InputGroup
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faShield,
  faCog,
  faUsers,
  faFlag,
  faDesktop,
  faPlay,
  faStop,
  faPause,
  faTrash,
  faEdit,
  faPlus,
  faEye,
  faChartLine,
  faDownload,
  faUpload,
  faExclamationTriangle,
  faSyncAlt,
  faServer,
  faNetworkWired,
  faDatabase,
  faTrophy,
  faHistory,
  faClipboardList,
  faUserShield
} from '@fortawesome/free-solid-svg-icons';
import { AuthContext } from '../../context/AuthContext';
import cyberwarService from '../../services/cyberwarService';

const AdminDashboard = () => {
  const { user, loading: authLoading } = useContext(AuthContext);
  const navigate = useNavigate();
  
  // State management
  const [stats, setStats] = useState({});
  const [matches, setMatches] = useState([]);
  const [teams, setTeams] = useState([]);
  const [users, setUsers] = useState([]);
  const [flags, setFlags] = useState([]);
  const [vms, setVms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Show loading state while auth is being checked
  if (authLoading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '80vh' }}>
        <Spinner animation="border" role="status">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
      </div>
    );
  }
  
  // Redirect to login if not authenticated (only after auth has loaded)
  if (!user) {
    navigate('/login', { state: { from: '/cyberwar/admin' }, replace: true });
    return null;
  }
  
  // Modals
  const [showCreateMatch, setShowCreateMatch] = useState(false);
  const [showCreateFlag, setShowCreateFlag] = useState(false);
  const [showVMControl, setShowVMControl] = useState(false);
  const [showUserManagement, setShowUserManagement] = useState(false);
  
  // Form data
  const [newMatch, setNewMatch] = useState({
    name: '',
    description: '',
    duration: 300, // Changed from 120 to 300 (5 minutes minimum)
    maxTeams: 4,   // Changed from 10 to 4 (max 8, using a safer default)
    flagIds: [],
    vmIds: []
  });
  
  const [newFlag, setNewFlag] = useState({
    name: '',
    description: '',
    category: 'web',
    value: '',
    points: 100,
    isActive: true
  });
  
  const [selectedVM, setSelectedVM] = useState(null);

// Replace this section in your AdminDashboard.jsx

useEffect(() => {
  // Check admin permissions
  if (!user) {
    // If user is not logged in, redirect to login
    navigate('/login', { state: { from: '/cyberwar/admin' } });
    return;
  }

  // Check if user has admin or cyberwar admin role
  // Fix: Check user.role instead of user.isAdmin
  const hasAdminAccess = user.role === 'admin' || user.role === 'cyberwar_admin';
  
  if (!hasAdminAccess) {
    // If user doesn't have required permissions, redirect to dashboard with error message
    navigate('/dashboard', { 
      state: { 
        error: 'You do not have permission to access the Cyberwar Admin Dashboard' 
      } 
    });
    return;
  }
  
  // If we get here, user has permission - fetch dashboard data
  fetchDashboardData();
}, [user, navigate]);

// Also fix this condition at the bottom:


  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const [
        statsRes,
        matchesRes,
        teamsRes,
        usersRes,
        flagsRes,
        vmsRes
      ] = await Promise.all([
        cyberwarService.getAdminStats(),
        cyberwarService.getMatches(),
        cyberwarService.getTeams(),
        cyberwarService.getAdminUsers(),
        cyberwarService.getAdminFlags(),
        cyberwarService.getAdminVMs()
      ]);
      
      setStats(statsRes);
      setMatches(matchesRes.matches || []);
      setTeams(teamsRes.teams || []);
      setUsers(usersRes.users || []);
      setFlags(flagsRes.flags || []);
      setVms(vmsRes.vms || []);
      
    } catch (err) {
      console.error('Failed to fetch admin dashboard data:', err);
      setError('Failed to load dashboard data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateMatch = async (e) => {
    e.preventDefault();
    try {
      await cyberwarService.createMatch(newMatch);
      setShowCreateMatch(false);
      setNewMatch({
        name: '',
        description: '',
        duration: 120,
        maxTeams: 10,
        flagIds: [],
        vmIds: []
      });
      fetchDashboardData();
    } catch (err) {
      console.error('Failed to create match:', err);
      setError('Failed to create match. Please try again.');
    }
  };

  const handleCreateFlag = async (e) => {
    e.preventDefault();
    try {
      await cyberwarService.createFlag(newFlag);
      setShowCreateFlag(false);
      setNewFlag({
        name: '',
        description: '',
        category: 'web',
        value: '',
        points: 100,
        isActive: true
      });
      fetchDashboardData();
    } catch (err) {
      console.error('Failed to create flag:', err);
      setError('Failed to create flag. Please try again.');
    }
  };

  const handleMatchAction = async (matchId, action) => {
    try {
      await cyberwarService.controlMatch(matchId, action);
      fetchDashboardData();
    } catch (err) {
      console.error(`Failed to ${action} match:`, err);
      setError(`Failed to ${action} match. Please try again.`);
    }
  };

  const handleVMAction = async (vmId, action) => {
    try {
      await cyberwarService.controlVM(vmId, action);
      fetchDashboardData();
    } catch (err) {
      console.error(`Failed to ${action} VM:`, err);
      setError(`Failed to ${action} VM. Please try again.`);
    }
  };

  const handleDeleteFlag = async (flagId) => {
    if (window.confirm('Are you sure you want to delete this flag?')) {
      try {
        await cyberwarService.deleteFlag(flagId);
        fetchDashboardData();
      } catch (err) {
        console.error('Failed to delete flag:', err);
        setError('Failed to delete flag. Please try again.');
      }
    }
  };

  const handleUserAction = async (userId, action) => {
    try {
      await cyberwarService.adminUserAction(userId, action);
      fetchDashboardData();
    } catch (err) {
      console.error(`Failed to ${action} user:`, err);
      setError(`Failed to ${action} user. Please try again.`);
    }
  };

  const exportData = async (type) => {
    try {
      const data = await cyberwarService.exportAdminData(type);
      const blob = new Blob([data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${type}-export-${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(`Failed to export ${type}:`, err);
      setError(`Failed to export ${type}. Please try again.`);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return <Badge bg="success">Active</Badge>;
      case 'completed':
        return <Badge bg="secondary">Completed</Badge>;
      case 'ready':
        return <Badge bg="warning">Ready</Badge>;
      case 'draft':
        return <Badge bg="info">Draft</Badge>;
      default:
        return <Badge bg="light" text="dark">{status}</Badge>;
    }
  };

  const getVMStatusBadge = (status) => {
    switch (status) {
      case 'running':
        return <Badge bg="success">Running</Badge>;
      case 'stopped':
        return <Badge bg="danger">Stopped</Badge>;
      case 'paused':
        return <Badge bg="warning">Paused</Badge>;
      case 'error':
        return <Badge bg="danger">Error</Badge>;
      default:
        return <Badge bg="secondary">{status}</Badge>;
    }
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" size="lg" />
        <p className="mt-3">Loading admin dashboard...</p>
      </Container>
    );
  }

  if (!user || (user.role !== 'admin' && user.role !== 'cyberwar_admin')) {
    return (
      <Container className="py-5 text-center">
        <Alert variant="danger">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          Access denied. Administrator privileges required.
        </Alert>
      </Container>
    );
  }

  return (
    <Container fluid className="py-4">
      {/* Header */}
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h1 className="mb-0">
                <FontAwesomeIcon icon={faShield} className="me-2 text-primary" />
                Cyber-Warfare Administration
              </h1>
              <p className="text-muted mt-1">Manage competitions, teams, and infrastructure</p>
            </div>
            
            <div className="d-flex gap-2">
              <Button variant="outline-secondary" size="sm" onClick={fetchDashboardData}>
                <FontAwesomeIcon icon={faSyncAlt} className="me-1" />
                Refresh
              </Button>
              
              <Dropdown>
                <Dropdown.Toggle variant="outline-primary" size="sm">
                  <FontAwesomeIcon icon={faDownload} className="me-1" />
                  Export
                </Dropdown.Toggle>
                <Dropdown.Menu>
                  <Dropdown.Item onClick={() => exportData('matches')}>Matches</Dropdown.Item>
                  <Dropdown.Item onClick={() => exportData('teams')}>Teams</Dropdown.Item>
                  <Dropdown.Item onClick={() => exportData('users')}>Users</Dropdown.Item>
                  <Dropdown.Item onClick={() => exportData('flags')}>Flags</Dropdown.Item>
                </Dropdown.Menu>
              </Dropdown>
            </div>
          </div>
        </Col>
      </Row>

      {error && (
        <Alert variant="danger" dismissible onClose={() => setError(null)}>
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      {/* Statistics Cards */}
      <Row className="mb-4">
        <Col lg={3} md={6} className="mb-3">
          <Card className="h-100">
            <Card.Body className="text-center">
              <FontAwesomeIcon icon={faTrophy} size="3x" className="text-primary mb-3" />
              <div className="h2 mb-0">{stats.totalMatches || 0}</div>
              <small className="text-muted">Total Matches</small>
              <div className="mt-2">
                <Badge bg="success" className="me-1">{stats.activeMatches || 0} Active</Badge>
                <Badge bg="secondary">{stats.completedMatches || 0} Complete</Badge>
              </div>
            </Card.Body>
          </Card>
        </Col>
        
        <Col lg={3} md={6} className="mb-3">
          <Card className="h-100">
            <Card.Body className="text-center">
              <FontAwesomeIcon icon={faUsers} size="3x" className="text-success mb-3" />
              <div className="h2 mb-0">{stats.totalTeams || 0}</div>
              <small className="text-muted">Active Teams</small>
              <div className="mt-2">
                <small className="text-muted">{stats.totalUsers || 0} total users</small>
              </div>
            </Card.Body>
          </Card>
        </Col>
        
        <Col lg={3} md={6} className="mb-3">
          <Card className="h-100">
            <Card.Body className="text-center">
              <FontAwesomeIcon icon={faFlag} size="3x" className="text-warning mb-3" />
              <div className="h2 mb-0">{stats.totalFlags || 0}</div>
              <small className="text-muted">Challenge Flags</small>
              <div className="mt-2">
                <Badge bg="success" className="me-1">{stats.activeFlags || 0} Active</Badge>
                <Badge bg="info">{stats.capturedFlags || 0} Captured</Badge>
              </div>
            </Card.Body>
          </Card>
        </Col>
        
        <Col lg={3} md={6} className="mb-3">
          <Card className="h-100">
            <Card.Body className="text-center">
              <FontAwesomeIcon icon={faDesktop} size="3x" className="text-info mb-3" />
              <div className="h2 mb-0">{stats.totalVMs || 0}</div>
              <small className="text-muted">Virtual Machines</small>
              <div className="mt-2">
                <Badge bg="success" className="me-1">{stats.runningVMs || 0} Running</Badge>
                <Badge bg="danger">{stats.stoppedVMs || 0} Stopped</Badge>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Tabs */}
      <Tabs activeKey={activeTab} onSelect={setActiveTab} className="mb-4">
        <Tab eventKey="overview" title="Overview">
          <Row>
            <Col lg={8}>
              <Card className="mb-4">
                <Card.Header className="d-flex justify-content-between align-items-center">
                  <span>Recent Matches</span>
                  <Button size="sm" variant="outline-primary" onClick={() => setShowCreateMatch(true)}>
                    <FontAwesomeIcon icon={faPlus} className="me-1" />
                    Create Match
                  </Button>
                </Card.Header>
                <Card.Body>
                  {matches.slice(0, 5).map(match => (
                    <div key={match.id} className="d-flex justify-content-between align-items-center mb-3 pb-3 border-bottom">
                      <div>
                        <h6 className="mb-1">{match.name}</h6>
                        <p className="small text-muted mb-1">{match.description}</p>
                        <div>
                          {getStatusBadge(match.status)}
                          <Badge bg="info" className="ms-2">{match.teams?.length || 0} teams</Badge>
                          <Badge bg="secondary" className="ms-2">{match.duration}m</Badge>
                        </div>
                      </div>
                      <div className="d-flex gap-1">
                        {match.status === 'ready' && (
                          <Button size="sm" variant="success" onClick={() => handleMatchAction(match.id, 'start')}>
                            <FontAwesomeIcon icon={faPlay} />
                          </Button>
                        )}
                        {match.status === 'active' && (
                          <>
                            <Button size="sm" variant="warning" onClick={() => handleMatchAction(match.id, 'pause')}>
                              <FontAwesomeIcon icon={faPause} />
                            </Button>
                            <Button size="sm" variant="danger" onClick={() => handleMatchAction(match.id, 'stop')}>
                              <FontAwesomeIcon icon={faStop} />
                            </Button>
                          </>
                        )}
                        <Button size="sm" variant="outline-primary" onClick={() => navigate(`/cyberwar/match/${match.id}/scoreboard`)}>
                          <FontAwesomeIcon icon={faEye} />
                        </Button>
                      </div>
                    </div>
                  ))}
                </Card.Body>
              </Card>
              
              <Card>
                <Card.Header>System Health</Card.Header>
                <Card.Body>
                  <Row>
                    <Col md={4}>
                      <div className="text-center mb-3">
                        <FontAwesomeIcon icon={faServer} size="2x" className="text-success mb-2" />
                        <div className="h5 mb-0">Online</div>
                        <small className="text-muted">Backend Services</small>
                      </div>
                    </Col>
                    <Col md={4}>
                      <div className="text-center mb-3">
                        <FontAwesomeIcon icon={faDatabase} size="2x" className="text-success mb-2" />
                        <div className="h5 mb-0">Connected</div>
                        <small className="text-muted">Database</small>
                      </div>
                    </Col>
                    <Col md={4}>
                      <div className="text-center mb-3">
                        <FontAwesomeIcon icon={faNetworkWired} size="2x" className="text-success mb-2" />
                        <div className="h5 mb-0">Active</div>
                        <small className="text-muted">WebSocket</small>
                      </div>
                    </Col>
                  </Row>
                </Card.Body>
              </Card>
            </Col>
            
            <Col lg={4}>
              <Card className="mb-4">
                <Card.Header>Quick Actions</Card.Header>
                <Card.Body className="d-grid gap-2">
                  <Button variant="primary" onClick={() => setShowCreateMatch(true)}>
                    <FontAwesomeIcon icon={faPlus} className="me-2" />
                    Create New Match
                  </Button>
                  <Button variant="outline-primary" onClick={() => setShowCreateFlag(true)}>
                    <FontAwesomeIcon icon={faFlag} className="me-2" />
                    Add Challenge Flag
                  </Button>
                  <Button variant="outline-secondary" onClick={() => setShowVMControl(true)}>
                    <FontAwesomeIcon icon={faDesktop} className="me-2" />
                    VM Management
                  </Button>
                  <Button variant="outline-info" onClick={() => setShowUserManagement(true)}>
                    <FontAwesomeIcon icon={faUserShield} className="me-2" />
                    User Management
                  </Button>
                </Card.Body>
              </Card>
              
              <Card>
                <Card.Header>Active Alerts</Card.Header>
                <Card.Body>
                  {stats.alerts && stats.alerts.length > 0 ? (
                    stats.alerts.map((alert, index) => (
                      <Alert key={index} variant={alert.type} className="small mb-2">
                        {alert.message}
                      </Alert>
                    ))
                  ) : (
                    <p className="text-muted small">No active alerts</p>
                  )}
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>

        <Tab eventKey="matches" title="Match Management">
          <Card>
            <Card.Header className="d-flex justify-content-between align-items-center">
              <span>All Matches</span>
              <Button variant="primary" onClick={() => setShowCreateMatch(true)}>
                <FontAwesomeIcon icon={faPlus} className="me-1" />
                Create Match
              </Button>
            </Card.Header>
            <Card.Body className="p-0">
              <Table responsive>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Teams</th>
                    <th>Duration</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {matches.map(match => (
                    <tr key={match.id}>
                      <td>
                        <strong>{match.name}</strong>
                        <br />
                        <small className="text-muted">{match.description}</small>
                      </td>
                      <td>{getStatusBadge(match.status)}</td>
                      <td>{match.teams?.length || 0}/{match.maxTeams}</td>
                      <td>{match.duration} minutes</td>
                      <td>{new Date(match.createdAt).toLocaleDateString()}</td>
                      <td>
                        <div className="d-flex gap-1">
                          {match.status === 'ready' && (
                            <Button size="sm" variant="success" onClick={() => handleMatchAction(match.id, 'start')}>
                              <FontAwesomeIcon icon={faPlay} />
                            </Button>
                          )}
                          {match.status === 'active' && (
                            <>
                              <Button size="sm" variant="warning" onClick={() => handleMatchAction(match.id, 'pause')}>
                                <FontAwesomeIcon icon={faPause} />
                              </Button>
                              <Button size="sm" variant="danger" onClick={() => handleMatchAction(match.id, 'stop')}>
                                <FontAwesomeIcon icon={faStop} />
                              </Button>
                            </>
                          )}
                          <Button size="sm" variant="outline-primary" onClick={() => navigate(`/cyberwar/match/${match.id}/scoreboard`)}>
                            <FontAwesomeIcon icon={faEye} />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Tab>

        <Tab eventKey="flags" title="Flag Management">
          <Card>
            <Card.Header className="d-flex justify-content-between align-items-center">
              <span>Challenge Flags</span>
              <Button variant="primary" onClick={() => setShowCreateFlag(true)}>
                <FontAwesomeIcon icon={faPlus} className="me-1" />
                Add Flag
              </Button>
            </Card.Header>
            <Card.Body className="p-0">
              <Table responsive>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Category</th>
                    <th>Points</th>
                    <th>Status</th>
                    <th>Captures</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {flags.map(flag => (
                    <tr key={flag.id}>
                      <td>
                        <strong>{flag.name}</strong>
                        <br />
                        <small className="text-muted">{flag.description}</small>
                      </td>
                      <td>
                        <Badge bg="info">{flag.category}</Badge>
                      </td>
                      <td>{flag.points}</td>
                      <td>
                        <Badge bg={flag.isActive ? 'success' : 'secondary'}>
                          {flag.isActive ? 'Active' : 'Inactive'}
                        </Badge>
                      </td>
                      <td>{flag.captures || 0}</td>
                      <td>
                        <div className="d-flex gap-1">
                          <Button size="sm" variant="outline-primary">
                            <FontAwesomeIcon icon={faEdit} />
                          </Button>
                          <Button size="sm" variant="outline-danger" onClick={() => handleDeleteFlag(flag.id)}>
                            <FontAwesomeIcon icon={faTrash} />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Tab>

        <Tab eventKey="infrastructure" title="Infrastructure">
          <Row>
            <Col lg={8}>
              <Card>
                <Card.Header>Virtual Machines</Card.Header>
                <Card.Body className="p-0">
                  <Table responsive>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>OS</th>
                        <th>Status</th>
                        <th>Match</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vms.map(vm => (
                        <tr key={vm.id}>
                          <td><strong>{vm.name}</strong></td>
                          <td><code>{vm.ipAddress}</code></td>
                          <td>{vm.os}</td>
                          <td>{getVMStatusBadge(vm.status)}</td>
                          <td>
                            {vm.matchId ? (
                              <Badge bg="info">{vm.matchName}</Badge>
                            ) : (
                              <Badge bg="secondary">Unassigned</Badge>
                            )}
                          </td>
                          <td>
                            <div className="d-flex gap-1">
                              {vm.status === 'stopped' ? (
                                <Button size="sm" variant="success" onClick={() => handleVMAction(vm.id, 'start')}>
                                  <FontAwesomeIcon icon={faPlay} />
                                </Button>
                              ) : (
                                <>
                                  <Button size="sm" variant="warning" onClick={() => handleVMAction(vm.id, 'restart')}>
                                    <FontAwesomeIcon icon={faSyncAlt} />
                                  </Button>
                                  <Button size="sm" variant="danger" onClick={() => handleVMAction(vm.id, 'stop')}>
                                    <FontAwesomeIcon icon={faStop} />
                                  </Button>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                </Card.Body>
              </Card>
            </Col>
            
            <Col lg={4}>
              <Card>
                <Card.Header>Infrastructure Stats</Card.Header>
                <Card.Body>
                  <div className="mb-3">
                    <div className="d-flex justify-content-between mb-1">
                      <small>VM Utilization</small>
                      <small>{Math.round((stats.runningVMs / stats.totalVMs) * 100)}%</small>
                    </div>
                    <ProgressBar now={(stats.runningVMs / stats.totalVMs) * 100} />
                  </div>
                  
                  <div className="text-center">
                    <div className="row">
                      <div className="col-6">
                        <div className="h4 text-success mb-0">{stats.runningVMs || 0}</div>
                        <small className="text-muted">Running</small>
                      </div>
                      <div className="col-6">
                        <div className="h4 text-danger mb-0">{stats.stoppedVMs || 0}</div>
                        <small className="text-muted">Stopped</small>
                      </div>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>

        <Tab eventKey="users" title="User Management">
          <Card>
            <Card.Header>
              <span>User Accounts</span>
            </Card.Header>
            <Card.Body className="p-0">
              <Table responsive>
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(user => (
                    <tr key={user.id}>
                      <td><strong>{user.username}</strong></td>
                      <td>{user.email}</td>
                      <td>
                        <Badge bg={user.isAdmin ? 'danger' : 'primary'}>
                          {user.isAdmin ? 'Admin' : 'User'}
                        </Badge>
                      </td>
                      <td>
                        <Badge bg={user.isActive ? 'success' : 'secondary'}>
                          {user.isActive ? 'Active' : 'Inactive'}
                        </Badge>
                      </td>
                      <td>
                        {user.lastLogin ? new Date(user.lastLogin).toLocaleDateString() : 'Never'}
                      </td>
                      <td>
                        <div className="d-flex gap-1">
                          <Button 
                            size="sm" 
                            variant={user.isActive ? 'outline-warning' : 'outline-success'}
                            onClick={() => handleUserAction(user.id, user.isActive ? 'deactivate' : 'activate')}
                          >
                            {user.isActive ? 'Deactivate' : 'Activate'}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Tab>
      </Tabs>

      {/* Create Match Modal */}
      <Modal show={showCreateMatch} onHide={() => setShowCreateMatch(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Create New Match</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form onSubmit={handleCreateMatch}>
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Match Name *</Form.Label>
                  <Form.Control 
                    type="text"
                    value={newMatch.name}
                    onChange={(e) => setNewMatch({...newMatch, name: e.target.value})}
                    required
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Duration (minutes) *</Form.Label>
                  <Form.Control 
                    type="number"
                    min="30"
                    max="480"
                    value={newMatch.duration}
                    onChange={(e) => setNewMatch({...newMatch, duration: parseInt(e.target.value)})}
                    required
                  />
                </Form.Group>
              </Col>
            </Row>
            
            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control 
                as="textarea"
                rows={3}
                value={newMatch.description}
                onChange={(e) => setNewMatch({...newMatch, description: e.target.value})}
              />
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Maximum Teams</Form.Label>
              <Form.Control 
                type="number"
                min="2"
                max="20"
                value={newMatch.maxTeams}
                onChange={(e) => setNewMatch({...newMatch, maxTeams: parseInt(e.target.value)})}
              />
            </Form.Group>

            <div className="d-grid gap-2 d-md-flex justify-content-md-end">
              <Button variant="secondary" onClick={() => setShowCreateMatch(false)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                Create Match
              </Button>
            </div>
          </Form>
        </Modal.Body>
      </Modal>

      {/* Create Flag Modal */}
      <Modal show={showCreateFlag} onHide={() => setShowCreateFlag(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Create Challenge Flag</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form onSubmit={handleCreateFlag}>
            <Form.Group className="mb-3">
              <Form.Label>Flag Name *</Form.Label>
              <Form.Control 
                type="text"
                value={newFlag.name}
                onChange={(e) => setNewFlag({...newFlag, name: e.target.value})}
                required
              />
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control 
                as="textarea"
                rows={3}
                value={newFlag.description}
                onChange={(e) => setNewFlag({...newFlag, description: e.target.value})}
              />
            </Form.Group>
            
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Category *</Form.Label>
                  <Form.Select 
                    value={newFlag.category}
                    onChange={(e) => setNewFlag({...newFlag, category: e.target.value})}
                  >
                    <option value="web">Web Security</option>
                    <option value="crypto">Cryptography</option>
                    <option value="forensics">Forensics</option>
                    <option value="reversing">Reverse Engineering</option>
                    <option value="pwn">Binary Exploitation</option>
                    <option value="misc">Miscellaneous</option>
                  </Form.Select>
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Points *</Form.Label>
                  <Form.Control 
                    type="number"
                    min="50"
                    max="1000"
                    step="50"
                    value={newFlag.points}
                    onChange={(e) => setNewFlag({...newFlag, points: parseInt(e.target.value)})}
                    required
                  />
                </Form.Group>
              </Col>
            </Row>
            
            <Form.Group className="mb-3">
              <Form.Label>Flag Value *</Form.Label>
              <Form.Control 
                type="text"
                value={newFlag.value}
                onChange={(e) => setNewFlag({...newFlag, value: e.target.value})}
                placeholder="flag{example_value}"
                required
              />
            </Form.Group>
            
            <Form.Check 
              type="checkbox"
              label="Active"
              checked={newFlag.isActive}
              onChange={(e) => setNewFlag({...newFlag, isActive: e.target.checked})}
              className="mb-3"
            />

            <div className="d-grid gap-2 d-md-flex justify-content-md-end">
              <Button variant="secondary" onClick={() => setShowCreateFlag(false)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                Create Flag
              </Button>
            </div>
          </Form>
        </Modal.Body>
      </Modal>
    </Container>
  );
};

export default AdminDashboard;
