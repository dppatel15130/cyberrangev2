import { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Button, Alert, Spinner, Table, Badge, Modal } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUsers, faFlask, faServer, faPlus, faExclamationTriangle, faTrophy, faChartBar, faRefresh, faDesktop, faStop, faUser, faNetworkWired, faClock } from '@fortawesome/free-solid-svg-icons';
import axios from '../../utils/axiosConfig';

const AdminDashboard = () => {
  const [stats, setStats] = useState({
    totalUsers: 0,
    totalLabs: 0,
    activeVMs: 0,
    totalPoints: 0,
    completedLabs: 0
  });
  const [leaderboard, setLeaderboard] = useState([]);
  const [activeVMs, setActiveVMs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [vmsLoading, setVmsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showStopModal, setShowStopModal] = useState(false);
  const [vmToStop, setVmToStop] = useState(null);
  const [stoppingVm, setStoppingVm] = useState(false);
  const [status, setStatus] = useState({
    server: 'Unknown',
    database: 'Unknown',
    proxmox: 'Unknown',
    guacamole: 'Unknown'
  });

  const checkSystemStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://localhost:5000/api/status');
      setStatus({
        server: response.data.server || 'Offline',
        database: response.data.database || 'Disconnected',
        proxmox: response.data.proxmox || 'Disconnected',
        guacamole: response.data.guacamole || 'Disconnected'
      });
    } catch (err) {
      console.error('Error checking system status:', err);
      setError('Failed to check system status. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const fetchActiveVMs = async () => {
    try {
      setVmsLoading(true);
      const response = await axios.get('/vms');
      const vms = response.data.vms || [];
      setActiveVMs(vms);
      
      // Update the stats count as well
      setStats(prev => ({
        ...prev,
        activeVMs: vms.length
      }));
    } catch (err) {
      console.error('Error fetching active VMs:', err);
    } finally {
      setVmsLoading(false);
    }
  };

  const handleStopVM = async () => {
    if (!vmToStop) return;
    
    try {
      setStoppingVm(true);
      await axios.post(`/vms/${vmToStop.id}/stop`);
      setShowStopModal(false);
      setVmToStop(null);
      await fetchActiveVMs(); // Refresh the list
    } catch (err) {
      console.error('Error stopping VM:', err);
      setError('Failed to stop VM. Please try again.');
    } finally {
      setStoppingVm(false);
    }
  };

  const getStatusBadge = (status) => {
    const statusConfig = {
      'running': { variant: 'success', text: 'Running' },
      'stopped': { variant: 'secondary', text: 'Stopped' },
      'creating': { variant: 'info', text: 'Creating' },
      'stopping': { variant: 'warning', text: 'Stopping' },
      'error': { variant: 'danger', text: 'Error' },
      'failed': { variant: 'danger', text: 'Failed' },
      'unknown': { variant: 'secondary', text: 'Unknown' }
    };
    
    const config = statusConfig[status] || statusConfig['unknown'];
    return <Badge bg={config.variant}>{config.text}</Badge>;
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  useEffect(() => {
    const fetchStats = async () => {
      try {
        // Fetch basic stats and leaderboard
        const [usersRes, labsRes, vmsRes, leaderboardRes] = await Promise.all([
          axios.get('/auth/users'),
          axios.get('/labs'),
          axios.get('/vms'),
          axios.get('/flags/leaderboard?limit=10')
        ]);

        // Calculate total points and completed labs from all users
        const totalPoints = usersRes.data.reduce((sum, user) => sum + (user.totalPoints || 0), 0);
        const completedLabs = leaderboardRes.data.leaderboard.reduce((sum, user) => sum + user.labsCompleted, 0);

        setStats({
          totalUsers: usersRes.data.length,
          totalLabs: labsRes.data.length,
          activeVMs: vmsRes.data.vms ? vmsRes.data.vms.length : 0,
          totalPoints,
          completedLabs
        });
        
        setActiveVMs(vmsRes.data.vms || []);
        setLeaderboard(leaderboardRes.data.leaderboard || []);
        setStatsLoading(false);
      } catch (err) {
        console.error('Error fetching admin stats:', err);
        setError('Failed to load dashboard statistics. Please try again later.');
        setStatsLoading(false);
      }
    };

    fetchStats();
    checkSystemStatus();
  }, []);

  const handleCheckServices = () => {
    checkSystemStatus();
  };

  if (statsLoading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" />
        <p className="mt-3">Loading dashboard...</p>
      </Container>
    );
  }

  return (
    <Container className="admin-dashboard py-4">
      <h1 className="mb-4">Admin Dashboard</h1>

      {error && (
        <Alert variant="danger" className="mb-4">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Row className="mb-4">
        <Col lg={3} md={6}>
          <Card className="shadow-sm h-100">
            <Card.Body className="text-center">
              <div className="display-4 text-primary mb-2">
                <FontAwesomeIcon icon={faUsers} />
              </div>
              <h2>{stats.totalUsers}</h2>
              <p className="text-muted">Total Users</p>
              <Button as={Link} to="/admin/users" variant="outline-primary" size="sm">
                Manage Users
              </Button>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6}>
          <Card className="shadow-sm h-100">
            <Card.Body className="text-center">
              <div className="display-4 text-success mb-2">
                <FontAwesomeIcon icon={faFlask} />
              </div>
              <h2>{stats.totalLabs}</h2>
              <p className="text-muted">Total Labs</p>
              <Button as={Link} to="/admin/labs" variant="outline-success" size="sm">
                Manage Labs
              </Button>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6}>
          <Card className="shadow-sm h-100">
            <Card.Body className="text-center">
              <div className="display-4 text-warning mb-2">
                <FontAwesomeIcon icon={faTrophy} />
              </div>
              <h2>{stats.totalPoints.toLocaleString()}</h2>
              <p className="text-muted">Total Points Earned</p>
              <Button variant="outline-warning" size="sm" disabled>
                {stats.completedLabs} Labs Completed
              </Button>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6}>
          <Card className="shadow-sm h-100">
            <Card.Body className="text-center">
              <div className="display-4 text-danger mb-2">
                <FontAwesomeIcon icon={faServer} />
              </div>
              <h2>{stats.activeVMs}</h2>
              <p className="text-muted">Active VMs</p>
              <Button as={Link} to="/admin/vms" variant="outline-danger" size="sm">
                View Active VMs
              </Button>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row className="mb-4">
        <Col>
          <Card className="shadow-sm">
            <Card.Header className="bg-primary text-white">
              <h5 className="mb-0">Quick Actions</h5>
            </Card.Header>
            <Card.Body>
              <Row>
                <Col md={6} className="mb-3 mb-md-0">
                  <Button
                    as={Link}
                    to="/admin/labs/create"
                    variant="primary"
                    className="w-100 py-3"
                  >
                    <FontAwesomeIcon icon={faPlus} className="me-2" />
                    Create New Lab
                  </Button>
                </Col>
                <Col md={6}>
                  <Button
                    as={Link}
                    to="/admin/users/create"
                    variant="success"
                    className="w-100 py-3"
                  >
                    <FontAwesomeIcon icon={faPlus} className="me-2" />
                    Add New User
                  </Button>
                </Col>
              </Row>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row className="mb-4">
        <Col md={6}>
          <Card className="shadow-sm h-100">
            <Card.Header className="bg-info text-white">
              <h5 className="mb-0">
                <FontAwesomeIcon icon={faTrophy} className="me-2" />
                Leaderboard - Top Users
              </h5>
            </Card.Header>
            <Card.Body>
              {leaderboard.length > 0 ? (
                <div className="table-responsive">
                  <table className="table table-sm">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Username</th>
                        <th>Points</th>
                        <th>Labs Completed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {leaderboard.slice(0, 5).map((user, index) => (
                        <tr key={user.id}>
                          <td>
                            {index === 0 && <FontAwesomeIcon icon={faTrophy} className="text-warning me-1" />}
                            {index + 1}
                          </td>
                          <td>{user.username}</td>
                          <td><strong>{user.totalPoints.toLocaleString()}</strong></td>
                          <td>{user.labsCompleted}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-muted mb-0">No user activity yet.</p>
              )}
            </Card.Body>
          </Card>
        </Col>
        <Col md={6}>
          <Card className="shadow-sm h-100">
            <Card.Header className="bg-danger text-white d-flex justify-content-between align-items-center">
              <h5 className="mb-0">
                <FontAwesomeIcon icon={faServer} className="me-2" />
                Active VMs ({activeVMs.length})
              </h5>
              <Button 
                variant="dark"
                size="sm" 
                onClick={fetchActiveVMs} 
                disabled={vmsLoading}
              >
                {vmsLoading ? (
                  <>
                    <Spinner as="span" size="sm" animation="border" className="me-1" />
                    Loading...
                  </>
                ) : (
                  <>
                    <FontAwesomeIcon icon={faRefresh} className="me-1" />
                    Refresh
                  </>
                )}
              </Button>
            </Card.Header>
            <Card.Body className="p-0">
              {activeVMs.length > 0 ? (
                <div className="table-responsive">
                  <Table size="sm" className="mb-0">
                    <thead>
                      <tr>
                        <th>VM ID</th>
                        <th>User</th>
                        <th>Status</th>
                        <th>IP</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeVMs.slice(0, 8).map((vm) => (
                        <tr key={vm.id}>
                          <td>
                            <code className="small">{vm.vmId}</code>
                          </td>
                          <td>
                            <div className="small">
                              <FontAwesomeIcon icon={faUser} className="me-1 text-muted" />
                              {vm.user.username}
                            </div>
                          </td>
                          <td>{getStatusBadge(vm.status)}</td>
                          <td>
                            {vm.ipAddress ? (
                              <code className="small">{vm.ipAddress}</code>
                            ) : (
                              <span className="text-muted small">N/A</span>
                            )}
                          </td>
                          <td>
                            <div className="d-flex gap-1">
                              {vm.guacamoleUrl && (
                                <Button
                                  variant="outline-primary"
                                  size="sm"
                                  onClick={() => window.open(vm.guacamoleUrl, '_blank')}
                                  title="Open Remote Desktop"
                                >
                                  <FontAwesomeIcon icon={faDesktop} />
                                </Button>
                              )}
                              {vm.status === 'running' && (
                                <Button
                                  variant="outline-danger"
                                  size="sm"
                                  onClick={() => {
                                    setVmToStop(vm);
                                    setShowStopModal(true);
                                  }}
                                  title="Stop VM"
                                >
                                  <FontAwesomeIcon icon={faStop} />
                                </Button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                </div>
              ) : (
                <div className="text-center py-4">
                  <FontAwesomeIcon icon={faServer} size="2x" className="text-muted mb-2" />
                  <p className="text-muted mb-0 small">No active VMs</p>
                </div>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>
      
      <Row className="mb-4">
        <Col md={12}>
          <Card className="shadow-sm h-100">
            <Card.Header className="bg-info text-white d-flex justify-content-between align-items-center">
              <h5 className="mb-0">System Status</h5>
              <Button 
                variant="dark"
                size="sm" 
                onClick={handleCheckServices} 
                disabled={loading}
              >
                {loading ? (
                  <>
                    <Spinner as="span" size="sm" animation="border" className="me-1" />
                    Checking...
                  </>
                ) : 'Check Status'}
              </Button>
            </Card.Header>
            <Card.Body>
              {error ? (
                <Alert variant="danger">{error}</Alert>
              ) : (
                <>
                  <p className="mb-2">
                    <strong>Server Status:</strong> {status?.server === 'Online' ? 
                      <span className="text-success">Online</span> : 
                      <span className="text-danger">Offline</span>}
                  </p>
                  <p className="mb-2">
                    <strong>Proxmox Connection:</strong> {status?.proxmox === 'Connected' ? 
                      <span className="text-success">Connected</span> : 
                      <span className="text-danger">Disconnected</span>}
                  </p>
                  <p className="mb-2">
                    <strong>Guacamole Connection:</strong> {status?.guacamole === 'Connected' ? 
                      <span className="text-success">Connected</span> : 
                      <span className="text-danger">Disconnected</span>}
                  </p>
                  <p className="mb-0">
                    <strong>Database Status:</strong> {status?.database === 'Connected' ? 
                      <span className="text-success">Connected</span> : 
                      <span className="text-danger">Disconnected</span>}
                  </p>
                </>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Stop VM Confirmation Modal */}
      <Modal show={showStopModal} onHide={() => setShowStopModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Stop Virtual Machine</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="d-flex align-items-center mb-3">
            <FontAwesomeIcon icon={faExclamationTriangle} className="text-warning me-3" size="2x" />
            <div>
              <h6>Are you sure you want to stop this VM?</h6>
              <p className="mb-0 text-muted">
                This will terminate the lab session for the user. This action cannot be undone.
              </p>
            </div>
          </div>
          
          {vmToStop && (
            <div className="bg-light p-3 rounded">
              <div className="row">
                <div className="col-sm-4"><strong>VM ID:</strong></div>
                <div className="col-sm-8"><code>{vmToStop.vmId}</code></div>
              </div>
              <div className="row">
                <div className="col-sm-4"><strong>User:</strong></div>
                <div className="col-sm-8">{vmToStop.user.username}</div>
              </div>
              <div className="row">
                <div className="col-sm-4"><strong>Lab ID:</strong></div>
                <div className="col-sm-8">{vmToStop.labId}</div>
              </div>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowStopModal(false)} disabled={stoppingVm}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleStopVM} disabled={stoppingVm}>
            {stoppingVm ? (
              <>
                <Spinner as="span" animation="border" size="sm" className="me-2" />
                Stopping...
              </>
            ) : (
              <>
                <FontAwesomeIcon icon={faStop} className="me-2" />
                Stop VM
              </>
            )}
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

// System Status Card
const SystemStatus = () => {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await axios.get('/status');
        setStatus(res.data);
      } catch (err) {
        setError('Failed to fetch system status');
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
  }, []);

  const handleCheckServices = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get('/status');
      setStatus(res.data);
    } catch (err) {
      setError('Failed to fetch system status');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="mb-4">
      <Card.Header>System Status</Card.Header>
      <Card.Body>
        <div className="d-flex justify-content-between align-items-center mb-2">
          <div><strong>System Status</strong></div>
          <Button size="sm" variant="outline-primary" onClick={handleCheckServices} disabled={loading}>
            {loading ? <Spinner animation="border" size="sm" /> : 'Check Services'}
          </Button>
        </div>
        {loading ? (
          <Spinner animation="border" size="sm" />
        ) : error ? (
          <Alert variant="danger">{error}</Alert>
        ) : (
          <>
            <p>Server Status: {status?.server === 'Online' ? <span style={{color: 'green'}}>Online</span> : <span style={{color: 'red'}}>Offline</span>}</p>
            <p>Database Status: {status?.database === 'Connected' ? <span style={{color: 'green'}}>Connected</span> : <span style={{color: 'red'}}>Not Connected</span>}</p>
            <p>Proxmox Connection: {status?.proxmox === 'Connected' ? <span style={{color: 'green'}}>Connected</span> : <span style={{color: 'red'}}>Not Connected</span>}</p>
            <p>Guacamole Connection: {status?.guacamole === 'Connected' ? <span style={{color: 'green'}}>Connected</span> : <span style={{color: 'red'}}>Not Connected</span>}</p>
          </>
        )}
      </Card.Body>
    </Card>
  );
};

export default AdminDashboard;