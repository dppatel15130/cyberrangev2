import React, { useState, useEffect, useContext } from 'react';
import { 
  Container, 
  Row, 
  Col, 
  Card, 
  Button, 
  Badge, 
  Table,
  Modal,
  Form,
  Tab,
  Tabs,
  Alert,
  Spinner,
  ProgressBar,
  ListGroup,
  ButtonGroup
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faFire, 
  faUsers, 
  faTrophy, 
  faPlay, 
  faStop,
  faClock,
  faChartLine,
  faShieldAlt,
  faBug,
  faNetworkWired,
  faServer,
  faEye,
  faEdit,
  faTrash,
  faPlus,
  faDownload,
  faRefresh,
  faExclamationTriangle,
  faCheckCircle,
  faTimes,
  faDesktop,
  faTerminal,
  faRocket
} from '@fortawesome/free-solid-svg-icons';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { AuthContext } from '../../context/AuthContext';
import cyberwarService from '../../services/cyberwarService';
import useWebSocket from '../../hooks/useWebSocket';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const CyberWarAdminDashboard = () => {
  const { user } = useContext(AuthContext);
  
  // State management
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Dashboard data
  const [dashboardData, setDashboardData] = useState({
    totalMatches: 0,
    activeMatches: 0,
    totalTeams: 0,
    totalUsers: 0,
    totalVulnerabilities: 0,
    activeVMs: 0
  });
  
  // Real-time data
  const [activeMatches, setActiveMatches] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [systemStatus, setSystemStatus] = useState({});
  const [vulnerabilityStats, setVulnerabilityStats] = useState({});
  
  // Modals
  const [showCreateMatch, setShowCreateMatch] = useState(false);
  const [showVMManager, setShowVMManager] = useState(false);
  const [selectedMatch, setSelectedMatch] = useState(null);
  
  // Form data
  const [newMatch, setNewMatch] = useState({
    name: '',
    description: '',
    matchType: 'attack_defend',
    duration: 120,
    maxTeams: 4,
    packetCaptureEnabled: true,
    autoScoring: true
  });

  // WebSocket for real-time updates
  const wsUrl = `ws://localhost:5000/ws/scoring`;
  const { lastMessage, isConnected, sendMessage } = useWebSocket(wsUrl, {
    onMessage: (data) => {
      handleWebSocketMessage(data);
    }
  });

  useEffect(() => {
    fetchDashboardData();
    fetchSystemStatus();
    
    // Set up periodic refresh
    const interval = setInterval(() => {
      fetchDashboardData();
      fetchSystemStatus();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  // Handle WebSocket messages
  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'scoring_event':
        setRecentEvents(prev => [data.event, ...prev.slice(0, 19)]);
        break;
      case 'match_started':
      case 'match_ended':
        fetchDashboardData();
        break;
      case 'system_status':
        setSystemStatus(data.status);
        break;
      case 'vulnerability_detected':
        updateVulnerabilityStats(data);
        break;
    }
  };

  // Fetch dashboard overview data
  const fetchDashboardData = async () => {
    try {
      const [matches, teams, events, vulnStats] = await Promise.all([
        cyberwarService.getMatches(),
        cyberwarService.getTeams(),
        cyberwarService.getRecentScoringEvents(),
        cyberwarService.getVulnerabilityStats()
      ]);

      setActiveMatches(matches.filter(m => ['active', 'waiting'].includes(m.status)));
      setRecentEvents(events);
      setVulnerabilityStats(vulnStats);
      
      setDashboardData({
        totalMatches: matches.length,
        activeMatches: matches.filter(m => m.status === 'active').length,
        totalTeams: teams.length,
        totalUsers: teams.reduce((sum, team) => sum + (team.memberCount || 0), 0),
        totalVulnerabilities: vulnStats.totalVulnerabilities || 0,
        activeVMs: vulnStats.activeVMs || 0
      });

      setLoading(false);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError('Failed to load dashboard data');
      setLoading(false);
    }
  };

  // Fetch system status
  const fetchSystemStatus = async () => {
    try {
      const status = await cyberwarService.getSystemStatus();
      setSystemStatus(status);
    } catch (error) {
      console.error('Error fetching system status:', error);
    }
  };

  // Update vulnerability statistics
  const updateVulnerabilityStats = (data) => {
    setVulnerabilityStats(prev => ({
      ...prev,
      recentDetections: [data, ...(prev.recentDetections || []).slice(0, 9)]
    }));
  };

  // Create new match
  const handleCreateMatch = async () => {
    try {
      await cyberwarService.createMatch(newMatch);
      setShowCreateMatch(false);
      setNewMatch({
        name: '',
        description: '',
        matchType: 'attack_defend',
        duration: 120,
        maxTeams: 4,
        packetCaptureEnabled: true,
        autoScoring: true
      });
      fetchDashboardData();
    } catch (error) {
      console.error('Error creating match:', error);
    }
  };

  // Start/Stop match
  const handleMatchAction = async (matchId, action) => {
    try {
      if (action === 'start') {
        await cyberwarService.startMatch(matchId);
      } else if (action === 'stop') {
        await cyberwarService.stopMatch(matchId);
      }
      fetchDashboardData();
    } catch (error) {
      console.error(`Error ${action}ing match:`, error);
    }
  };

  // Chart configurations
  const scoringTrendData = {
    labels: recentEvents.slice(0, 10).reverse().map((_, i) => `Event ${i + 1}`),
    datasets: [
      {
        label: 'Points Awarded',
        data: recentEvents.slice(0, 10).reverse().map(e => e.points || 0),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        fill: true,
        tension: 0.4
      }
    ]
  };

  const vulnerabilityTypeData = {
    labels: Object.keys(vulnerabilityStats.byType || {}),
    datasets: [
      {
        data: Object.values(vulnerabilityStats.byType || {}),
        backgroundColor: [
          'rgba(255, 99, 132, 0.8)',
          'rgba(54, 162, 235, 0.8)',
          'rgba(255, 205, 86, 0.8)',
          'rgba(75, 192, 192, 0.8)',
          'rgba(153, 102, 255, 0.8)',
          'rgba(255, 159, 64, 0.8)'
        ]
      }
    ]
  };

  const teamPerformanceData = {
    labels: vulnerabilityStats.topTeams?.map(t => t.name) || [],
    datasets: [
      {
        label: 'Vulnerabilities Found',
        data: vulnerabilityStats.topTeams?.map(t => t.vulnerabilityCount) || [],
        backgroundColor: 'rgba(54, 162, 235, 0.8)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1
      }
    ]
  };

  if (loading) {
    return (
      <Container className="d-flex justify-content-center align-items-center" style={{minHeight: '60vh'}}>
        <Spinner animation="border" variant="primary" />
        <span className="ms-2">Loading admin dashboard...</span>
      </Container>
    );
  }

  return (
    <Container fluid className="p-4">
      <Row className="mb-4">
        <Col>
          <h2>
            <FontAwesomeIcon icon={faShieldAlt} className="me-2 text-danger" />
            Cyber Warfare Admin Dashboard
          </h2>
          <p className="text-muted">Real-time monitoring and management of cyber warfare competitions</p>
        </Col>
        <Col xs="auto">
          <ButtonGroup>
            <Button variant="primary" onClick={() => setShowCreateMatch(true)}>
              <FontAwesomeIcon icon={faPlus} className="me-1" />
              Create Match
            </Button>
            <Button variant="outline-primary" onClick={() => setShowVMManager(true)}>
              <FontAwesomeIcon icon={faServer} className="me-1" />
              VM Manager
            </Button>
            <Button variant="outline-secondary" onClick={fetchDashboardData}>
              <FontAwesomeIcon icon={faRefresh} className="me-1" />
              Refresh
            </Button>
          </ButtonGroup>
        </Col>
      </Row>

      {/* WebSocket Connection Status */}
      <Row className="mb-3">
        <Col>
          <Alert variant={isConnected ? 'success' : 'warning'} className="py-2">
            <FontAwesomeIcon icon={isConnected ? faCheckCircle : faExclamationTriangle} className="me-2" />
            Real-time connection: {isConnected ? 'Connected' : 'Disconnected'}
            {!isConnected && <span className="ms-2">Some features may not update automatically</span>}
          </Alert>
        </Col>
      </Row>

      {/* Quick Stats */}
      <Row className="mb-4">
        <Col md={3}>
          <Card className="text-center h-100 border-primary">
            <Card.Body>
              <FontAwesomeIcon icon={faFire} size="2x" className="text-primary mb-2" />
              <h3 className="mb-1">{dashboardData.activeMatches}</h3>
              <small className="text-muted">Active Matches</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="text-center h-100 border-info">
            <Card.Body>
              <FontAwesomeIcon icon={faUsers} size="2x" className="text-info mb-2" />
              <h3 className="mb-1">{dashboardData.totalTeams}</h3>
              <small className="text-muted">Teams Competing</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="text-center h-100 border-warning">
            <Card.Body>
              <FontAwesomeIcon icon={faBug} size="2x" className="text-warning mb-2" />
              <h3 className="mb-1">{dashboardData.totalVulnerabilities}</h3>
              <small className="text-muted">Vulnerabilities Found</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="text-center h-100 border-success">
            <Card.Body>
              <FontAwesomeIcon icon={faServer} size="2x" className="text-success mb-2" />
              <h3 className="mb-1">{dashboardData.activeVMs}</h3>
              <small className="text-muted">Active VMs</small>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Main Dashboard Tabs */}
      <Tabs activeKey={activeTab} onSelect={setActiveTab} className="mb-4">
        
        {/* Overview Tab */}
        <Tab eventKey="overview" title={
          <span><FontAwesomeIcon icon={faChartLine} className="me-1" />Overview</span>
        }>
          <Row>
            <Col lg={8}>
              <Card className="mb-4">
                <Card.Header>
                  <h5><FontAwesomeIcon icon={faChartLine} className="me-2" />Scoring Trends</h5>
                </Card.Header>
                <Card.Body>
                  <Line 
                    data={scoringTrendData} 
                    options={{
                      responsive: true,
                      plugins: {
                        legend: { position: 'top' },
                        title: { display: true, text: 'Recent Scoring Activity' }
                      },
                      scales: {
                        y: { beginAtZero: true }
                      }
                    }}
                  />
                </Card.Body>
              </Card>

              <Card>
                <Card.Header>
                  <h5><FontAwesomeIcon icon={faBug} className="me-2" />Vulnerability Detection by Type</h5>
                </Card.Header>
                <Card.Body>
                  <Doughnut 
                    data={vulnerabilityTypeData}
                    options={{
                      responsive: true,
                      plugins: {
                        legend: { position: 'right' }
                      }
                    }}
                  />
                </Card.Body>
              </Card>
            </Col>

            <Col lg={4}>
              <Card className="mb-4">
                <Card.Header>
                  <h5><FontAwesomeIcon icon={faNetworkWired} className="me-2" />System Status</h5>
                </Card.Header>
                <Card.Body>
                  <ListGroup variant="flush">
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      <span>Database</span>
                      <Badge bg={systemStatus.database === 'Connected' ? 'success' : 'danger'}>
                        {systemStatus.database || 'Unknown'}
                      </Badge>
                    </ListGroup.Item>
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      <span>Proxmox API</span>
                      <Badge bg={systemStatus.proxmox === 'Connected' ? 'success' : 'danger'}>
                        {systemStatus.proxmox || 'Unknown'}
                      </Badge>
                    </ListGroup.Item>
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      <span>Guacamole</span>
                      <Badge bg={systemStatus.guacamole === 'Connected' ? 'success' : 'danger'}>
                        {systemStatus.guacamole || 'Unknown'}
                      </Badge>
                    </ListGroup.Item>
                    <ListGroup.Item className="d-flex justify-content-between align-items-center">
                      <span>ELK Stack</span>
                      <Badge bg={systemStatus.elk === 'Connected' ? 'success' : 'warning'}>
                        {systemStatus.elk || 'Optional'}
                      </Badge>
                    </ListGroup.Item>
                  </ListGroup>
                </Card.Body>
              </Card>

              <Card>
                <Card.Header>
                  <h5><FontAwesomeIcon icon={faTrophy} className="me-2" />Recent Events</h5>
                </Card.Header>
                <Card.Body style={{maxHeight: '400px', overflowY: 'auto'}}>
                  {recentEvents.length > 0 ? (
                    <ListGroup variant="flush">
                      {recentEvents.slice(0, 10).map((event, index) => (
                        <ListGroup.Item key={index} className="px-0">
                          <div className="d-flex justify-content-between align-items-start">
                            <div>
                              <small className="text-muted">
                                {new Date(event.timestamp).toLocaleTimeString()}
                              </small>
                              <div>{event.description}</div>
                              <small className="text-primary">Team: {event.teamName}</small>
                            </div>
                            <Badge bg="success">+{event.points}</Badge>
                          </div>
                        </ListGroup.Item>
                      ))}
                    </ListGroup>
                  ) : (
                    <p className="text-muted text-center">No recent events</p>
                  )}
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>

        {/* Active Matches Tab */}
        <Tab eventKey="matches" title={
          <span><FontAwesomeIcon icon={faFire} className="me-1" />Active Matches</span>
        }>
          <Row>
            {activeMatches.map(match => (
              <Col lg={6} key={match.id} className="mb-4">
                <Card className="h-100">
                  <Card.Header className="d-flex justify-content-between align-items-center">
                    <h6 className="mb-0">{match.name}</h6>
                    <Badge bg={match.status === 'active' ? 'success' : 'warning'}>
                      {match.status}
                    </Badge>
                  </Card.Header>
                  <Card.Body>
                    <p className="text-muted small">{match.description}</p>
                    
                    <Row className="mb-3">
                      <Col xs={6}>
                        <strong>Teams:</strong> {match.currentTeams}/{match.maxTeams}
                      </Col>
                      <Col xs={6}>
                        <strong>Type:</strong> {match.matchType}
                      </Col>
                    </Row>

                    {match.status === 'active' && match.timeRemaining && (
                      <div className="mb-3">
                        <div className="d-flex justify-content-between align-items-center mb-1">
                          <small>Time Remaining</small>
                          <small>{Math.floor(match.timeRemaining / 60)}:{(match.timeRemaining % 60).toString().padStart(2, '0')}</small>
                        </div>
                        <ProgressBar 
                          now={(match.timeRemaining / match.duration) * 100} 
                          variant="info"
                          size="sm"
                        />
                      </div>
                    )}

                    <div className="d-flex gap-2">
                      {match.status === 'waiting' && (
                        <Button 
                          size="sm" 
                          variant="success"
                          onClick={() => handleMatchAction(match.id, 'start')}
                        >
                          <FontAwesomeIcon icon={faPlay} className="me-1" />
                          Start
                        </Button>
                      )}
                      {match.status === 'active' && (
                        <Button 
                          size="sm" 
                          variant="danger"
                          onClick={() => handleMatchAction(match.id, 'stop')}
                        >
                          <FontAwesomeIcon icon={faStop} className="me-1" />
                          Stop
                        </Button>
                      )}
                      <Button 
                        size="sm" 
                        variant="outline-primary"
                        onClick={() => window.open(`/match/${match.id}`, '_blank')}
                      >
                        <FontAwesomeIcon icon={faEye} className="me-1" />
                        View
                      </Button>
                    </div>
                  </Card.Body>
                </Card>
              </Col>
            ))}
          </Row>
        </Tab>

        {/* Analytics Tab */}
        <Tab eventKey="analytics" title={
          <span><FontAwesomeIcon icon={faChartLine} className="me-1" />Analytics</span>
        }>
          <Row>
            <Col lg={6} className="mb-4">
              <Card>
                <Card.Header>
                  <h5>Team Performance</h5>
                </Card.Header>
                <Card.Body>
                  <Bar 
                    data={teamPerformanceData}
                    options={{
                      responsive: true,
                      plugins: {
                        legend: { display: false }
                      },
                      scales: {
                        y: { beginAtZero: true }
                      }
                    }}
                  />
                </Card.Body>
              </Card>
            </Col>
            <Col lg={6} className="mb-4">
              <Card>
                <Card.Header>
                  <h5>Vulnerability Statistics</h5>
                </Card.Header>
                <Card.Body>
                  <Table striped size="sm">
                    <thead>
                      <tr>
                        <th>Vulnerability</th>
                        <th>Found By</th>
                        <th>Points</th>
                        <th>First Blood</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(vulnerabilityStats.recentDetections || []).map((vuln, index) => (
                        <tr key={index}>
                          <td>{vuln.name}</td>
                          <td>{vuln.teamName}</td>
                          <td>{vuln.points}</td>
                          <td>
                            {vuln.firstBlood && <Badge bg="warning">First!</Badge>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>

      </Tabs>

      {/* Create Match Modal */}
      <Modal show={showCreateMatch} onHide={() => setShowCreateMatch(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Create New Match</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form>
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Match Name</Form.Label>
                  <Form.Control
                    type="text"
                    value={newMatch.name}
                    onChange={(e) => setNewMatch({...newMatch, name: e.target.value})}
                    placeholder="Enter match name"
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Match Type</Form.Label>
                  <Form.Select
                    value={newMatch.matchType}
                    onChange={(e) => setNewMatch({...newMatch, matchType: e.target.value})}
                  >
                    <option value="attack_defend">Attack vs Defense</option>
                    <option value="capture_flag">Capture the Flag</option>
                    <option value="red_vs_blue">Red vs Blue Team</option>
                    <option value="free_for_all">Free for All</option>
                  </Form.Select>
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
                placeholder="Describe the match objectives and rules"
              />
            </Form.Group>

            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Duration (minutes)</Form.Label>
                  <Form.Control
                    type="number"
                    value={newMatch.duration}
                    onChange={(e) => setNewMatch({...newMatch, duration: parseInt(e.target.value)})}
                    min="10"
                    max="480"
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Max Teams</Form.Label>
                  <Form.Control
                    type="number"
                    value={newMatch.maxTeams}
                    onChange={(e) => setNewMatch({...newMatch, maxTeams: parseInt(e.target.value)})}
                    min="2"
                    max="8"
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row>
              <Col md={6}>
                <Form.Check
                  type="checkbox"
                  label="Enable Packet Capture"
                  checked={newMatch.packetCaptureEnabled}
                  onChange={(e) => setNewMatch({...newMatch, packetCaptureEnabled: e.target.checked})}
                />
              </Col>
              <Col md={6}>
                <Form.Check
                  type="checkbox"
                  label="Enable Auto Scoring"
                  checked={newMatch.autoScoring}
                  onChange={(e) => setNewMatch({...newMatch, autoScoring: e.target.checked})}
                />
              </Col>
            </Row>
          </Form>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowCreateMatch(false)}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleCreateMatch}>
            <FontAwesomeIcon icon={faRocket} className="me-1" />
            Create Match
          </Button>
        </Modal.Footer>
      </Modal>

    </Container>
  );
};

export default CyberWarAdminDashboard;
