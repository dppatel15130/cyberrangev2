import { useState, useEffect, useContext } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Container, Row, Col, Card, Button, Badge, Alert, Spinner, ProgressBar, ListGroup, Tab, Tabs } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFlask, faInfoCircle, faExclamationTriangle, faTrophy, faShield, faFire, faUsers, faFlag, faDesktop, faClock, faChartLine, faPlay, faRocket, faGlobe, faCog, faLightbulb, faCode } from '@fortawesome/free-solid-svg-icons';
import axios from '../utils/axiosConfig';
import { AuthContext } from '../context/AuthContext';

const Dashboard = () => {
  const [labs, setLabs] = useState([]);
  const [webLabs, setWebLabs] = useState([]);
  const [matches, setMatches] = useState([]);
  const [userTeams, setUserTeams] = useState([]);
  const [userStats, setUserStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  
  const { user, isAdmin } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        
        // Fetch user stats and basic lab data
        const [labsRes, userStatsRes] = await Promise.all([
          axios.get('/labs'),
          axios.get('/flags/user-stats').catch(() => ({ data: { user: { totalPoints: 0 } } }))
        ]);
        
        const labsData = Array.isArray(labsRes.data) ? labsRes.data : [];
        setLabs(labsData);
        setUserStats(userStatsRes.data.user || { totalPoints: 0 });

        // Fetch additional data
        try {
          // Web labs
          const webLabsRes = await axios.get('/weblabs').catch(() => ({ data: [] }));
          setWebLabs(Array.isArray(webLabsRes.data) ? webLabsRes.data : []);

          // Active matches
          const matchesRes = await axios.get('/matches?status=waiting').catch(() => ({ data: { matches: [] } }));
          setMatches(matchesRes.data.matches || []);

          // User teams
          const teamsRes = await axios.get('/teams').catch(() => ({ data: { teams: [] } }));
          setUserTeams(teamsRes.data.teams || []);
        } catch (err) {
          console.warn('Some dashboard data could not be loaded:', err);
        }
        
        setLoading(false);
      } catch (err) {
        console.error('Error fetching dashboard data:', err);
        setError('Failed to load dashboard. Please try again later.');
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, [isAdmin]);

  const getDifficultyBadge = (difficulty) => {
    switch (difficulty) {
      case 'beginner':
        return <Badge bg="success" className="fw-bold">Beginner</Badge>;
      case 'intermediate':
        return <Badge bg="warning" className="fw-bold">Intermediate</Badge>;
      case 'advanced':
        return <Badge bg="danger" className="fw-bold">Advanced</Badge>;
      default:
        return <Badge bg="secondary" className="fw-bold">{difficulty}</Badge>;
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return <Badge bg="success" className="fw-bold">Active</Badge>;
      case 'waiting':
        return <Badge bg="warning" className="fw-bold">Waiting</Badge>;
      case 'finished':
        return <Badge bg="secondary" className="fw-bold">Finished</Badge>;
      default:
        return <Badge bg="info" className="fw-bold">{status}</Badge>;
    }
  };



  if (loading) {
    return (
      <Container className="py-5">
        <div className="loading-container">
        <Spinner animation="border" variant="primary" />
          <p className="mt-3 text-accent">Loading your cyber range dashboard...</p>
        </div>
      </Container>
    );
  }

  return (
    <Container fluid className="py-4">
      {/* Welcome Header */}
      <Row className="mb-4">
        <Col>
          <div className="text-center mb-4">
            <h1 className="display-4 fw-bold text-accent mb-3">
              <FontAwesomeIcon icon={faShield} className="me-3" />
              CyberRange Platform
        </h1>
            <p className="lead text-secondary mb-0">
              Welcome back, <span className="text-accent fw-bold">{user?.username}</span>! 
              Ready to enhance your cybersecurity skills?
            </p>
      </div>
        </Col>
      </Row>

      {/* Quick Stats */}
      <Row className="mb-4">
        <Col md={3} sm={6} className="mb-3">
          <Card className="h-100 border-0 bg-gradient text-center">
            <Card.Body className="d-flex flex-column justify-content-center">
              <FontAwesomeIcon icon={faTrophy} size="2x" className="text-warning mb-2" />
              <h3 className="fw-bold mb-1">{userStats.totalPoints || 0}</h3>
              <small className="text-muted">Total Points</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3} sm={6} className="mb-3">
          <Card className="h-100 border-0 bg-gradient text-center">
            <Card.Body className="d-flex flex-column justify-content-center">
              <FontAwesomeIcon icon={faFlask} size="2x" className="text-success mb-2" />
              <h3 className="fw-bold mb-1">{labs.length}</h3>
              <small className="text-muted">Available Labs</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3} sm={6} className="mb-3">
          <Card className="h-100 border-0 bg-gradient text-center">
            <Card.Body className="d-flex flex-column justify-content-center">
              <FontAwesomeIcon icon={faUsers} size="2x" className="text-info mb-2" />
              <h3 className="fw-bold mb-1">{userTeams.length}</h3>
              <small className="text-muted">My Teams</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3} sm={6} className="mb-3">
          <Card className="h-100 border-0 bg-gradient text-center">
            <Card.Body className="d-flex flex-column justify-content-center">
              <FontAwesomeIcon icon={faFire} size="2x" className="text-danger mb-2" />
              <h3 className="fw-bold mb-1">{matches.length}</h3>
              <small className="text-muted">Active Matches</small>
            </Card.Body>
          </Card>
        </Col>
      </Row>


      {error && (
        <Alert variant="danger" className="mb-4">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      {/* Quick Actions */}
      <Row className="mb-4">
        <Col lg={4} className="mb-4">
          <Card className="h-100">
            <Card.Header className="text-center">
              <FontAwesomeIcon icon={faRocket} className="me-2" />
              Quick Actions
            </Card.Header>
            <Card.Body>
              <div className="d-grid gap-3">
                <Button 
                  variant="outline-primary" 
                  size="lg" 
                  onClick={() => navigate('/cyberwar/lobby')}
                  className="d-flex align-items-center justify-content-center"
                >
                  <FontAwesomeIcon icon={faFire} className="me-2" />
                  Join Cyber Warfare
                </Button>
                
                <Button 
                  variant="outline-success" 
                  size="lg"
                  onClick={() => navigate('/cyberwar/teams/new')}
                  className="d-flex align-items-center justify-content-center"
                >
                  <FontAwesomeIcon icon={faUsers} className="me-2" />
                  Create Team
                </Button>
                
                {isAdmin() && (
                  <Button 
                    variant="outline-warning" 
                    size="lg"
                    onClick={() => navigate('/admin')}
                    className="d-flex align-items-center justify-content-center"
                  >
                    <FontAwesomeIcon icon={faCog} className="me-2" />
                    Admin Panel
                  </Button>
                )}
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col lg={8} className="mb-4">
          <Card className="h-100">
            <Card.Header>
              <FontAwesomeIcon icon={faFlask} className="me-2" />
              Available Labs
            </Card.Header>
                <Card.Body>
              {labs.length > 0 ? (
                <Row>
                  {labs.slice(0, 6).map((lab) => (
                    <Col md={6} key={lab.id || lab._id} className="mb-3">
                      <Card className="border-secondary h-100">
                        <Card.Body className="p-3">
                          <div className="d-flex justify-content-between align-items-start mb-2">
                            <h6 className="mb-0">{lab.name}</h6>
                    {getDifficultyBadge(lab.difficulty)}
                  </div>
                          <p className="text-muted small mb-3">
                            {lab.description?.length > 80
                              ? `${lab.description.substring(0, 80)}...`
                      : lab.description}
                          </p>
                          <div className="d-flex justify-content-between align-items-center">
                            <small className="text-muted">
                              <FontAwesomeIcon icon={faDesktop} className="me-1" />
                              {lab.category || 'General'}
                            </small>
                  <Button
                    as={Link}
                    to={`/labs/${lab.id || lab._id}`}
                              variant="outline-primary" 
                              size="sm"
                  >
                              <FontAwesomeIcon icon={faPlay} className="me-1" />
                              Start
                  </Button>
                          </div>
                        </Card.Body>
              </Card>
            </Col>
          ))}
        </Row>
              ) : (
                <Alert variant="info">
                  <FontAwesomeIcon icon={faInfoCircle} className="me-2" />
                  No labs available at the moment. Check back later!
                </Alert>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Platform Activity */}
      <Row>
        <Col md={6} className="mb-4">
          <Card>
            <Card.Header>
              <FontAwesomeIcon icon={faFire} className="me-2" />
              Active Matches
            </Card.Header>
            <Card.Body>
              {matches.length > 0 ? (
                <ListGroup variant="flush">
                  {matches.slice(0, 3).map((match) => (
                    <ListGroup.Item key={match.id} className="d-flex justify-content-between align-items-center bg-transparent border-secondary">
                      <div>
                        <div className="fw-bold">{match.name}</div>
                        <small className="text-muted">{match.teams?.length || 0} teams</small>
                      </div>
                      {getStatusBadge(match.status)}
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              ) : (
                <p className="text-muted">No active matches</p>
              )}
              
              <div className="mt-3 d-grid">
                <Button variant="primary" as={Link} to="/cyberwar/lobby">
                  <FontAwesomeIcon icon={faFire} className="me-2" />
                  Enter Cyber Warfare
                </Button>
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col md={6} className="mb-4">
          <Card>
            <Card.Header>
              <FontAwesomeIcon icon={faUsers} className="me-2" />
              My Teams
            </Card.Header>
            <Card.Body>
              {userTeams.length > 0 ? (
                <ListGroup variant="flush">
                  {userTeams.slice(0, 3).map((team) => (
                    <ListGroup.Item key={team.id} className="d-flex justify-content-between align-items-center bg-transparent border-secondary">
                      <div>
                        <div className="fw-bold">{team.name}</div>
                        <small className="text-muted">{team.members?.length || 0} members</small>
                      </div>
                      <Badge bg="info">{team.currentPoints || 0} pts</Badge>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              ) : (
                <p className="text-muted">No teams joined</p>
              )}
              
              <div className="mt-3 d-grid">
                <Button variant="outline-success" as={Link} to="/cyberwar/teams/new">
                  <FontAwesomeIcon icon={faUsers} className="me-2" />
                  Create Team
                </Button>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default Dashboard;