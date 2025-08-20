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
  Tabs
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faFire, 
  faUsers, 
  faTrophy, 
  faPlay, 
  faStop,
  faClock,
  faPlus,
  faEye,
  faChartLine,
  faExclamationTriangle
} from '@fortawesome/free-solid-svg-icons';
import { AuthContext } from '../../context/AuthContext';
import cyberwarService from '../../services/cyberwarService';
import useWebSocket from '../../hooks/useWebSocket';

const MatchLobby = () => {
  const { user } = useContext(AuthContext);
  const navigate = useNavigate();
  
  // State management
  const [activeMatches, setActiveMatches] = useState([]);
  const [upcomingMatches, setUpcomingMatches] = useState([]);
  const [userTeams, setUserTeams] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [showJoinTeam, setShowJoinTeam] = useState(false);
  const [availableTeams, setAvailableTeams] = useState([]);
  const [newTeamData, setNewTeamData] = useState({
    name: '',
    description: '',
    color: '#007bff',
    maxMembers: 4
  });
  const [joinTeamData, setJoinTeamData] = useState({
    teamId: '',
    inviteCode: ''
  });
  const [selectedMatchForJoin, setSelectedMatchForJoin] = useState(null);
  const [showTeamSelection, setShowTeamSelection] = useState(false);

  // WebSocket for real-time updates
  const wsUrl = `ws://localhost:5000/ws/scoring`;
  const { lastMessage, isConnected } = useWebSocket(wsUrl, {
    onMessage: (data) => {
      if (data.type === 'match_started' || data.type === 'match_ended') {
        fetchMatches(); // Refresh matches on status change
      }
    }
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [activeRes, allMatches, teamsRes] = await Promise.all([
        cyberwarService.getActiveMatches(),
        cyberwarService.getMatches({ status: 'waiting' }),
        cyberwarService.getTeams({ search: '', status: 'active' })
      ]);
      
      setActiveMatches(activeRes || []);
      setUpcomingMatches(allMatches.matches || []);
      
      // Filter teams where user is a member
      const userTeamsList = (teamsRes.teams || []).filter(team => 
        team.members && team.members.some(member => member.id === user.id)
      );
      setUserTeams(userTeamsList);
      
    } catch (err) {
      console.error('Failed to fetch lobby data:', err);
      setError('Failed to load lobby data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const fetchMatches = async () => {
    try {
      const [activeRes, upcomingRes] = await Promise.all([
        cyberwarService.getActiveMatches(),
        cyberwarService.getMatches({ status: 'waiting' })
      ]);
      setActiveMatches(activeRes || []);
      setUpcomingMatches(upcomingRes.matches || []);
    } catch (err) {
      console.error('Failed to refresh matches:', err);
    }
  };

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    try {
      await cyberwarService.createTeam(newTeamData);
      setShowCreateTeam(false);
      setNewTeamData({ name: '', description: '', color: '#007bff', maxMembers: 4 });
      fetchData(); // Refresh data
    } catch (err) {
      console.error('Failed to create team:', err);
      
      // Check if it's a team name already exists error
      if (err.error && err.error.includes('already exists')) {
        setError(`Team name "${newTeamData.name}" already exists. You can either:
          • Try a different team name
          • Join the existing team using the "Join Existing Team" button
          • Contact an administrator if you believe this is an error`);
      } else {
        setError('Failed to create team. Please try again.');
      }
    }
  };

  const fetchAvailableTeams = async () => {
    try {
      const response = await cyberwarService.getTeams({ status: 'active' });
      setAvailableTeams(response.teams || []);
    } catch (err) {
      console.error('Failed to fetch available teams:', err);
      setError('Failed to load available teams.');
    }
  };

  const handleJoinTeam = async (e) => {
    e.preventDefault();
    try {
      await cyberwarService.joinTeam(joinTeamData.teamId, joinTeamData.inviteCode);
      setShowJoinTeam(false);
      setJoinTeamData({ teamId: '', inviteCode: '' });
      fetchData(); // Refresh data
    } catch (err) {
      console.error('Failed to join team:', err);
      setError('Failed to join team. Please try again.');
    }
  };

  const joinMatch = async (matchId) => {
    try {
      // Check if user has a team
      if (userTeams.length === 0) {
        setError('You need to be in a team to join matches. Please create or join a team first.');
        return;
      }

      // If user has multiple teams, show team selection
      if (userTeams.length > 1) {
        setSelectedMatchForJoin(matchId);
        setShowTeamSelection(true);
        return;
      }

      // If user has only one team, join with that team
      const teamId = userTeams[0].id;
      await cyberwarService.joinMatch(matchId, teamId);
      navigate(`/cyberwar/match/${matchId}`);
    } catch (err) {
      console.error('Failed to join match:', err);
      setError('Failed to join match. Please try again.');
    }
  };

  const viewMatch = (matchId) => {
    navigate(`/cyberwar/match/${matchId}/spectate`);
  };

  const getMatchStatusBadge = (match) => {
    switch (match.status) {
      case 'active':
        return <Badge bg="success"><FontAwesomeIcon icon={faPlay} className="me-1" />Active</Badge>;
      case 'waiting':
        return <Badge bg="warning"><FontAwesomeIcon icon={faClock} className="me-1" />Waiting</Badge>;
      case 'completed':
        return <Badge bg="secondary"><FontAwesomeIcon icon={faStop} className="me-1" />Completed</Badge>;
      default:
        return <Badge bg="info">{match.status}</Badge>;
    }
  };

  const formatDuration = (minutes) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" size="lg" />
        <p className="mt-3">Loading cyber-warfare lobby...</p>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      {/* Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h1 className="mb-0">
            <FontAwesomeIcon icon={faFire} className="me-2 text-danger" />
            Cyber-Warfare Lobby
          </h1>
          <p className="text-muted mt-1">
            Join team-based cyber-warfare matches in real-time
            {isConnected && (
              <Badge bg="success" className="ms-2">
                <span className="pulse-dot"></span>
                Live
              </Badge>
            )}
          </p>
        </div>
        <div>
          {userTeams.length === 0 && (
            <Button variant="outline-primary" onClick={() => setShowCreateTeam(true)}>
              <FontAwesomeIcon icon={faPlus} className="me-1" />
              Create Team
            </Button>
          )}
        </div>
      </div>

      {error && (
        <Alert variant="danger" dismissible onClose={() => setError(null)}>
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Row>
        <Col lg={8}>
          {/* Active Matches */}
          <Card className="mb-4">
            <Card.Header className="bg-success text-white">
              <FontAwesomeIcon icon={faPlay} className="me-2" />
              Active Matches ({activeMatches.length})
            </Card.Header>
            <Card.Body>
              {activeMatches.length === 0 ? (
                <div className="text-center py-4 text-muted">
                  <FontAwesomeIcon icon={faFire} size="3x" className="mb-3 opacity-25" />
                  <p>No active matches at the moment</p>
                  <small>Check back later or spectate completed matches</small>
                </div>
              ) : (
                <Row>
                  {activeMatches.map(match => (
                    <Col md={6} key={match.id} className="mb-3">
                      <Card className="border-success">
                        <Card.Body>
                          <div className="d-flex justify-content-between align-items-start mb-2">
                            <h6 className="mb-0">{match.name}</h6>
                            {getMatchStatusBadge(match)}
                          </div>
                          
                          <div className="mb-2">
                            <small className="text-muted">
                              <FontAwesomeIcon icon={faUsers} className="me-1" />
                              {match.teams?.length || 0} teams competing
                            </small>
                          </div>
                          
                          {match.duration && (
                            <div className="mb-2">
                              <small className="text-muted">
                                <FontAwesomeIcon icon={faClock} className="me-1" />
                                Duration: {formatDuration(match.duration)}
                              </small>
                            </div>
                          )}

                          <div className="d-grid gap-2 d-md-flex">
                            <Button 
                              size="sm" 
                              variant="outline-success"
                              onClick={() => viewMatch(match.id)}
                              className="flex-fill"
                            >
                              <FontAwesomeIcon icon={faEye} className="me-1" />
                              Spectate
                            </Button>
                            <Button 
                              size="sm" 
                              variant="outline-primary"
                              onClick={() => navigate(`/cyberwar/match/${match.id}/scoreboard`)}
                            >
                              <FontAwesomeIcon icon={faChartLine} className="me-1" />
                              Scoreboard
                            </Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
              )}
            </Card.Body>
          </Card>

          {/* Upcoming/Waiting Matches */}
          <Card>
            <Card.Header>
              <FontAwesomeIcon icon={faClock} className="me-2" />
              Waiting Matches ({upcomingMatches.length})
            </Card.Header>
            <Card.Body>
              {upcomingMatches.length === 0 ? (
                <div className="text-center py-4 text-muted">
                  <FontAwesomeIcon icon={faClock} size="3x" className="mb-3 opacity-25" />
                  <p>No waiting matches available</p>
                  <small>Matches appear here when teams are assigned</small>
                </div>
              ) : (
                <Row>
                  {upcomingMatches.map(match => (
                    <Col md={6} key={match.id} className="mb-3">
                      <Card className="border-warning">
                        <Card.Body>
                          <div className="d-flex justify-content-between align-items-start mb-2">
                            <h6 className="mb-0">{match.name}</h6>
                            {getMatchStatusBadge(match)}
                          </div>
                          
                          <p className="small text-muted mb-2">
                            {match.description}
                          </p>
                          
                          <div className="mb-2">
                            <small className="text-muted">
                              <FontAwesomeIcon icon={faUsers} className="me-1" />
                              {match.teams?.length || 0}/{match.maxTeams} teams
                            </small>
                          </div>

                          <div className="d-grid">
                            <Button 
                              size="sm" 
                              variant="warning"
                              onClick={() => joinMatch(match.id)}
                              disabled={userTeams.length === 0}
                            >
                              <FontAwesomeIcon icon={faPlay} className="me-1" />
                              {userTeams.length === 0 ? 'Need Team' : 'View Match'}
                            </Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
              )}
            </Card.Body>
          </Card>
        </Col>

        <Col lg={4}>
          {/* User Teams */}
          <Card className="mb-4">
            <Card.Header>
              <FontAwesomeIcon icon={faUsers} className="me-2" />
              My Teams ({userTeams.length})
            </Card.Header>
            <Card.Body>
              {userTeams.length === 0 ? (
                <div className="text-center py-3">
                  <p className="text-muted mb-3">You're not in any teams yet</p>
                  <div className="d-grid gap-2">
                    <Button variant="outline-primary" onClick={() => setShowCreateTeam(true)}>
                      <FontAwesomeIcon icon={faPlus} className="me-1" />
                      Create Team
                    </Button>
                    <Button variant="outline-secondary" onClick={() => setShowJoinTeam(true)}>
                      <FontAwesomeIcon icon={faUsers} className="me-1" />
                      Join Existing Team
                    </Button>
                  </div>
                </div>
              ) : (
                <ListGroup variant="flush">
                  {userTeams.map(team => (
                    <ListGroup.Item key={team.id} className="px-0">
                      <div className="d-flex justify-content-between align-items-center">
                        <div>
                          <div className="d-flex align-items-center">
                            <div 
                              className="rounded-circle me-2" 
                              style={{ 
                                width: '12px', 
                                height: '12px', 
                                backgroundColor: team.color 
                              }}
                            ></div>
                            <strong>{team.name}</strong>
                          </div>
                          <small className="text-muted">
                            {team.memberCount || team.members?.length || 0} members
                            {team.currentPoints > 0 && (
                              <span className="ms-2">
                                • {team.currentPoints} pts
                              </span>
                            )}
                          </small>
                        </div>
                        <div className="d-flex gap-1">
                          <Button 
                            size="sm" 
                            variant="outline-primary"
                            onClick={() => navigate(`/cyberwar/teams/${team.id}`)}
                          >
                            View
                          </Button>
                          <Button 
                            size="sm" 
                            variant="outline-danger"
                            onClick={async () => {
                              if (window.confirm(`Are you sure you want to leave ${team.name}?`)) {
                                try {
                                  await cyberwarService.leaveTeam(team.id);
                                  fetchData(); // Refresh data
                                } catch (err) {
                                  console.error('Failed to leave team:', err);
                                  setError('Failed to leave team. Please try again.');
                                }
                              }
                            }}
                          >
                            Leave
                          </Button>
                        </div>
                      </div>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              )}
            </Card.Body>
          </Card>

          {/* Quick Stats */}
          <Card>
            <Card.Header>
              <FontAwesomeIcon icon={faTrophy} className="me-2" />
              Quick Stats
            </Card.Header>
            <Card.Body>
              <div className="row text-center">
                <div className="col-4">
                  <div className="h4 mb-0 text-success">{activeMatches.length}</div>
                  <small className="text-muted">Active</small>
                </div>
                <div className="col-4">
                  <div className="h4 mb-0 text-warning">{upcomingMatches.length}</div>
                  <small className="text-muted">Ready</small>
                </div>
                <div className="col-4">
                  <div className="h4 mb-0 text-primary">{userTeams.length}</div>
                  <small className="text-muted">My Teams</small>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Create Team Modal */}
      <Modal show={showCreateTeam} onHide={() => setShowCreateTeam(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Create New Team</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form onSubmit={handleCreateTeam}>
            <Form.Group className="mb-3">
              <Form.Label>Team Name *</Form.Label>
              <Form.Control 
                type="text"
                value={newTeamData.name}
                onChange={(e) => setNewTeamData({...newTeamData, name: e.target.value})}
                required
                placeholder="Enter team name"
              />
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control 
                as="textarea"
                rows={3}
                value={newTeamData.description}
                onChange={(e) => setNewTeamData({...newTeamData, description: e.target.value})}
                placeholder="Describe your team's mission"
              />
            </Form.Group>
            
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Team Color</Form.Label>
                  <Form.Control 
                    type="color"
                    value={newTeamData.color}
                    onChange={(e) => setNewTeamData({...newTeamData, color: e.target.value})}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Max Members</Form.Label>
                  <Form.Control 
                    type="number"
                    min="2"
                    max="10"
                    value={newTeamData.maxMembers}
                    onChange={(e) => setNewTeamData({...newTeamData, maxMembers: parseInt(e.target.value)})}
                  />
                </Form.Group>
              </Col>
            </Row>

            <div className="d-grid gap-2 d-md-flex justify-content-md-end">
              <Button 
                variant="secondary" 
                onClick={() => setShowCreateTeam(false)}
              >
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                <FontAwesomeIcon icon={faPlus} className="me-1" />
                Create Team
              </Button>
            </div>
          </Form>
        </Modal.Body>
      </Modal>

      {/* Join Team Modal */}
      <Modal show={showJoinTeam} onHide={() => setShowJoinTeam(false)} onShow={fetchAvailableTeams}>
        <Modal.Header closeButton>
          <Modal.Title>Join Existing Team</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form onSubmit={handleJoinTeam}>
            <Form.Group className="mb-3">
              <Form.Label>Select Team *</Form.Label>
              <Form.Select 
                value={joinTeamData.teamId}
                onChange={(e) => setJoinTeamData({...joinTeamData, teamId: e.target.value})}
                required
              >
                <option value="">Choose a team...</option>
                {availableTeams.map(team => (
                  <option key={team.id} value={team.id}>
                    {team.name} ({team.memberCount || team.members?.length || 0}/{team.maxMembers} members)
                  </option>
                ))}
              </Form.Select>
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Invite Code (Optional)</Form.Label>
              <Form.Control 
                type="text"
                value={joinTeamData.inviteCode}
                onChange={(e) => setJoinTeamData({...joinTeamData, inviteCode: e.target.value})}
                placeholder="Enter invite code if required"
              />
              <Form.Text className="text-muted">
                Some teams may require an invite code to join
              </Form.Text>
            </Form.Group>

            <div className="d-grid gap-2 d-md-flex justify-content-md-end">
              <Button 
                variant="secondary" 
                onClick={() => setShowJoinTeam(false)}
              >
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                <FontAwesomeIcon icon={faUsers} className="me-1" />
                Join Team
              </Button>
            </div>
          </Form>
        </Modal.Body>
      </Modal>

      {/* Team Selection Modal */}
      <Modal show={showTeamSelection} onHide={() => setShowTeamSelection(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Select Team to Join Match</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="mb-3">You have multiple teams. Which team would you like to use for this match?</p>
          <ListGroup>
            {userTeams.map(team => (
              <ListGroup.Item 
                key={team.id} 
                action 
                onClick={async () => {
                  try {
                    await cyberwarService.joinMatch(selectedMatchForJoin, team.id);
                    setShowTeamSelection(false);
                    setSelectedMatchForJoin(null);
                    navigate(`/cyberwar/match/${selectedMatchForJoin}`);
                  } catch (err) {
                    console.error('Failed to join match:', err);
                    setError('Failed to join match. Please try again.');
                  }
                }}
                className="d-flex justify-content-between align-items-center"
              >
                <div>
                  <div className="d-flex align-items-center">
                    <div 
                      className="rounded-circle me-2" 
                      style={{ 
                        width: '12px', 
                        height: '12px', 
                        backgroundColor: team.color 
                      }}
                    ></div>
                    <strong>{team.name}</strong>
                  </div>
                  <small className="text-muted">{team.description}</small>
                </div>
                <Button size="sm" variant="outline-primary">
                  Select
                </Button>
              </ListGroup.Item>
            ))}
          </ListGroup>
        </Modal.Body>
      </Modal>

      {/* CSS for pulse animation */}
      <style jsx>{`
        .pulse-dot {
          width: 8px;
          height: 8px;
          background-color: currentColor;
          border-radius: 50%;
          display: inline-block;
          animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
          0% {
            transform: scale(0.95);
            box-shadow: 0 0 0 0 rgba(255, 255, 255, 0.7);
          }
          
          70% {
            transform: scale(1);
            box-shadow: 0 0 0 10px rgba(255, 255, 255, 0);
          }
          
          100% {
            transform: scale(0.95);
            box-shadow: 0 0 0 0 rgba(255, 255, 255, 0);
          }
        }
      `}</style>
    </Container>
  );
};

export default MatchLobby;
