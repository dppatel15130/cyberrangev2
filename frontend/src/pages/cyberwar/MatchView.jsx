import { useState, useEffect, useContext } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
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
  Toast,
  ToastContainer,
  InputGroup
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faPlay,
  faStop,
  faClock,
  faFlag,
  faUsers,
  faTrophy,
  faEye,
  faTerminal,
  faDesktop,
  faNetworkWired,
  faShield,
  faExclamationTriangle,
  faCheckCircle,
  faTimesCircle,
  faSyncAlt,
  faChartLine,
  faComments,
  faPaperPlane,
  faDownload,
  faBug,
  faLightbulb
} from '@fortawesome/free-solid-svg-icons';
import { AuthContext } from '../../context/AuthContext';
import cyberwarService from '../../services/cyberwarService';
import useWebSocket from '../../hooks/useWebSocket';

const MatchView = () => {
  const { matchId } = useParams();
  const { user } = useContext(AuthContext);
  const navigate = useNavigate();
  
  // State management
  const [match, setMatch] = useState(null);
  const [userTeam, setUserTeam] = useState(null);
  const [scoreboard, setScoreboard] = useState([]);
  const [flags, setFlags] = useState([]);
  const [vms, setVms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Match state
  const [timeRemaining, setTimeRemaining] = useState(0);
  const [matchStatus, setMatchStatus] = useState('loading');
  
  // Modals & Forms
  const [showFlagSubmission, setShowFlagSubmission] = useState(false);
  const [selectedFlag, setSelectedFlag] = useState(null);
  const [flagValue, setFlagValue] = useState('');
  const [submissionResult, setSubmissionResult] = useState(null);
  
  // Chat system
  const [chatMessages, setChatMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  
  // Notifications
  const [toasts, setToasts] = useState([]);

  // WebSocket for real-time updates
  const wsUrl = `ws://localhost:5000/ws/match/${matchId}`;
  const { lastMessage, isConnected, sendMessage } = useWebSocket(wsUrl, {
    onMessage: (data) => {
      handleWebSocketMessage(data);
    }
  });

  useEffect(() => {
    if (matchId) {
      fetchMatchData();
    }
  }, [matchId]);

  // Timer effect
  useEffect(() => {
    let interval;
    if (matchStatus === 'active' && timeRemaining > 0) {
      interval = setInterval(() => {
        setTimeRemaining(prev => {
          if (prev <= 1) {
            setMatchStatus('completed');
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [matchStatus, timeRemaining]);

  const fetchMatchData = async () => {
    try {
      setLoading(true);
      const [matchRes, teamRes, scoreRes, flagsRes, vmsRes] = await Promise.all([
        cyberwarService.getMatchById(matchId),
        cyberwarService.getUserTeamForMatch(matchId),
        cyberwarService.getMatchScoreboard(matchId),
        cyberwarService.getMatchFlags(matchId),
        cyberwarService.getMatchVMAssignments(matchId) // Updated from getMatchVMs to getMatchVMAssignments
      ]);
      
      setMatch(matchRes);
      setUserTeam(teamRes);
      setScoreboard(scoreRes.teams || []);
      setFlags(flagsRes.flags || []);
      setVms(vmsRes.vms || []);
      
      // Calculate time remaining
      if (matchRes.status === 'active' && matchRes.startTime && matchRes.duration) {
        const startTime = new Date(matchRes.startTime);
        const endTime = new Date(startTime.getTime() + matchRes.duration * 60000);
        const remaining = Math.max(0, Math.floor((endTime - new Date()) / 1000));
        setTimeRemaining(remaining);
      }
      
      setMatchStatus(matchRes.status);
      
    } catch (err) {
      console.error('Failed to fetch match data:', err);
      setError('Failed to load match data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'match_started':
        setMatchStatus('active');
        setTimeRemaining(data.duration * 60);
        addToast('Match started!', 'success');
        break;
        
      case 'match_ended':
        setMatchStatus('completed');
        setTimeRemaining(0);
        addToast('Match completed!', 'info');
        break;
        
      case 'score_update':
        setScoreboard(data.scoreboard);
        break;
        
      case 'flag_captured':
        if (data.teamId === userTeam?.id) {
          addToast(`Flag captured: ${data.flagName}`, 'success');
        } else {
          addToast(`${data.teamName} captured: ${data.flagName}`, 'warning');
        }
        setFlags(prev => prev.map(flag => 
          flag.id === data.flagId ? { ...flag, capturedBy: data.teamId } : flag
        ));
        break;
        
      case 'vm_status_change':
        setVms(prev => prev.map(vm => 
          vm.id === data.vmId ? { ...vm, status: data.status } : vm
        ));
        break;
        
      case 'team_message':
        if (data.teamId === userTeam?.id) {
          setChatMessages(prev => [...prev, data.message]);
        }
        break;
        
      default:
        console.log('Unknown message type:', data.type);
    }
  };

  const addToast = (message, variant = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, variant }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(toast => toast.id !== id));
    }, 5000);
  };

  const handleFlagSubmission = async (e) => {
    e.preventDefault();
    try {
      const result = await cyberwarService.submitFlag(matchId, {
        flagId: selectedFlag.id,
        value: flagValue
      });
      
      setSubmissionResult(result);
      setFlagValue('');
      
      if (result.correct) {
        addToast(`Correct flag! +${result.points} points`, 'success');
        setShowFlagSubmission(false);
        fetchMatchData(); // Refresh data
      } else {
        addToast('Incorrect flag value', 'danger');
      }
      
    } catch (err) {
      console.error('Failed to submit flag:', err);
      setError('Failed to submit flag. Please try again.');
    }
  };

  const handleVMAction = async (vmId, action) => {
    try {
      await cyberwarService.controlVM(vmId, action);
      addToast(`VM ${action} initiated`, 'info');
    } catch (err) {
      console.error('Failed to control VM:', err);
      addToast(`Failed to ${action} VM`, 'danger');
    }
  };

  const handleSendMessage = () => {
    if (newMessage.trim() && userTeam) {
      const message = {
        id: Date.now(),
        userId: user.id,
        username: user.username,
        message: newMessage,
        timestamp: new Date().toISOString()
      };
      
      sendMessage({
        type: 'team_message',
        teamId: userTeam.id,
        message
      });
      
      setChatMessages(prev => [...prev, message]);
      setNewMessage('');
    }
  };

  const formatTime = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return <Badge bg="success">Active</Badge>;
      case 'completed':
        return <Badge bg="secondary">Completed</Badge>;
      case 'ready':
        return <Badge bg="warning">Ready</Badge>;
      default:
        return <Badge bg="info">{status}</Badge>;
    }
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" size="lg" />
        <p className="mt-3">Loading match data...</p>
      </Container>
    );
  }

  if (!match) {
    return (
      <Container className="py-5 text-center">
        <Alert variant="danger">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          Match not found or access denied
        </Alert>
        <Button variant="primary" onClick={() => navigate('/cyberwar/lobby')}>
          Back to Lobby
        </Button>
      </Container>
    );
  }

  if (!userTeam) {
    return (
      <Container className="py-5 text-center">
        <Alert variant="warning">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          You need to be part of a team to participate in this match
        </Alert>
        <Button variant="primary" onClick={() => navigate('/cyberwar/lobby')}>
          Back to Lobby
        </Button>
      </Container>
    );
  }

  return (
    <Container fluid className="py-3">
      {/* Header */}
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h1 className="mb-0 d-flex align-items-center">
                <FontAwesomeIcon icon={faPlay} className="me-2 text-primary" />
                {match.name}
                <span className="ms-3">{getStatusBadge(matchStatus)}</span>
              </h1>
              <p className="text-muted mt-1">
                Team: <strong style={{ color: userTeam.color }}>{userTeam.name}</strong>
                {isConnected && (
                  <Badge bg="success" className="ms-2">
                    <span className="pulse-dot"></span>
                    Live
                  </Badge>
                )}
              </p>
            </div>
            
            <div className="text-end">
              {matchStatus === 'active' && (
                <div>
                  <h2 className="mb-0 text-danger">
                    <FontAwesomeIcon icon={faClock} className="me-2" />
                    {formatTime(timeRemaining)}
                  </h2>
                  <small className="text-muted">Time Remaining</small>
                </div>
              )}
              {matchStatus === 'completed' && (
                <div>
                  <h3 className="mb-0 text-secondary">
                    <FontAwesomeIcon icon={faStop} className="me-2" />
                    Match Complete
                  </h3>
                </div>
              )}
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

      <Row>
        <Col lg={9}>
          {/* Main Content Tabs */}
          <Tabs activeKey={activeTab} onSelect={setActiveTab} className="mb-3">
            <Tab eventKey="overview" title="Overview">
              <Row>
                <Col md={6}>
                  {/* Flags */}
                  <Card className="mb-4">
                    <Card.Header className="d-flex justify-content-between align-items-center">
                      <span>
                        <FontAwesomeIcon icon={faFlag} className="me-2" />
                        Capture the Flag
                      </span>
                      <Badge bg="info">{flags.filter(f => f.capturedBy === userTeam.id).length}/{flags.length}</Badge>
                    </Card.Header>
                    <Card.Body style={{ maxHeight: '400px', overflowY: 'auto' }}>
                      {flags.length === 0 ? (
                        <p className="text-muted">No flags available yet</p>
                      ) : (
                        <ListGroup variant="flush">
                          {flags.map(flag => (
                            <ListGroup.Item key={flag.id} className="px-0">
                              <div className="d-flex justify-content-between align-items-center">
                                <div>
                                  <div className="fw-bold">{flag.name}</div>
                                  <small className="text-muted">{flag.category} • {flag.points} pts</small>
                                  {flag.description && (
                                    <p className="small mb-0 mt-1">{flag.description}</p>
                                  )}
                                </div>
                                <div>
                                  {flag.capturedBy === userTeam.id ? (
                                    <Badge bg="success">
                                      <FontAwesomeIcon icon={faCheckCircle} className="me-1" />
                                      Captured
                                    </Badge>
                                  ) : flag.capturedBy ? (
                                    <Badge bg="danger">
                                      <FontAwesomeIcon icon={faTimesCircle} className="me-1" />
                                      Taken
                                    </Badge>
                                  ) : (
                                    <Button 
                                      size="sm" 
                                      variant="outline-primary"
                                      onClick={() => {
                                        setSelectedFlag(flag);
                                        setShowFlagSubmission(true);
                                      }}
                                      disabled={matchStatus !== 'active'}
                                    >
                                      Submit
                                    </Button>
                                  )}
                                </div>
                              </div>
                            </ListGroup.Item>
                          ))}
                        </ListGroup>
                      )}
                    </Card.Body>
                  </Card>
                </Col>
                
                <Col md={6}>
                  {/* Virtual Machines */}
                  <Card>
                    <Card.Header>
                      <FontAwesomeIcon icon={faDesktop} className="me-2" />
                      Virtual Machines
                    </Card.Header>
                    <Card.Body style={{ maxHeight: '400px', overflowY: 'auto' }}>
                      {vms.length === 0 ? (
                        <p className="text-muted">No VMs assigned to your team</p>
                      ) : (
                        <ListGroup variant="flush">
                          {vms.map(vm => (
                            <ListGroup.Item key={vm.id} className="px-0">
                              <div className="d-flex justify-content-between align-items-center mb-2">
                                <div>
                                  <div className="fw-bold">{vm.name}</div>
                                  <small className="text-muted">
                                    {vm.os} • {vm.ipAddress}
                                  </small>
                                </div>
                                <Badge bg={vm.status === 'running' ? 'success' : 'secondary'}>
                                  {vm.status}
                                </Badge>
                              </div>
                              
                              <div className="d-flex gap-2">
                                {vm.status === 'stopped' ? (
                                  <Button 
                                    size="sm" 
                                    variant="success"
                                    onClick={() => handleVMAction(vm.id, 'start')}
                                    disabled={matchStatus !== 'active'}
                                  >
                                    <FontAwesomeIcon icon={faPlay} className="me-1" />
                                    Start
                                  </Button>
                                ) : (
                                  <>
                                    <Button 
                                      size="sm" 
                                      variant="outline-primary"
                                      onClick={() => window.open(vm.consoleUrl, '_blank')}
                                      disabled={!vm.consoleUrl}
                                    >
                                      <FontAwesomeIcon icon={faDesktop} className="me-1" />
                                      Console
                                    </Button>
                                    <Button 
                                      size="sm" 
                                      variant="outline-secondary"
                                      onClick={() => handleVMAction(vm.id, 'restart')}
                                    >
                                      <FontAwesomeIcon icon={faSyncAlt} className="me-1" />
                                      Restart
                                    </Button>
                                    <Button 
                                      size="sm" 
                                      variant="outline-danger"
                                      onClick={() => handleVMAction(vm.id, 'stop')}
                                    >
                                      <FontAwesomeIcon icon={faStop} className="me-1" />
                                      Stop
                                    </Button>
                                  </>
                                )}
                              </div>
                            </ListGroup.Item>
                          ))}
                        </ListGroup>
                      )}
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
            </Tab>

            <Tab eventKey="scoreboard" title="Scoreboard">
              <Card>
                <Card.Header>
                  <FontAwesomeIcon icon={faTrophy} className="me-2" />
                  Live Scoreboard
                </Card.Header>
                <Card.Body>
                  <Table responsive striped>
                    <thead>
                      <tr>
                        <th>Rank</th>
                        <th>Team</th>
                        <th>Score</th>
                        <th>Flags</th>
                        <th>Last Activity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scoreboard.map((team, index) => (
                        <tr key={team.id} className={team.id === userTeam.id ? 'table-warning' : ''}>
                          <td>
                            <strong>#{index + 1}</strong>
                          </td>
                          <td>
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
                              {team.id === userTeam.id && <Badge bg="primary" className="ms-2">You</Badge>}
                            </div>
                          </td>
                          <td>
                            <strong className="h5 mb-0">{team.score}</strong>
                          </td>
                          <td>
                            {team.flagsCaptured}/{flags.length}
                          </td>
                          <td>
                            {team.lastActivity ? new Date(team.lastActivity).toLocaleTimeString() : 'N/A'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                </Card.Body>
              </Card>
            </Tab>

            <Tab eventKey="resources" title="Resources">
              <Row>
                <Col md={6}>
                  <Card className="mb-4">
                    <Card.Header>
                      <FontAwesomeIcon icon={faLightbulb} className="me-2" />
                      Match Resources
                    </Card.Header>
                    <Card.Body>
                      {match.resources && match.resources.length > 0 ? (
                        <ListGroup variant="flush">
                          {match.resources.map((resource, index) => (
                            <ListGroup.Item key={index} className="px-0">
                              <div className="d-flex justify-content-between align-items-center">
                                <div>
                                  <strong>{resource.name}</strong>
                                  <p className="small text-muted mb-0">{resource.description}</p>
                                </div>
                                <Button 
                                  size="sm" 
                                  variant="outline-primary"
                                  href={resource.url}
                                  target="_blank"
                                >
                                  <FontAwesomeIcon icon={faDownload} className="me-1" />
                                  Access
                                </Button>
                              </div>
                            </ListGroup.Item>
                          ))}
                        </ListGroup>
                      ) : (
                        <p className="text-muted">No additional resources provided</p>
                      )}
                    </Card.Body>
                  </Card>
                </Col>
                
                <Col md={6}>
                  <Card>
                    <Card.Header>
                      <FontAwesomeIcon icon={faBug} className="me-2" />
                      Match Rules & Guidelines
                    </Card.Header>
                    <Card.Body>
                      <div className="small">
                        <h6>Competition Rules:</h6>
                        <ul>
                          <li>Teams can only access their assigned VMs</li>
                          <li>Flag sharing between teams is prohibited</li>
                          <li>No denial-of-service attacks on infrastructure</li>
                          <li>Social engineering of other teams is not allowed</li>
                        </ul>
                        
                        <h6>Scoring:</h6>
                        <ul>
                          <li>Points awarded based on flag difficulty</li>
                          <li>Bonus points for first blood captures</li>
                          <li>Time-based scoring multipliers apply</li>
                        </ul>
                        
                        <h6>Technical Support:</h6>
                        <p>Contact administrators for technical issues with VMs or infrastructure.</p>
                      </div>
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
            </Tab>
          </Tabs>
        </Col>

        <Col lg={3}>
          {/* Team Chat */}
          <Card className="h-100">
            <Card.Header>
              <FontAwesomeIcon icon={faComments} className="me-2" />
              Team Chat
            </Card.Header>
            <Card.Body className="d-flex flex-column" style={{ height: '500px' }}>
              <div className="flex-grow-1 mb-3" style={{ overflowY: 'auto' }}>
                {chatMessages.length === 0 ? (
                  <p className="text-muted small">No messages yet. Start collaborating!</p>
                ) : (
                  <div>
                    {chatMessages.map(msg => (
                      <div key={msg.id} className="mb-2">
                        <small className="text-muted">
                          <strong>{msg.username}</strong> • {new Date(msg.timestamp).toLocaleTimeString()}
                        </small>
                        <p className="small mb-0">{msg.message}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              
              <div>
                <InputGroup>
                  <Form.Control
                    size="sm"
                    placeholder="Type a message..."
                    value={newMessage}
                    onChange={(e) => setNewMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                    disabled={matchStatus !== 'active'}
                  />
                  <Button 
                    variant="primary" 
                    size="sm"
                    onClick={handleSendMessage}
                    disabled={!newMessage.trim() || matchStatus !== 'active'}
                  >
                    <FontAwesomeIcon icon={faPaperPlane} />
                  </Button>
                </InputGroup>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Flag Submission Modal */}
      <Modal show={showFlagSubmission} onHide={() => setShowFlagSubmission(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Submit Flag</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedFlag && (
            <div>
              <div className="mb-3">
                <h6>{selectedFlag.name}</h6>
                <p className="text-muted">{selectedFlag.description}</p>
                <Badge bg="info">{selectedFlag.points} points</Badge>
              </div>
              
              <Form onSubmit={handleFlagSubmission}>
                <Form.Group className="mb-3">
                  <Form.Label>Flag Value</Form.Label>
                  <Form.Control 
                    type="text"
                    value={flagValue}
                    onChange={(e) => setFlagValue(e.target.value)}
                    placeholder="Enter the flag value..."
                    required
                    autoFocus
                  />
                  <Form.Text className="text-muted">
                    Usually in format: flag{"{"}value{"}"}
                  </Form.Text>
                </Form.Group>
                
                <div className="d-grid gap-2 d-md-flex justify-content-md-end">
                  <Button variant="secondary" onClick={() => setShowFlagSubmission(false)}>
                    Cancel
                  </Button>
                  <Button variant="primary" type="submit">
                    <FontAwesomeIcon icon={faFlag} className="me-1" />
                    Submit Flag
                  </Button>
                </div>
              </Form>
              
              {submissionResult && (
                <Alert variant={submissionResult.correct ? 'success' : 'danger'} className="mt-3">
                  <FontAwesomeIcon 
                    icon={submissionResult.correct ? faCheckCircle : faTimesCircle} 
                    className="me-2" 
                  />
                  {submissionResult.message}
                </Alert>
              )}
            </div>
          )}
        </Modal.Body>
      </Modal>

      {/* Toast Container */}
      <ToastContainer position="top-end" className="p-3">
        {toasts.map(toast => (
          <Toast 
            key={toast.id}
            bg={toast.variant}
            text={toast.variant === 'dark' ? 'white' : 'dark'}
            autohide
          >
            <Toast.Body>{toast.message}</Toast.Body>
          </Toast>
        ))}
      </ToastContainer>

      {/* Pulse animation CSS */}
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

export default MatchView;
