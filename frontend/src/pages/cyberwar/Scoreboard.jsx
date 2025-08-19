import { useState, useEffect } from 'react';
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
  Table,
  ProgressBar,
  Tab,
  Tabs,
  Form,
  InputGroup,
  Dropdown,
  Modal
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faTrophy,
  faChartLine,
  faUsers,
  faFlag,
  faClock,
  faEye,
  faDownload,
  faRefresh,
  faFilter,
  faSearch,
  faMedal,
  faFire,
  faBullseye,
  faHistory,
  faExclamationTriangle,
  faStar
} from '@fortawesome/free-solid-svg-icons';
import cyberwarService from '../../services/cyberwarService';
import useWebSocket from '../../hooks/useWebSocket';

const Scoreboard = () => {
  const { matchId } = useParams();
  const navigate = useNavigate();
  
  // State management
  const [match, setMatch] = useState(null);
  const [scoreboard, setScoreboard] = useState([]);
  const [flags, setFlags] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('leaderboard');
  const [autoRefresh, setAutoRefresh] = useState(true);
  
  // Filters and Search
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('rank');
  const [sortOrder, setSortOrder] = useState('asc');
  
  // Modal state
  const [showTeamDetail, setShowTeamDetail] = useState(false);
  const [selectedTeam, setSelectedTeam] = useState(null);

  // WebSocket for real-time updates
  const wsUrl = `ws://localhost:5000/ws/scoring`;
  const { lastMessage, isConnected } = useWebSocket(wsUrl, {
    onMessage: (data) => {
      handleWebSocketMessage(data);
    },
    onOpen: (socket) => {
      // Subscribe to match updates after connection is established
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
          type: 'subscribe_match',
          matchId: matchId
        }));
      }
    }
  });

  useEffect(() => {
    if (matchId) {
      fetchScoreboardData();
    }
  }, [matchId]);

  // Auto-refresh effect
  useEffect(() => {
    let interval;
    if (autoRefresh && match?.status === 'active') {
      interval = setInterval(fetchScoreboardData, 30000); // Refresh every 30 seconds
    }
    return () => clearInterval(interval);
  }, [autoRefresh, match?.status]);

  const fetchScoreboardData = async () => {
    try {
      setLoading(true);
      const [matchRes, scoreRes, flagsRes, timelineRes] = await Promise.all([
        cyberwarService.getMatchById(matchId),
        cyberwarService.getMatchScoreboard(matchId),
        cyberwarService.getMatchFlags(matchId),
        cyberwarService.getMatchEvents(matchId) // Updated from getMatchTimeline to getMatchEvents
      ]);
      
      setMatch(matchRes);
      setScoreboard(scoreRes.teams || []);
      setFlags(flagsRes.flags || []);
      setTimeline(timelineRes.events || []);
      
    } catch (err) {
      console.error('Failed to fetch scoreboard data:', err);
      setError('Failed to load scoreboard data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'score_update':
        setScoreboard(data.scoreboard);
        break;
        
      case 'flag_captured':
        // Add to timeline
        setTimeline(prev => [data.event, ...prev]);
        
        // Update flags
        setFlags(prev => prev.map(flag => 
          flag.id === data.flagId ? { ...flag, capturedBy: data.teamId, capturedAt: data.timestamp } : flag
        ));
        break;
        
      case 'match_ended':
        setMatch(prev => ({ ...prev, status: 'completed', endTime: data.endTime }));
        setAutoRefresh(false);
        break;
        
      default:
        console.log('Unknown scoreboard message:', data.type);
    }
  };

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('asc');
    }
  };

  const getSortedScoreboard = () => {
    let filtered = scoreboard.filter(team => 
      team.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return filtered.sort((a, b) => {
      let aVal, bVal;
      
      switch (sortBy) {
        case 'rank':
          aVal = a.rank || 999;
          bVal = b.rank || 999;
          break;
        case 'score':
          aVal = a.score || 0;
          bVal = b.score || 0;
          break;
        case 'flags':
          aVal = a.flagsCaptured || 0;
          bVal = b.flagsCaptured || 0;
          break;
        case 'name':
          aVal = a.name.toLowerCase();
          bVal = b.name.toLowerCase();
          break;
        default:
          aVal = a.rank || 999;
          bVal = b.rank || 999;
      }

      if (sortOrder === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });
  };

  const exportScoreboard = async () => {
    try {
      const data = await cyberwarService.exportScoreboard(matchId);
      const blob = new Blob([data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scoreboard-${match.name}-${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export scoreboard:', err);
    }
  };

  const getRankBadge = (rank) => {
    if (rank === 1) return <Badge bg="warning"><FontAwesomeIcon icon={faTrophy} className="me-1" />1st</Badge>;
    if (rank === 2) return <Badge bg="secondary"><FontAwesomeIcon icon={faMedal} className="me-1" />2nd</Badge>;
    if (rank === 3) return <Badge bg="info"><FontAwesomeIcon icon={faMedal} className="me-1" />3rd</Badge>;
    return <Badge bg="light" text="dark">#{rank}</Badge>;
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return <Badge bg="success">Live</Badge>;
      case 'completed':
        return <Badge bg="secondary">Completed</Badge>;
      case 'ready':
        return <Badge bg="warning">Ready</Badge>;
      default:
        return <Badge bg="info">{status}</Badge>;
    }
  };

  const formatTimeAgo = (timestamp) => {
    const now = new Date();
    const time = new Date(timestamp);
    const diff = now - time;
    const minutes = Math.floor(diff / 60000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" size="lg" />
        <p className="mt-3">Loading scoreboard...</p>
      </Container>
    );
  }

  if (!match) {
    return (
      <Container className="py-5 text-center">
        <Alert variant="danger">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          Match not found
        </Alert>
        <Button variant="primary" onClick={() => navigate('/cyberwar/lobby')}>
          Back to Lobby
        </Button>
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
              <h1 className="mb-0 d-flex align-items-center">
                <FontAwesomeIcon icon={faTrophy} className="me-2 text-warning" />
                {match.name} - Scoreboard
                <span className="ms-3">{getStatusBadge(match.status)}</span>
              </h1>
              <p className="text-muted mt-1">
                {scoreboard.length} teams competing
                {isConnected && (
                  <Badge bg="success" className="ms-2">
                    <span className="pulse-dot"></span>
                    Live Updates
                  </Badge>
                )}
              </p>
            </div>
            
            <div className="d-flex gap-2">
              <Button
                variant="outline-secondary"
                size="sm"
                onClick={fetchScoreboardData}
              >
                <FontAwesomeIcon icon={faRefresh} className="me-1" />
                Refresh
              </Button>
              
              <Form.Check
                type="switch"
                id="auto-refresh"
                label="Auto-refresh"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="d-flex align-items-center"
              />
              
              <Button
                variant="outline-primary"
                size="sm"
                onClick={exportScoreboard}
              >
                <FontAwesomeIcon icon={faDownload} className="me-1" />
                Export
              </Button>
              
              {match.status === 'active' && (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => navigate(`/cyberwar/match/${matchId}`)}
                >
                  <FontAwesomeIcon icon={faEye} className="me-1" />
                  View Match
                </Button>
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

      {/* Tabs */}
      <Tabs activeKey={activeTab} onSelect={setActiveTab} className="mb-4">
        <Tab eventKey="leaderboard" title="Leaderboard">
          <Row className="mb-3">
            <Col md={6}>
              <InputGroup>
                <Form.Control
                  placeholder="Search teams..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                <InputGroup.Text>
                  <FontAwesomeIcon icon={faSearch} />
                </InputGroup.Text>
              </InputGroup>
            </Col>
            <Col md={6}>
              <div className="d-flex gap-2">
                <Dropdown>
                  <Dropdown.Toggle variant="outline-secondary" size="sm">
                    <FontAwesomeIcon icon={faFilter} className="me-1" />
                    Sort by: {sortBy}
                  </Dropdown.Toggle>
                  <Dropdown.Menu>
                    <Dropdown.Item onClick={() => handleSort('rank')}>Rank</Dropdown.Item>
                    <Dropdown.Item onClick={() => handleSort('score')}>Score</Dropdown.Item>
                    <Dropdown.Item onClick={() => handleSort('flags')}>Flags</Dropdown.Item>
                    <Dropdown.Item onClick={() => handleSort('name')}>Name</Dropdown.Item>
                  </Dropdown.Menu>
                </Dropdown>
              </div>
            </Col>
          </Row>

          <Card>
            <Card.Body className="p-0">
              <Table responsive className="mb-0">
                <thead className="table-dark">
                  <tr>
                    <th 
                      style={{ cursor: 'pointer' }} 
                      onClick={() => handleSort('rank')}
                    >
                      Rank
                      {sortBy === 'rank' && (
                        <FontAwesomeIcon 
                          icon={sortOrder === 'asc' ? faChartLine : faChartLine} 
                          className="ms-1" 
                        />
                      )}
                    </th>
                    <th 
                      style={{ cursor: 'pointer' }} 
                      onClick={() => handleSort('name')}
                    >
                      Team
                    </th>
                    <th 
                      style={{ cursor: 'pointer' }} 
                      onClick={() => handleSort('score')}
                      className="text-center"
                    >
                      Score
                    </th>
                    <th 
                      style={{ cursor: 'pointer' }} 
                      onClick={() => handleSort('flags')}
                      className="text-center"
                    >
                      Flags
                    </th>
                    <th className="text-center">Progress</th>
                    <th className="text-center">Last Activity</th>
                    <th className="text-center">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {getSortedScoreboard().map((team, index) => (
                    <tr key={team.id} className={index < 3 ? 'table-warning' : ''}>
                      <td>
                        <div className="d-flex align-items-center">
                          {getRankBadge(team.rank || index + 1)}
                          {team.rank === 1 && match.status === 'active' && (
                            <FontAwesomeIcon icon={faFire} className="ms-2 text-danger" title="Leading" />
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="d-flex align-items-center">
                          <div 
                            className="rounded-circle me-2" 
                            style={{ 
                              width: '16px', 
                              height: '16px', 
                              backgroundColor: team.color || '#6c757d'
                            }}
                          ></div>
                          <div>
                            <strong>{team.name}</strong>
                            <br />
                            <small className="text-muted">
                              {team.memberCount || team.members?.length || 0} members
                            </small>
                          </div>
                        </div>
                      </td>
                      <td className="text-center">
                        <div className="h4 mb-0 text-primary">{team.score}</div>
                        {team.scoreChange && team.scoreChange !== 0 && (
                          <small className={team.scoreChange > 0 ? 'text-success' : 'text-danger'}>
                            {team.scoreChange > 0 ? '+' : ''}{team.scoreChange}
                          </small>
                        )}
                      </td>
                      <td className="text-center">
                        <Badge bg="info">
                          {team.flagsCaptured || 0}/{flags.length}
                        </Badge>
                      </td>
                      <td className="text-center" style={{ width: '150px' }}>
                        <div>
                          <ProgressBar 
                            now={(team.flagsCaptured || 0) / flags.length * 100}
                            variant={team.rank === 1 ? 'success' : 'info'}
                            size="sm"
                          />
                          <small className="text-muted">
                            {Math.round((team.flagsCaptured || 0) / flags.length * 100)}%
                          </small>
                        </div>
                      </td>
                      <td className="text-center">
                        {team.lastActivity ? (
                          <div>
                            <div>{formatTimeAgo(team.lastActivity)}</div>
                            <small className="text-muted">
                              {new Date(team.lastActivity).toLocaleTimeString()}
                            </small>
                          </div>
                        ) : (
                          <span className="text-muted">No activity</span>
                        )}
                      </td>
                      <td className="text-center">
                        <Button
                          size="sm"
                          variant="outline-primary"
                          onClick={() => {
                            setSelectedTeam(team);
                            setShowTeamDetail(true);
                          }}
                        >
                          <FontAwesomeIcon icon={faEye} />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Tab>

        <Tab eventKey="flags" title="Flag Status">
          <Row>
            {flags.map(flag => (
              <Col md={6} lg={4} key={flag.id} className="mb-3">
                <Card className={flag.captured ? 'border-success' : 'border-warning'}>
                  <Card.Header className="d-flex justify-content-between align-items-center">
                    <span className="fw-bold">{flag.name}</span>
                    <Badge bg={flag.captured ? 'success' : 'warning'}>
                      {flag.captured ? 'Captured' : 'Available'}
                    </Badge>
                  </Card.Header>
                  <Card.Body>
                    <div className="mb-2">
                      <small className="text-muted">
                        {flag.category} • {flag.points} points
                      </small>
                    </div>
                    
                    {flag.description && (
                      <p className="small mb-2">{flag.description}</p>
                    )}
                    
                    {flag.captured && flag.captureInfo && (
                      <div>
                        <div className="d-flex align-items-center">
                          <div 
                            className="rounded-circle me-2" 
                            style={{ 
                              width: '12px', 
                              height: '12px', 
                              backgroundColor: flag.captureInfo?.teamColor || '#6c757d'
                            }}
                          ></div>
                          <strong>{flag.captureInfo?.teamName}</strong>
                        </div>
                        {flag.captureInfo?.capturedAt && (
                          <small className="text-muted">
                            Captured {formatTimeAgo(flag.captureInfo.capturedAt)}
                          </small>
                        )}
                      </div>
                    )}
                  </Card.Body>
                </Card>
              </Col>
            ))}
          </Row>
        </Tab>

        <Tab eventKey="timeline" title="Activity Timeline">
          <Card>
            <Card.Header>
              <FontAwesomeIcon icon={faHistory} className="me-2" />
              Match Timeline
            </Card.Header>
            <Card.Body style={{ maxHeight: '600px', overflowY: 'auto' }}>
              {timeline.length === 0 ? (
                <div className="text-center py-4 text-muted">
                  <FontAwesomeIcon icon={faHistory} size="3x" className="mb-3 opacity-25" />
                  <p>No activity yet</p>
                </div>
              ) : (
                <div>
                  {timeline.map((event, index) => (
                    <div key={index} className="d-flex mb-3">
                      <div className="me-3 mt-1">
                        <div 
                          className="rounded-circle d-flex align-items-center justify-content-center"
                          style={{ 
                            width: '32px', 
                            height: '32px',
                            backgroundColor: event.type === 'flag_captured' ? '#28a745' : '#17a2b8'
                          }}
                        >
                          <FontAwesomeIcon 
                            icon={event.type === 'flag_captured' ? faFlag : faBullseye} 
                            className="text-white"
                            size="sm"
                          />
                        </div>
                      </div>
                      <div className="flex-grow-1">
                        <div className="d-flex justify-content-between align-items-start mb-1">
                          <div>
                            <strong>{event.teamName}</strong>
                            {event.type === 'flag_captured' && (
                              <span className="ms-2">
                                captured <strong>{event.flagName}</strong>
                                <Badge bg="success" className="ms-2">+{event.points} pts</Badge>
                              </span>
                            )}
                          </div>
                          <small className="text-muted">{formatTimeAgo(event.timestamp)}</small>
                        </div>
                        {event.description && (
                          <p className="small text-muted mb-0">{event.description}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card.Body>
          </Card>
        </Tab>

        <Tab eventKey="analytics" title="Analytics">
          <Row>
            <Col lg={6}>
              <Card className="mb-4">
                <Card.Header>
                  <FontAwesomeIcon icon={faChartLine} className="me-2" />
                  Competition Statistics
                </Card.Header>
                <Card.Body>
                  <Row className="text-center">
                    <Col md={3}>
                      <div className="h3 text-primary mb-0">{scoreboard.length}</div>
                      <small className="text-muted">Teams</small>
                    </Col>
                    <Col md={3}>
                      <div className="h3 text-success mb-0">{flags.filter(f => f.capturedBy).length}</div>
                      <small className="text-muted">Flags Captured</small>
                    </Col>
                    <Col md={3}>
                      <div className="h3 text-warning mb-0">{flags.length - flags.filter(f => f.capturedBy).length}</div>
                      <small className="text-muted">Flags Remaining</small>
                    </Col>
                    <Col md={3}>
                      <div className="h3 text-info mb-0">{timeline.length}</div>
                      <small className="text-muted">Total Events</small>
                    </Col>
                  </Row>
                </Card.Body>
              </Card>

              <Card>
                <Card.Header>Top Performers</Card.Header>
                <Card.Body>
                  {scoreboard.slice(0, 5).map((team, index) => (
                    <div key={team.id} className="d-flex justify-content-between align-items-center mb-2">
                      <div className="d-flex align-items-center">
                        {getRankBadge(index + 1)}
                        <span className="ms-2 fw-bold">{team.name}</span>
                      </div>
                      <div>
                        <Badge bg="primary">{team.score} pts</Badge>
                        <Badge bg="info" className="ms-1">{team.flagsCaptured} flags</Badge>
                      </div>
                    </div>
                  ))}
                </Card.Body>
              </Card>
            </Col>
            
            <Col lg={6}>
              <Card>
                <Card.Header>Flag Categories</Card.Header>
                <Card.Body>
                  {/* Group flags by category and show capture rates */}
                  {[...new Set(flags.map(f => f.category))].map(category => {
                    const categoryFlags = flags.filter(f => f.category === category);
                    const capturedCount = categoryFlags.filter(f => f.capturedBy).length;
                    const captureRate = (capturedCount / categoryFlags.length) * 100;
                    
                    return (
                      <div key={category} className="mb-3">
                        <div className="d-flex justify-content-between mb-1">
                          <span className="fw-bold">{category}</span>
                          <span>{capturedCount}/{categoryFlags.length}</span>
                        </div>
                        <ProgressBar 
                          now={captureRate}
                          variant={captureRate === 100 ? 'success' : 'info'}
                        />
                        <small className="text-muted">{Math.round(captureRate)}% captured</small>
                      </div>
                    );
                  })}
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>
      </Tabs>

      {/* Team Detail Modal */}
      <Modal show={showTeamDetail} onHide={() => setShowTeamDetail(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            {selectedTeam && (
              <div className="d-flex align-items-center">
                <div 
                  className="rounded-circle me-2" 
                  style={{ 
                    width: '24px', 
                    height: '24px', 
                    backgroundColor: selectedTeam.color || '#6c757d'
                  }}
                ></div>
                {selectedTeam.name} - Team Details
              </div>
            )}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedTeam && (
            <Row>
              <Col md={6}>
                <h6>Team Statistics</h6>
                <Table size="sm">
                  <tbody>
                    <tr>
                      <td>Current Rank:</td>
                      <td>{getRankBadge(selectedTeam.rank)}</td>
                    </tr>
                    <tr>
                      <td>Total Score:</td>
                      <td><Badge bg="primary">{selectedTeam.score}</Badge></td>
                    </tr>
                    <tr>
                      <td>Flags Captured:</td>
                      <td><Badge bg="success">{selectedTeam.flagsCaptured}/{flags.length}</Badge></td>
                    </tr>
                    <tr>
                      <td>Members:</td>
                      <td>{selectedTeam.memberCount || selectedTeam.members?.length || 0}</td>
                    </tr>
                  </tbody>
                </Table>
              </Col>
              
              <Col md={6}>
                <h6>Captured Flags</h6>
                <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                  {flags.filter(f => f.capturedBy === selectedTeam.id).length === 0 ? (
                    <p className="text-muted">No flags captured yet</p>
                  ) : (
                    flags.filter(f => f.capturedBy === selectedTeam.id).map(flag => (
                      <div key={flag.id} className="mb-2">
                        <div className="d-flex justify-content-between">
                          <strong>{flag.name}</strong>
                          <Badge bg="info">{flag.points} pts</Badge>
                        </div>
                        <small className="text-muted">{flag.category}</small>
                      </div>
                    ))
                  )}
                </div>
              </Col>
            </Row>
          )}
        </Modal.Body>
      </Modal>

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

export default Scoreboard;
