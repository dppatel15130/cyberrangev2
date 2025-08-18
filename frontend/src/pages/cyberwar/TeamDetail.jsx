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
  Dropdown
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faUser, 
  faUsers, 
  faUserPlus,
  faUserMinus,
  faCrown,
  faEnvelope,
  faHistory,
  faTrophy,
  faFlag,
  faCalendarAlt,
  faClock,
  faSearch,
  faFilter,
  faSort,
  faSortUp,
  faSortDown,
  faPlus,
  faEdit,
  faTrash,
  faCog,
  faEye,
  faChartLine,
  faShield,
  faExclamationTriangle,
  faCopy,
  faCheck
} from '@fortawesome/free-solid-svg-icons';
import { AuthContext } from '../../context/AuthContext';
import cyberwarService from '../../services/cyberwarService';

const TeamDetail = () => {
  const { teamId } = useParams();
  const { user } = useContext(AuthContext);
  const navigate = useNavigate();
  
  // State management
  const [team, setTeam] = useState(null);
  const [teamStats, setTeamStats] = useState(null);
  const [matchHistory, setMatchHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Modals
  const [showInvite, setShowInvite] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  const [showRemoveMember, setShowRemoveMember] = useState(false);
  const [selectedMember, setSelectedMember] = useState(null);
  
  // Form data
  const [inviteEmail, setInviteEmail] = useState('');
  const [editData, setEditData] = useState({
    name: '',
    description: '',
    color: '#007bff',
    maxMembers: 4
  });
  
  const [inviteLink, setInviteLink] = useState('');
  const [linkCopied, setLinkCopied] = useState(false);

  useEffect(() => {
    if (teamId) {
      fetchTeamData();
    }
  }, [teamId]);

  const fetchTeamData = async () => {
    try {
      setLoading(true);
      const [teamRes, statsRes, historyRes] = await Promise.all([
        cyberwarService.getTeamById(teamId),
        cyberwarService.getTeamStats(teamId),
        cyberwarService.getTeamMatches(teamId)
      ]);
      
      setTeam(teamRes);
      setTeamStats(statsRes);
      setMatchHistory(historyRes.matches || []);
      
      // Set edit form data
      setEditData({
        name: teamRes.name,
        description: teamRes.description || '',
        color: teamRes.color || '#007bff',
        maxMembers: teamRes.maxMembers || 4
      });
      
    } catch (err) {
      console.error('Failed to fetch team data:', err);
      setError('Failed to load team data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleInviteMember = async (e) => {
    e.preventDefault();
    try {
      await cyberwarService.inviteTeamMember(teamId, { email: inviteEmail });
      setShowInvite(false);
      setInviteEmail('');
      fetchTeamData(); // Refresh data
    } catch (err) {
      console.error('Failed to invite member:', err);
      setError('Failed to send invitation. Please try again.');
    }
  };

  const handleGenerateInviteLink = async () => {
    try {
      const response = await cyberwarService.generateTeamInviteLink(teamId);
      setInviteLink(response.inviteLink);
    } catch (err) {
      console.error('Failed to generate invite link:', err);
      setError('Failed to generate invite link.');
    }
  };

  const handleCopyInviteLink = () => {
    navigator.clipboard.writeText(inviteLink);
    setLinkCopied(true);
    setTimeout(() => setLinkCopied(false), 2000);
  };

  const handleUpdateTeam = async (e) => {
    e.preventDefault();
    try {
      await cyberwarService.updateTeam(teamId, editData);
      setShowEdit(false);
      fetchTeamData(); // Refresh data
    } catch (err) {
      console.error('Failed to update team:', err);
      setError('Failed to update team. Please try again.');
    }
  };

  const handleRemoveMember = async () => {
    try {
      await cyberwarService.removeTeamMember(teamId, selectedMember.id);
      setShowRemoveMember(false);
      setSelectedMember(null);
      fetchTeamData(); // Refresh data
    } catch (err) {
      console.error('Failed to remove member:', err);
      setError('Failed to remove member. Please try again.');
    }
  };

  const handleLeaveTeam = async () => {
    try {
      await cyberwarService.leaveTeam(teamId);
      navigate('/cyberwar/lobby');
    } catch (err) {
      console.error('Failed to leave team:', err);
      setError('Failed to leave team. Please try again.');
    }
  };

  const isTeamLeader = () => {
    return team && team.leaderId === user.id;
  };

  const formatMatchResult = (match, team) => {
    const teamResult = match.results?.find(r => r.teamId === team.id);
    if (!teamResult) return 'N/A';
    
    const position = teamResult.position;
    if (position === 1) return <Badge bg="success">1st</Badge>;
    if (position === 2) return <Badge bg="warning">2nd</Badge>;
    if (position === 3) return <Badge bg="info">3rd</Badge>;
    return <Badge bg="secondary">{position}th</Badge>;
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" size="lg" />
        <p className="mt-3">Loading team data...</p>
      </Container>
    );
  }

  if (!team) {
    return (
      <Container className="py-5 text-center">
        <Alert variant="danger">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          Team not found
        </Alert>
        <Button variant="primary" onClick={() => navigate('/cyberwar/lobby')}>
          Back to Lobby
        </Button>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      {/* Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div className="d-flex align-items-center">
          <div 
            className="rounded-circle me-3" 
            style={{ 
              width: '40px', 
              height: '40px', 
              backgroundColor: team.color 
            }}
          ></div>
          <div>
            <h1 className="mb-0 d-flex align-items-center">
              {team.name}
              {isTeamLeader() && (
                <FontAwesomeIcon icon={faCrown} className="ms-2 text-warning" title="Team Leader" />
              )}
            </h1>
            <p className="text-muted mt-1">
              {team.members?.length || 0}/{team.maxMembers} members
              {team.status && <Badge bg="success" className="ms-2">{team.status}</Badge>}
            </p>
          </div>
        </div>
        
        <div>
          {isTeamLeader() && (
            <Dropdown>
              <Dropdown.Toggle variant="outline-primary" size="sm">
                <FontAwesomeIcon icon={faCog} className="me-1" />
                Manage
              </Dropdown.Toggle>
              <Dropdown.Menu>
                <Dropdown.Item onClick={() => setShowEdit(true)}>
                  <FontAwesomeIcon icon={faEdit} className="me-2" />
                  Edit Team
                </Dropdown.Item>
                <Dropdown.Item onClick={() => setShowInvite(true)}>
                  <FontAwesomeIcon icon={faUserPlus} className="me-2" />
                  Invite Members
                </Dropdown.Item>
                <Dropdown.Divider />
                <Dropdown.Item onClick={handleLeaveTeam} className="text-danger">
                  <FontAwesomeIcon icon={faTrash} className="me-2" />
                  Leave Team
                </Dropdown.Item>
              </Dropdown.Menu>
            </Dropdown>
          )}
          {!isTeamLeader() && (
            <Button variant="outline-danger" size="sm" onClick={handleLeaveTeam}>
              Leave Team
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

      {/* Tabs */}
      <Tabs activeKey={activeTab} onSelect={setActiveTab} className="mb-4">
        <Tab eventKey="overview" title="Overview">
          <Row>
            <Col lg={8}>
              {/* Team Description */}
              <Card className="mb-4">
                <Card.Header>
                  <FontAwesomeIcon icon={faShield} className="me-2" />
                  Team Information
                </Card.Header>
                <Card.Body>
                  {team.description ? (
                    <p className="mb-0">{team.description}</p>
                  ) : (
                    <p className="text-muted mb-0 fst-italic">No description provided</p>
                  )}
                </Card.Body>
              </Card>

              {/* Team Members */}
              <Card>
                <Card.Header className="d-flex justify-content-between align-items-center">
                  <span>
                    <FontAwesomeIcon icon={faUsers} className="me-2" />
                    Team Members ({team.members?.length || 0})
                  </span>
                  {isTeamLeader() && (
                    <Button size="sm" variant="outline-primary" onClick={() => setShowInvite(true)}>
                      <FontAwesomeIcon icon={faUserPlus} className="me-1" />
                      Invite
                    </Button>
                  )}
                </Card.Header>
                <Card.Body className="p-0">
                  <ListGroup variant="flush">
                    {(team.members || []).map(member => (
                      <ListGroup.Item key={member.id} className="d-flex justify-content-between align-items-center">
                        <div className="d-flex align-items-center">
                          <div className="me-3">
                            <div 
                              className="rounded-circle d-flex align-items-center justify-content-center text-white fw-bold"
                              style={{ 
                                width: '32px', 
                                height: '32px',
                                backgroundColor: '#6c757d'
                              }}
                            >
                              {member.username?.charAt(0).toUpperCase()}
                            </div>
                          </div>
                          <div>
                            <div className="fw-bold">
                              {member.username}
                              {member.id === team.leaderId && (
                                <FontAwesomeIcon icon={faCrown} className="ms-2 text-warning" title="Leader" />
                              )}
                            </div>
                            <small className="text-muted">{member.email}</small>
                          </div>
                        </div>
                        
                        <div className="d-flex align-items-center">
                          {member.lastSeen && (
                            <small className="text-muted me-3">
                              Last seen: {new Date(member.lastSeen).toLocaleDateString()}
                            </small>
                          )}
                          {isTeamLeader() && member.id !== user.id && (
                            <Button 
                              size="sm" 
                              variant="outline-danger"
                              onClick={() => {
                                setSelectedMember(member);
                                setShowRemoveMember(true);
                              }}
                            >
                              <FontAwesomeIcon icon={faUserMinus} />
                            </Button>
                          )}
                        </div>
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
                </Card.Body>
              </Card>
            </Col>

            <Col lg={4}>
              {/* Team Stats */}
              {teamStats && (
                <Card className="mb-4">
                  <Card.Header>
                    <FontAwesomeIcon icon={faTrophy} className="me-2" />
                    Statistics
                  </Card.Header>
                  <Card.Body>
                    <div className="row text-center mb-3">
                      <div className="col-4">
                        <div className="h4 mb-0 text-primary">{teamStats.matchesPlayed || 0}</div>
                        <small className="text-muted">Matches</small>
                      </div>
                      <div className="col-4">
                        <div className="h4 mb-0 text-success">{teamStats.wins || 0}</div>
                        <small className="text-muted">Wins</small>
                      </div>
                      <div className="col-4">
                        <div className="h4 mb-0 text-warning">{teamStats.totalPoints || 0}</div>
                        <small className="text-muted">Points</small>
                      </div>
                    </div>
                    
                    {teamStats.winRate !== undefined && (
                      <div className="mb-3">
                        <div className="d-flex justify-content-between mb-1">
                          <small>Win Rate</small>
                          <small>{Math.round(teamStats.winRate * 100)}%</small>
                        </div>
                        <ProgressBar now={teamStats.winRate * 100} variant="success" />
                      </div>
                    )}
                    
                    {teamStats.averageScore !== undefined && (
                      <div>
                        <div className="d-flex justify-content-between mb-1">
                          <small>Average Score</small>
                          <small>{Math.round(teamStats.averageScore)}</small>
                        </div>
                        <ProgressBar now={Math.min(teamStats.averageScore / 10, 100)} variant="info" />
                      </div>
                    )}
                  </Card.Body>
                </Card>
              )}

              {/* Quick Actions */}
              <Card>
                <Card.Header>Quick Actions</Card.Header>
                <Card.Body className="d-grid gap-2">
                  <Button variant="primary" onClick={() => navigate('/cyberwar/lobby')}>
                    <FontAwesomeIcon icon={faEye} className="me-2" />
                    View Matches
                  </Button>
                  <Button variant="outline-primary" onClick={() => setActiveTab('history')}>
                    <FontAwesomeIcon icon={faHistory} className="me-2" />
                    Match History
                  </Button>
                  <Button variant="outline-primary" onClick={() => setActiveTab('stats')}>
                    <FontAwesomeIcon icon={faChartLine} className="me-2" />
                    Detailed Stats
                  </Button>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>

        <Tab eventKey="history" title="Match History">
          <Card>
            <Card.Header>
              <FontAwesomeIcon icon={faHistory} className="me-2" />
              Recent Matches
            </Card.Header>
            <Card.Body>
              {matchHistory.length === 0 ? (
                <div className="text-center py-4 text-muted">
                  <FontAwesomeIcon icon={faHistory} size="3x" className="mb-3 opacity-25" />
                  <p>No match history yet</p>
                  <small>Join some matches to see results here</small>
                </div>
              ) : (
                <Table responsive striped>
                  <thead>
                    <tr>
                      <th>Match</th>
                      <th>Date</th>
                      <th>Duration</th>
                      <th>Result</th>
                      <th>Score</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {matchHistory.map(match => (
                      <tr key={match.id}>
                        <td>
                          <strong>{match.name}</strong>
                          <br />
                          <small className="text-muted">{match.teams?.length} teams</small>
                        </td>
                        <td>
                          {new Date(match.startTime || match.createdAt).toLocaleDateString()}
                        </td>
                        <td>
                          {match.duration ? `${match.duration}m` : 'N/A'}
                        </td>
                        <td>
                          {formatMatchResult(match, team)}
                        </td>
                        <td>
                          {match.results?.find(r => r.teamId === team.id)?.score || 0}
                        </td>
                        <td>
                          <Button 
                            size="sm" 
                            variant="outline-primary"
                            onClick={() => navigate(`/cyberwar/match/${match.id}/scoreboard`)}
                          >
                            <FontAwesomeIcon icon={faEye} />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card.Body>
          </Card>
        </Tab>

        <Tab eventKey="stats" title="Statistics">
          <Row>
            <Col md={6}>
              <Card className="mb-4">
                <Card.Header>Performance Metrics</Card.Header>
                <Card.Body>
                  {teamStats ? (
                    <div className="row">
                      <div className="col-6 mb-3">
                        <div className="text-center">
                          <div className="h2 text-primary">{teamStats.matchesPlayed || 0}</div>
                          <small className="text-muted">Total Matches</small>
                        </div>
                      </div>
                      <div className="col-6 mb-3">
                        <div className="text-center">
                          <div className="h2 text-success">{teamStats.wins || 0}</div>
                          <small className="text-muted">Victories</small>
                        </div>
                      </div>
                      <div className="col-6 mb-3">
                        <div className="text-center">
                          <div className="h2 text-danger">{teamStats.losses || 0}</div>
                          <small className="text-muted">Defeats</small>
                        </div>
                      </div>
                      <div className="col-6 mb-3">
                        <div className="text-center">
                          <div className="h2 text-warning">{teamStats.totalPoints || 0}</div>
                          <small className="text-muted">Total Points</small>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <p className="text-muted">No statistics available yet</p>
                  )}
                </Card.Body>
              </Card>
            </Col>
            
            <Col md={6}>
              <Card>
                <Card.Header>Rankings & Achievements</Card.Header>
                <Card.Body>
                  {teamStats?.ranking && (
                    <div className="mb-3">
                      <h5>Current Ranking</h5>
                      <div className="d-flex align-items-center">
                        <div className="h3 text-warning me-3">#{teamStats.ranking}</div>
                        <div>
                          <div>Global Rank</div>
                          <small className="text-muted">Based on recent performance</small>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {teamStats?.achievements && teamStats.achievements.length > 0 && (
                    <div>
                      <h6>Recent Achievements</h6>
                      {teamStats.achievements.map((achievement, index) => (
                        <div key={index} className="d-flex align-items-center mb-2">
                          <FontAwesomeIcon icon={faTrophy} className="text-warning me-2" />
                          <span>{achievement.name}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>
      </Tabs>

      {/* Invite Member Modal */}
      <Modal show={showInvite} onHide={() => setShowInvite(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Invite Team Members</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Tabs defaultActiveKey="email">
            <Tab eventKey="email" title="By Email">
              <Form onSubmit={handleInviteMember} className="mt-3">
                <Form.Group className="mb-3">
                  <Form.Label>Email Address</Form.Label>
                  <Form.Control 
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    required
                    placeholder="Enter member's email"
                  />
                </Form.Group>
                <div className="d-grid">
                  <Button variant="primary" type="submit">
                    <FontAwesomeIcon icon={faEnvelope} className="me-1" />
                    Send Invitation
                  </Button>
                </div>
              </Form>
            </Tab>
            
            <Tab eventKey="link" title="Invite Link">
              <div className="mt-3">
                <p className="text-muted">Generate a shareable invite link:</p>
                {!inviteLink ? (
                  <div className="d-grid">
                    <Button variant="outline-primary" onClick={handleGenerateInviteLink}>
                      <FontAwesomeIcon icon={faPlus} className="me-1" />
                      Generate Link
                    </Button>
                  </div>
                ) : (
                  <div>
                    <Form.Group className="mb-3">
                      <Form.Label>Invite Link</Form.Label>
                      <div className="input-group">
                        <Form.Control 
                          type="text"
                          value={inviteLink}
                          readOnly
                        />
                        <Button 
                          variant="outline-secondary"
                          onClick={handleCopyInviteLink}
                        >
                          <FontAwesomeIcon icon={linkCopied ? faCheck : faCopy} />
                        </Button>
                      </div>
                    </Form.Group>
                    {linkCopied && (
                      <small className="text-success">Link copied to clipboard!</small>
                    )}
                  </div>
                )}
              </div>
            </Tab>
          </Tabs>
        </Modal.Body>
      </Modal>

      {/* Edit Team Modal */}
      <Modal show={showEdit} onHide={() => setShowEdit(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Edit Team</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form onSubmit={handleUpdateTeam}>
            <Form.Group className="mb-3">
              <Form.Label>Team Name</Form.Label>
              <Form.Control 
                type="text"
                value={editData.name}
                onChange={(e) => setEditData({...editData, name: e.target.value})}
                required
              />
            </Form.Group>
            
            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control 
                as="textarea"
                rows={3}
                value={editData.description}
                onChange={(e) => setEditData({...editData, description: e.target.value})}
              />
            </Form.Group>
            
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Team Color</Form.Label>
                  <Form.Control 
                    type="color"
                    value={editData.color}
                    onChange={(e) => setEditData({...editData, color: e.target.value})}
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
                    value={editData.maxMembers}
                    onChange={(e) => setEditData({...editData, maxMembers: parseInt(e.target.value)})}
                  />
                </Form.Group>
              </Col>
            </Row>

            <div className="d-grid gap-2 d-md-flex justify-content-md-end">
              <Button variant="secondary" onClick={() => setShowEdit(false)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                Save Changes
              </Button>
            </div>
          </Form>
        </Modal.Body>
      </Modal>

      {/* Remove Member Modal */}
      <Modal show={showRemoveMember} onHide={() => setShowRemoveMember(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Remove Team Member</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedMember && (
            <div>
              <p>Are you sure you want to remove <strong>{selectedMember.username}</strong> from the team?</p>
              <div className="d-grid gap-2 d-md-flex justify-content-md-end">
                <Button variant="secondary" onClick={() => setShowRemoveMember(false)}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={handleRemoveMember}>
                  Remove Member
                </Button>
              </div>
            </div>
          )}
        </Modal.Body>
      </Modal>
    </Container>
  );
};

export default TeamDetail;
