import { useState, useEffect, useContext } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  Container, 
  Row, 
  Col, 
  Card, 
  Button, 
  Badge, 
  Alert, 
  Spinner,
  Form,
  InputGroup,
  Dropdown,
  ButtonGroup,
  Tab,
  Tabs
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faFlask, 
  faInfoCircle, 
  faExclamationTriangle, 
  faTrophy,
  faPlay,
  faDesktop,
  faGlobe,
  faCode,
  faSearch,
  faFilter,
  faSortAmountDown,
  faSortAmountUp,
  faLaptopCode,
  faNetworkWired,
  faBug,
  faShieldAlt
} from '@fortawesome/free-solid-svg-icons';
import axios from '../utils/axiosConfig';
import { AuthContext } from '../context/AuthContext';

const Labs = () => {
  const [labs, setLabs] = useState([]);
  const [webLabs, setWebLabs] = useState([]);
  const [filteredLabs, setFilteredLabs] = useState([]);
  const [filteredWebLabs, setFilteredWebLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('traditional');
  const [searchTerm, setSearchTerm] = useState('');
  const [difficultyFilter, setDifficultyFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [sortBy, setSortBy] = useState('name');
  const [sortOrder, setSortOrder] = useState('asc');
  const [userStats, setUserStats] = useState({ totalPoints: 0 });

  const { user } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchLabsData = async () => {
      try {
        setLoading(true);
        
        const [labsRes, webLabsRes, userStatsRes] = await Promise.all([
          axios.get('/labs'),
          axios.get('/weblabs').catch(() => ({ data: [] })),
          axios.get('/flags/user-stats').catch(() => ({ data: { user: { totalPoints: 0 } } }))
        ]);
        
        const labsData = Array.isArray(labsRes.data) ? labsRes.data : [];
        const webLabsData = Array.isArray(webLabsRes.data) ? webLabsRes.data : [];
        
        setLabs(labsData);
        setWebLabs(webLabsData);
        setFilteredLabs(labsData);
        setFilteredWebLabs(webLabsData);
        setUserStats(userStatsRes.data.user || { totalPoints: 0 });
        
        setLoading(false);
      } catch (err) {
        console.error('Error fetching labs:', err);
        setError('Failed to load labs. Please try again later.');
        setLoading(false);
      }
    };

    fetchLabsData();
  }, []);

  // Filter and sort effects
  useEffect(() => {
    applyFiltersAndSorting();
  }, [labs, webLabs, searchTerm, difficultyFilter, categoryFilter, sortBy, sortOrder]);

  const applyFiltersAndSorting = () => {
    const filterAndSort = (labsArray) => {
      let filtered = labsArray.filter(lab => {
        const matchesSearch = lab.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            lab.description?.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesDifficulty = difficultyFilter === 'all' || lab.difficulty === difficultyFilter;
        const matchesCategory = categoryFilter === 'all' || lab.category === categoryFilter;
        
        return matchesSearch && matchesDifficulty && matchesCategory;
      });

      // Sort
      filtered.sort((a, b) => {
        let aValue, bValue;
        
        switch (sortBy) {
          case 'difficulty':
            const difficultyOrder = { beginner: 1, intermediate: 2, advanced: 3 };
            aValue = difficultyOrder[a.difficulty] || 0;
            bValue = difficultyOrder[b.difficulty] || 0;
            break;
          case 'category':
            aValue = a.category || '';
            bValue = b.category || '';
            break;
          default:
            aValue = a.name || '';
            bValue = b.name || '';
        }
        
        if (typeof aValue === 'string') {
          aValue = aValue.toLowerCase();
          bValue = bValue.toLowerCase();
        }
        
        if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
        if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
        return 0;
      });

      return filtered;
    };

    setFilteredLabs(filterAndSort(labs));
    setFilteredWebLabs(filterAndSort(webLabs));
  };

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

  const getCategoryIcon = (category) => {
    switch (category?.toLowerCase()) {
      case 'web security':
      case 'web':
        return faGlobe;
      case 'network':
      case 'networking':
        return faNetworkWired;
      case 'reverse engineering':
      case 'reversing':
        return faBug;
      case 'cryptography':
      case 'crypto':
        return faShieldAlt;
      case 'programming':
      case 'coding':
        return faCode;
      default:
        return faLaptopCode;
    }
  };

  const getUniqueValues = (array, field) => {
    return [...new Set(array.map(item => item[field]).filter(Boolean))];
  };

  if (loading) {
    return (
      <Container className="py-5">
        <div className="loading-container">
          <Spinner animation="border" variant="primary" />
          <p className="mt-3 text-accent">Loading labs...</p>
        </div>
      </Container>
    );
  }

  if (error) {
    return (
      <Container className="py-5">
        <Alert variant="danger" className="text-center">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
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
              <h1 className="display-5 fw-bold text-accent mb-2">
                <FontAwesomeIcon icon={faFlask} className="me-3" />
                Cybersecurity Labs
              </h1>
              <p className="lead text-secondary mb-0">
                Enhance your skills with hands-on security challenges
              </p>
            </div>
            <Card className="border-0 bg-gradient">
              <Card.Body className="text-center p-3">
                <FontAwesomeIcon icon={faTrophy} size="lg" className="text-warning mb-1" />
                <div className="fw-bold">{userStats.totalPoints || 0}</div>
                <small className="text-muted">Total Points</small>
              </Card.Body>
            </Card>
          </div>
        </Col>
      </Row>

      {/* Filters and Search */}
      <Row className="mb-4">
        <Col lg={6}>
          <InputGroup>
            <InputGroup.Text>
              <FontAwesomeIcon icon={faSearch} />
            </InputGroup.Text>
            <Form.Control
              type="text"
              placeholder="Search labs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </InputGroup>
        </Col>
        <Col lg={6}>
          <Row>
            <Col sm={4}>
              <Form.Select
                value={difficultyFilter}
                onChange={(e) => setDifficultyFilter(e.target.value)}
              >
                <option value="all">All Difficulties</option>
                <option value="beginner">Beginner</option>
                <option value="intermediate">Intermediate</option>
                <option value="advanced">Advanced</option>
              </Form.Select>
            </Col>
            <Col sm={4}>
              <Form.Select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
              >
                <option value="all">All Categories</option>
                {getUniqueValues([...labs, ...webLabs], 'category').map(category => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </Form.Select>
            </Col>
            <Col sm={4}>
              <ButtonGroup className="w-100">
                <Dropdown>
                  <Dropdown.Toggle variant="outline-secondary" className="w-100">
                    <FontAwesomeIcon icon={sortOrder === 'asc' ? faSortAmountDown : faSortAmountUp} className="me-2" />
                    Sort
                  </Dropdown.Toggle>
                  <Dropdown.Menu>
                    <Dropdown.Item onClick={() => { setSortBy('name'); setSortOrder('asc'); }}>
                      Name (A-Z)
                    </Dropdown.Item>
                    <Dropdown.Item onClick={() => { setSortBy('name'); setSortOrder('desc'); }}>
                      Name (Z-A)
                    </Dropdown.Item>
                    <Dropdown.Item onClick={() => { setSortBy('difficulty'); setSortOrder('asc'); }}>
                      Difficulty (Easy-Hard)
                    </Dropdown.Item>
                    <Dropdown.Item onClick={() => { setSortBy('difficulty'); setSortOrder('desc'); }}>
                      Difficulty (Hard-Easy)
                    </Dropdown.Item>
                  </Dropdown.Menu>
                </Dropdown>
              </ButtonGroup>
            </Col>
          </Row>
        </Col>
      </Row>

      {/* Labs Tabs */}
      <Tabs 
        activeKey={activeTab} 
        onSelect={(k) => setActiveTab(k)} 
        className="mb-4 custom-tabs"
        fill
      >
        <Tab eventKey="traditional" title={
          <>
            <FontAwesomeIcon icon={faDesktop} className="me-2" />
            Traditional Labs ({filteredLabs.length})
          </>
        }>
          <Row>
            {filteredLabs.length > 0 ? (
              filteredLabs.map((lab) => (
                <Col xl={4} lg={6} key={lab.id || lab._id} className="mb-4">
                  <Card className="h-100 lab-card">
                    <Card.Body>
                      <div className="d-flex justify-content-between align-items-start mb-3">
                        <Card.Title className="mb-0 flex-grow-1">{lab.name}</Card.Title>
                        {getDifficultyBadge(lab.difficulty)}
                      </div>
                      
                      <Card.Text className="text-muted mb-3">
                        {lab.description}
                      </Card.Text>
                      
                      <div className="d-flex justify-content-between align-items-center">
                        <div className="small text-muted">
                          <FontAwesomeIcon icon={getCategoryIcon(lab.category)} className="me-2" />
                          {lab.category || 'General'}
                        </div>
                        <Button 
                          as={Link} 
                          to={`/labs/${lab.id || lab._id}`} 
                          variant="outline-primary" 
                          size="sm"
                        >
                          <FontAwesomeIcon icon={faPlay} className="me-1" />
                          Start Lab
                        </Button>
                      </div>
                    </Card.Body>
                  </Card>
                </Col>
              ))
            ) : (
              <Col>
                <Alert variant="info" className="text-center">
                  <FontAwesomeIcon icon={faInfoCircle} className="me-2" />
                  {searchTerm || difficultyFilter !== 'all' || categoryFilter !== 'all' 
                    ? 'No labs match your current filters.' 
                    : 'No traditional labs available at the moment.'}
                </Alert>
              </Col>
            )}
          </Row>
        </Tab>

        <Tab eventKey="web" title={
          <>
            <FontAwesomeIcon icon={faGlobe} className="me-2" />
            Web Labs ({filteredWebLabs.length})
          </>
        }>
          <Row>
            {filteredWebLabs.length > 0 ? (
              filteredWebLabs.map((lab) => (
                <Col xl={4} lg={6} key={lab.id || lab._id} className="mb-4">
                  <Card className="h-100 lab-card">
                    <Card.Body>
                      <div className="d-flex justify-content-between align-items-start mb-3">
                        <Card.Title className="mb-0 flex-grow-1">{lab.name}</Card.Title>
                        {getDifficultyBadge(lab.difficulty)}
                      </div>
                      
                      <Card.Text className="text-muted mb-3">
                        {lab.description}
                      </Card.Text>
                      
                      <div className="d-flex justify-content-between align-items-center">
                        <div className="small text-muted">
                          <FontAwesomeIcon icon={faCode} className="me-2" />
                          {lab.category || 'Web Security'}
                        </div>
                        <Button 
                          as={Link} 
                          to={`/weblabs/${lab.id || lab._id}`} 
                          variant="outline-success" 
                          size="sm"
                        >
                          <FontAwesomeIcon icon={faPlay} className="me-1" />
                          Start Lab
                        </Button>
                      </div>
                    </Card.Body>
                  </Card>
                </Col>
              ))
            ) : (
              <Col>
                <Alert variant="info" className="text-center">
                  <FontAwesomeIcon icon={faInfoCircle} className="me-2" />
                  {searchTerm || difficultyFilter !== 'all' || categoryFilter !== 'all' 
                    ? 'No web labs match your current filters.' 
                    : 'No web labs available at the moment.'}
                </Alert>
              </Col>
            )}
          </Row>
        </Tab>
      </Tabs>

      {/* Quick Navigation */}
      <Row className="mt-5">
        <Col>
          <Card className="border-secondary">
            <Card.Header>
              <FontAwesomeIcon icon={faInfoCircle} className="me-2" />
              Looking for more challenges?
            </Card.Header>
            <Card.Body>
              <Row>
                <Col md={6}>
                  <h6 className="text-accent">🔥 Cyber Warfare</h6>
                  <p className="text-muted mb-3">
                    Join team-based competitions with real-time scoring and VM environments.
                  </p>
                  <Button variant="primary" as={Link} to="/cyberwar/lobby">
                    <FontAwesomeIcon icon={faFlask} className="me-2" />
                    Enter Cyber Warfare
                  </Button>
                </Col>
                <Col md={6}>
                  <h6 className="text-accent">🏆 Leaderboard</h6>
                  <p className="text-muted mb-3">
                    See how you rank against other cybersecurity enthusiasts.
                  </p>
                  <Button variant="outline-secondary" as={Link} to="/cyberwar/leaderboard">
                    <FontAwesomeIcon icon={faTrophy} className="me-2" />
                    View Rankings
                  </Button>
                </Col>
              </Row>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default Labs;
