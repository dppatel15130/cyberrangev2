import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Container, Row, Col, Card, Table, Button, Badge, Alert, Spinner, Modal } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faFlask, 
  faPlus, 
  faEdit, 
  faTrash, 
  faUsers, 
  faExclamationTriangle,
  faGlobe,
  faEye
} from '@fortawesome/free-solid-svg-icons';
import { Link } from 'react-router-dom';
import axios from '../../utils/axiosConfig';

const ManageLabs = () => {
  const navigate = useNavigate();
  const [labs, setLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [labToDelete, setLabToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [labToAssign, setLabToAssign] = useState(null);
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [assignedUsers, setAssignedUsers] = useState([]);
  const [unassignedUsers, setUnassignedUsers] = useState([]);
  const [labTypeFilter, setLabTypeFilter] = useState('all');
  
  // Helper function to get badge color based on difficulty
  const getDifficultyBadgeColor = (difficulty) => {
    switch (difficulty?.toLowerCase()) {
      case 'easy':
      case 'beginner':
        return 'success';
      case 'medium':
      case 'intermediate':
        return 'warning';
      case 'hard':
      case 'advanced':
        return 'danger';
      default:
        return 'secondary';
    }
  };

  useEffect(() => {
    const fetchLabs = async () => {
      try {
        const res = await axios.get('/labs');
        console.log('Labs response:', res.data);
        const labsData = Array.isArray(res.data) ? res.data : [];
        setLabs(labsData);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching labs:', err);
        setError('Failed to load labs. Please try again later.');
        setLoading(false);
      }
    };

    fetchLabs();
  }, []);
  
  // Filter and group labs
  const labsByCategory = useMemo(() => {
    const filtered = labTypeFilter === 'all' 
      ? [...labs] 
      : labs.filter(lab => lab.labType === labTypeFilter);
    
    return filtered.reduce((acc, lab) => {
      const category = lab.category || 'Uncategorized';
      if (!acc[category]) {
        acc[category] = [];
      }
      acc[category].push(lab);
      return acc;
    }, {});
  }, [labs, labTypeFilter]);

  const handleDeleteClick = (lab) => {
    setLabToDelete(lab);
    setShowDeleteModal(true);
  };

  const handleAssignClick = async (lab) => {
    setLabToAssign(lab);
    setLoadingUsers(true);
    
    try {
      // Fetch all users
      const usersRes = await axios.get('/auth/users');
      setUsers(usersRes.data);
      
      // Determine which users are already assigned to this lab
      const assignedUserIds = (lab.assignedUsers || []).filter(Boolean).map(u => u.id || u._id || u);
      const assigned = usersRes.data.filter(user => 
        assignedUserIds.includes(user.id || user._id)
      );
      const unassigned = usersRes.data.filter(user => 
        !assignedUserIds.includes(user.id || user._id)
      );
      
      setAssignedUsers(assigned);
      setUnassignedUsers(unassigned);
      setShowAssignModal(true);
    } catch (err) {
      console.error('Error fetching users:', err);
      setError('Failed to load users for assignment. Please try again later.');
    } finally {
      setLoadingUsers(false);
    }
  };

  const handleDeleteLab = async () => {
    setDeleting(true);
    
    try {
      await axios.delete(`/labs/${labToDelete.id || labToDelete._id}`);
      
      // Remove the deleted lab from the list
      setLabs(labs.filter(lab => (lab.id || lab._id) !== (labToDelete.id || labToDelete._id)));
      
      setShowDeleteModal(false);
    } catch (err) {
      console.error('Error deleting lab:', err);
      setError('Failed to delete lab. Please try again later.');
    } finally {
      setDeleting(false);
    }
  };

  const handleAssignUser = async (userId) => {
    if (!userId) {
      setError('Invalid user ID');
      return;
    }
    try {
      await axios.post('/labs/assign', { labId: labToAssign.id || labToAssign._id, userIds: [userId] });
      
      // Update the assigned and unassigned lists
      const userToAssign = unassignedUsers.find(user => (user.id || user._id) === userId);
      
      if (userToAssign) {
        setAssignedUsers([...assignedUsers, userToAssign]);
        setUnassignedUsers(unassignedUsers.filter(user => (user.id || user._id) !== userId));
        
        // Update the labs list
        setLabs(labs.map(lab => {
          if ((lab.id || lab._id) === (labToAssign.id || labToAssign._id)) {
            return {
              ...lab,
              assignedUsers: [ ...(lab.assignedUsers || []), userId ]
            };
          }
          return lab;
        }));
      }
    } catch (err) {
      console.error('Error assigning user to lab:', err);
      setError('Failed to assign user to lab. Please try again later.');
    }
  };

  const handleUnassignUser = async (userId) => {
    if (!userId) {
      setError('Invalid user ID');
      return;
    }
    try {
      await axios.post('/labs/unassign', { labId: labToAssign.id || labToAssign._id, userIds: [userId] });
      
      // Update the assigned and unassigned lists
      const userToUnassign = assignedUsers.find(user => (user.id || user._id) === userId);
      
      if (userToUnassign) {
        setUnassignedUsers([...unassignedUsers, userToUnassign]);
        setAssignedUsers(assignedUsers.filter(user => (user.id || user._id) !== userId));
        
        // Update the labs list
        setLabs(labs.map(lab => {
          if ((lab.id || lab._id) === (labToAssign.id || labToAssign._id)) {
            return {
              ...lab,
              assignedUsers: (lab.assignedUsers || []).filter(id => id !== userId)
            };
          }
          return lab;
        }));
      }
    } catch (err) {
      console.error('Error unassigning user from lab:', err);
      setError('Failed to unassign user from lab. Please try again later.');
    }
  };

  const getDifficultyBadge = (difficulty) => {
    switch (difficulty) {
      case 'beginner':
        return <Badge bg="success">Beginner</Badge>;
      case 'intermediate':
        return <Badge bg="warning">Intermediate</Badge>;
      case 'advanced':
        return <Badge bg="danger">Advanced</Badge>;
      default:
        return <Badge bg="secondary">{difficulty}</Badge>;
    }
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" />
        <p className="mt-3">Loading labs...</p>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      <div className="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center mb-4 gap-3">
        <h2 className="m-0">
          <FontAwesomeIcon icon={faFlask} className="me-2" />
          Manage Labs
        </h2>
        <div className="d-flex flex-column flex-md-row gap-3">
          <div className="btn-group">
            <Button 
              variant={labTypeFilter === 'all' ? 'primary' : 'outline-secondary'}
              size="sm"
              onClick={() => setLabTypeFilter('all')}
            >
              All Labs
            </Button>
            <Button 
              variant={labTypeFilter === 'vm' ? 'primary' : 'outline-secondary'}
              size="sm"
              onClick={() => setLabTypeFilter('vm')}
            >
              <FontAwesomeIcon icon={faFlask} className="me-1" /> VM
            </Button>
            <Button 
              variant={labTypeFilter === 'web' ? 'primary' : 'outline-secondary'}
              size="sm"
              onClick={() => setLabTypeFilter('web')}
            >
              <FontAwesomeIcon icon={faGlobe} className="me-1" /> Web
            </Button>
          </div>
          
          <div className="btn-group">
            <Button 
              variant="outline-primary" 
              size="sm"
              onClick={() => navigate('/admin/labs/create')}
            >
              <FontAwesomeIcon icon={faPlus} className="me-1" />
              VM Lab
            </Button>
            <Button 
              variant="primary" 
              size="sm"
              onClick={() => navigate('/admin/weblabs/new')}
            >
              <FontAwesomeIcon icon={faPlus} className="me-1" />
              Web Lab
            </Button>
          </div>
        </div>
      </div>

      {error && (
        <Alert variant="danger" className="mb-4">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Card className="shadow-sm">
        <Card.Body>
          {Object.keys(labsByCategory).length === 0 ? (
        <Alert variant="info">No labs found. Create your first lab to get started.</Alert>
      ) : (
        Object.entries(labsByCategory).map(([category, categoryLabs]) => (
            <div key={category} className="mb-4">
              <h5 className="text-muted mb-3">{category}</h5>
              <Table striped bordered hover className="mb-4">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Difficulty</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Assigned Users</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {categoryLabs.map((lab) => (
                  <tr key={lab.id || lab._id}>
                    <td>
                      <div className="d-flex align-items-center">
                        {lab.labType === 'web' ? (
                          <FontAwesomeIcon icon={faGlobe} className="me-2 text-primary" />
                        ) : (
                          <FontAwesomeIcon icon={faFlask} className="me-2 text-secondary" />
                        )}
                        <div>
                          <div>{lab.name}</div>
                          <small className="text-muted">{lab.category}</small>
                        </div>
                      </div>
                    </td>
                    <td>
                      <Badge bg={getDifficultyBadgeColor(lab.difficulty)}>
                        {lab.difficulty.charAt(0).toUpperCase() + lab.difficulty.slice(1)}
                      </Badge>
                    </td>
                    <td>
                      {lab.labType === 'vm' ? 'VM Lab' : 
                       lab.labType === 'web' ? 'Web Lab' : 'Special'}
                    </td>
                    <td>
                      <Badge bg={lab.isActive ? 'success' : 'secondary'}>
                        {lab.isActive ? 'Active' : 'Inactive'}
                      </Badge>
                    </td>
                    <td>{lab.assignedUsers && lab.assignedUsers.length} Users</td>
                    <td>
                      <Button
                        variant="primary"
                        size="sm"
                        className="me-2"
                        onClick={() => navigate(
                          lab.labType === 'web' 
                            ? `/admin/weblabs/edit/${lab.id || lab._id}`
                            : `/admin/labs/edit/${lab.id || lab._id}`
                        )}
                        title="Edit"
                      >
                        <FontAwesomeIcon icon={faEdit} />
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        className="me-2"
                        onClick={() => handleDeleteClick(lab)}
                        title="Delete"
                      >
                        <FontAwesomeIcon icon={faTrash} />
                      </Button>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => handleAssignClick(lab)}
                        title="Assign Users"
                      >
                        <FontAwesomeIcon icon={faUsers} />
                      </Button>
                      {lab.labType === 'web' && (
                        <Button
                          variant="success"
                          size="sm"
                          className="ms-2"
                          onClick={() => navigate(`/weblabs/${lab.id || lab._id}`)}
                          title="Preview Web Lab"
                        >
                          <FontAwesomeIcon icon={faEye} />
                        </Button>
                      )}
                      {lab.labType === 'vm' && (
                        <Button
                          variant="success"
                          size="sm"
                          className="ms-2"
                          onClick={() => navigate(`/labs/${lab.id || lab._id}`)}
                          title="Preview VM Lab"
                        >
                          <FontAwesomeIcon icon={faEye} />
                        </Button>
                      )}
                    </td>
                  </tr>
                  ))}
                </tbody>
              </Table>
            </div>
        ))
      )}
        </Card.Body>
      </Card>

      {/* Delete Confirmation Modal */}
      <Modal show={showDeleteModal} onHide={() => setShowDeleteModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Confirm Deletion</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {labToDelete && (
            <p>
              Are you sure you want to delete the lab <strong>{labToDelete.name}</strong>? This action cannot be undone.
            </p>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowDeleteModal(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleDeleteLab} disabled={deleting}>
            {deleting ? (
              <>
                <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                Deleting...
              </>
            ) : 'Delete Lab'}
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Assign Users Modal */}
      <Modal 
        show={showAssignModal} 
        onHide={() => setShowAssignModal(false)} 
        centered
        size="lg"
      >
        <Modal.Header closeButton>
          <Modal.Title>
            {labToAssign && `Manage Users for ${labToAssign.name}`}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {loadingUsers ? (
            <div className="text-center py-3">
              <Spinner animation="border" variant="primary" />
              <p className="mt-2">Loading users...</p>
            </div>
          ) : (
            <Row>
              <Col md={6}>
                <h5>Assigned Users</h5>
                {assignedUsers.length === 0 ? (
                  <Alert variant="info">No users assigned to this lab.</Alert>
                ) : (
                  <div className="list-group">
                    {assignedUsers.map(user => (
                      <div key={user.id || user._id} className="list-group-item d-flex justify-content-between align-items-center">
                        <div>
                          <strong>{user.username}</strong>
                          <br />
                          <small className="text-muted">{user.email}</small>
                        </div>
                        <Button 
                          variant="outline-danger" 
                          size="sm"
                          onClick={() => handleUnassignUser(user.id || user._id)}
                        >
                          Remove
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </Col>
              <Col md={6}>
                <h5>Available Users</h5>
                {unassignedUsers.length === 0 ? (
                  <Alert variant="info">No available users to assign.</Alert>
                ) : (
                  <div className="list-group">
                    {unassignedUsers.map(user => (
                      <div key={user.id || user._id} className="list-group-item d-flex justify-content-between align-items-center">
                        <div>
                          <strong>{user.username}</strong>
                          <br />
                          <small className="text-muted">{user.email}</small>
                        </div>
                        <Button 
                          variant="outline-success" 
                          size="sm"
                          onClick={() => handleAssignUser(user.id || user._id)}
                        >
                          Assign
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </Col>
            </Row>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowAssignModal(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

export default ManageLabs;