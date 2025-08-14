import { useState, useEffect } from 'react';
import { Container, Card, Table, Button, Badge, Alert, Spinner, Modal, Form } from 'react-bootstrap';
import './AdminComponents.css';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUsers, faUserPlus, faEdit, faTrash, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';
import { Link } from 'react-router-dom';
import axios from '../../utils/axiosConfig';

const ManageUsers = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [formData, setFormData] = useState({
    role: ''
  });
  const [updating, setUpdating] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const res = await axios.get('/auth/users');
        console.log('Users response:', res.data);
        setUsers(Array.isArray(res.data) ? res.data : []);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching users:', err);
        setError('Failed to load users. Please try again later.');
        setLoading(false);
      }
    };

    fetchUsers();
  }, []);

  const handleEditClick = (user) => {
    setCurrentUser(user);
    setFormData({
      role: user.role
    });
    setShowEditModal(true);
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setUpdating(true);
    
    try {
      // Use the correct user ID field (id or _id) that exists on currentUser
      const userId = currentUser.id || currentUser._id;
      const res = await axios.put('/auth/users/role', { userId, role: formData.role });
      
      // Update the users list with the updated user
      setUsers(users.map(user => 
        (user.id === userId || user._id === userId) ? { ...user, role: formData.role } : user
      ));
      
      setShowEditModal(false);
    } catch (err) {
      console.error('Error updating user:', err);
      setError('Failed to update user. Please try again later.');
    } finally {
      setUpdating(false);
    }
  };

  const handleDeleteClick = (user) => {
    setCurrentUser(user);
    setShowDeleteModal(true);
  };

  const handleDeleteUser = async () => {
    if (!currentUser) return;
    
    setDeleting(true);
    try {
      // Ensure we're using the correct user ID from currentUser
      const userId = currentUser.id || currentUser._id;
      if (!userId) {
        throw new Error('User ID is missing');
      }
      
      await axios.delete(`/auth/users/${userId}`);
      
      // Remove the deleted user from the list
      setUsers(users.filter(user => (user.id || user._id) !== userId));
      setShowDeleteModal(false);
    } catch (err) {
      console.error('Error deleting user:', err);
      const errorMessage = err.response?.data?.message || 'Failed to delete user. Please try again later.';
      setError(errorMessage);
    } finally {
      setDeleting(false);
    }
  };

  const getRoleBadge = (role) => {
    switch (role) {
      case 'admin':
        return <Badge bg="danger">Admin</Badge>;
      case 'red_team':
        return <Badge bg="warning">Red Team</Badge>;
      case 'blue_team':
        return <Badge bg="primary">Blue Team</Badge>;
      default:
        return <Badge bg="secondary">{role}</Badge>;
    }
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" />
        <p className="mt-3">Loading users...</p>
      </Container>
    );
  }

  return (
    <Container className="users-management py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1 className="text-light">
          <FontAwesomeIcon icon={faUsers} className="me-2" />
          Manage Users
        </h1>
        <Button as={Link} to="/admin/users/create" variant="success">
          <FontAwesomeIcon icon={faUserPlus} className="me-2" />
          Add New User
        </Button>
      </div>

      {error && (
        <Alert variant="danger" className="mb-4">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Card className="shadow-sm bg-dark text-light border-secondary">
        <Card.Body className="bg-dark">
          {users.length === 0 ? (
            <Alert variant="info" className="bg-dark text-light border-info">
              No users found.
            </Alert>
          ) : (
            <Table responsive hover variant="dark" className="text-light">
              <thead className="bg-dark">
                <tr>
                  <th className="text-light">Username</th>
                  <th className="text-light">Email</th>
                  <th className="text-light">Role</th>
                  <th className="text-light">Created At</th>
                  <th className="text-light">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user, index) => (
                  <tr key={user.id || user._id || `user-${index}`}>
                    <td>{user.username}</td>
                    <td>{user.email}</td>
                    <td>{getRoleBadge(user.role)}</td>
                    <td>{new Date(user.createdAt).toLocaleDateString()}</td>
                    <td>
                      <div className="d-flex gap-2">
                        <Button
                          variant="outline-primary"
                          size="sm"
                          onClick={() => handleEditClick(user)}
                        >
                          <FontAwesomeIcon icon={faEdit} className="me-1" />
                          Edit Role
                        </Button>
                        <Button
                          variant="outline-danger"
                          size="sm"
                          onClick={() => handleDeleteClick(user)}
                          disabled={user.role === 'admin'}
                          title={user.role === 'admin' ? 'Cannot delete admin users' : 'Delete User'}
                        >
                          <FontAwesomeIcon icon={faTrash} />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card.Body>
      </Card>

      {/* Edit User Modal */}
      <Modal 
        show={showEditModal} 
        onHide={() => setShowEditModal(false)} 
        centered
        contentClassName="bg-dark text-light"
      >
        <Modal.Header closeButton closeVariant="white" className="bg-dark border-secondary">
          <Modal.Title className="text-light">Edit User Role</Modal.Title>
        </Modal.Header>
        <Form onSubmit={handleSubmit}>
          <Modal.Body>
            {currentUser && (
              <>
                <p>
                  <strong>Username:</strong> {currentUser.username}
                </p>
                <p>
                  <strong>Email:</strong> {currentUser.email}
                </p>
                <Form.Group className="mb-3">
                  <Form.Label>Role</Form.Label>
                  <Form.Select
                    name="role"
                    value={formData.role}
                    onChange={handleInputChange}
                    required
                  >
                    <option value="">Select Role</option>
                    <option value="admin">Admin</option>
                    <option value="red_team">Red Team</option>
                    <option value="blue_team">Blue Team</option>
                  </Form.Select>
                </Form.Group>
              </>
            )}
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => setShowEditModal(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={updating}>
              {updating ? (
                <>
                  <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                  Updating...
                </>
              ) : 'Save Changes'}
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal 
        show={showDeleteModal} 
        onHide={() => !deleting && setShowDeleteModal(false)} 
        centered
        contentClassName="bg-dark text-light"
      >
        <Modal.Header closeButton={!deleting} closeVariant="white" className="bg-dark border-secondary">
          <Modal.Title className="text-light">Confirm Deletion</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Are you sure you want to delete the user <strong>{currentUser?.username}</strong>?</p>
          <p className="text-danger">This action cannot be undone.</p>
        </Modal.Body>
        <Modal.Footer>
          <Button 
            variant="secondary" 
            onClick={() => setShowDeleteModal(false)}
            disabled={deleting}
          >
            Cancel
          </Button>
          <Button 
            variant="danger" 
            onClick={handleDeleteUser}
            disabled={deleting}
          >
            {deleting ? (
              <>
                <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                Deleting...
              </>
            ) : 'Delete User'}
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

export default ManageUsers;