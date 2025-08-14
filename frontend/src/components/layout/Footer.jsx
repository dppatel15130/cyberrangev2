import React from 'react';
import { Container } from 'react-bootstrap';

const Footer = () => {
  return (
    <footer className="footer py-3 mt-auto scan-lines">
      <Container className="text-center">
        <p className="mb-0" style={{ color: 'var(--neon-cyan)', textShadow: '0 0 5px var(--neon-cyan)' }}>
          &copy; {new Date().getFullYear()} <span className="neon-pulse">Cyber Range Platform</span> | All Rights Reserved
        </p>
      </Container>
    </footer>
  );
};

export default Footer;