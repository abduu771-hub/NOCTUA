import React from 'react';
import { Box, Container, Typography } from '@mui/material';

const LogsPage = () => {
  return (
    <Box sx={{ p: 4 }}>
      <Container maxWidth="xl">
        <Typography variant="h4" sx={{ fontFamily: "'ClashDisplay', sans-serif", fontWeight: 600, color: '#1a237e', mb: 2 }}>
          Logs
        </Typography>
        <Typography sx={{ fontFamily: "'ClashDisplay', sans-serif", color: '#546e7a' }}>
          Event logs viewer - Coming soon
        </Typography>
      </Container>
    </Box>
  );
};

export default LogsPage;
