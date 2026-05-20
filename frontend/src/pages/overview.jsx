// src/pages/overview.jsx
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Helmet } from 'react-helmet-async';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Stack,
  IconButton,
  Paper,
  Divider,
  Alert,
  Slide,
  Fade,
  Snackbar,
  Button
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Whatshot as WhatshotIcon,
  Security as SecurityIcon,
  Storage as StorageIcon,
  NotificationsActive as NotificationsActiveIcon,
  Refresh as RefreshIcon,
  Circle as CircleIcon,
  Bolt as BoltIcon,
  AccountCircle as AccountCircleIcon,
  Devices as DevicesIcon,
  Router as RouterIcon,
  Schedule as ScheduleIcon,
  Close as CloseIcon
} from '@mui/icons-material';
import { keyframes } from '@mui/system';

// Animation keyframes for number changes
const pulse = keyframes`
  0% { transform: scale(1); }
  50% { transform: scale(1.05); }
  100% { transform: scale(1); }
`;

const glow = keyframes`
  0% { box-shadow: 0 0 0 0 rgba(26, 35, 126, 0.3); }
  70% { box-shadow: 0 0 0 10px rgba(26, 35, 126, 0); }
  100% { box-shadow: 0 0 0 0 rgba(26, 35, 126, 0); }
`;

const slideIn = keyframes`
  from {
    transform: translateX(100%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
`;

const API_BASE_URL = 'http://localhost:8000';

// Incident type configuration
const incidentTypeConfig = {
  brute_force_attack: { icon: '🔨', label: 'SSH Brute Force', severity: 'high', color: '#ff9800' },
  password_spray_attack: { icon: '🌧️', label: 'Password Spray', severity: 'high', color: '#ff9800' },
  distributed_bruteforce_attack: { icon: '🌐', label: 'Distributed Brute Force', severity: 'critical', color: '#f44336' },
  targeted_account_attack: { icon: '🎯', label: 'Targeted Account Attack', severity: 'critical', color: '#f44336' },
  account_compromise: { icon: '🔥', label: 'Account Compromise', severity: 'critical', color: '#f44336' },
  privilege_escalation_attempt: { icon: '⬆️', label: 'Privilege Escalation', severity: 'high', color: '#ff9800' },
  default: { icon: '⚠️', label: 'Security Incident', severity: 'medium', color: '#ffc107' }
};

// Alert severity config
const alertSeverityConfig = {
  critical: { color: '#f44336', icon: <ErrorIcon sx={{ fontSize: 14 }} /> },
  high: { color: '#ff9800', icon: <WarningIcon sx={{ fontSize: 14 }} /> },
  medium: { color: '#ffc107', icon: <InfoIcon sx={{ fontSize: 14 }} /> },
  low: { color: '#2196f3', icon: <InfoIcon sx={{ fontSize: 14 }} /> }
};

// Status config
const statusConfig = {
  open: { color: '#f44336', label: 'Open' },
  investigating: { color: '#ff9800', label: 'Investigating' },
  closed: { color: '#4caf50', label: 'Closed' },
  escalated: { color: '#9c27b0', label: 'Escalated' }
};

// Notification component
const NotificationBanner = ({ notification, onClose }) => {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setVisible(false);
      setTimeout(() => onClose(notification.id), 300);
    }, notification.type === 'incident' ? 10000 : 6000);
    return () => clearTimeout(timer);
  }, [notification.id, notification.type, onClose]);

  return (
    <Slide direction="left" in={visible} mountOnEnter unmountOnExit>
      <Paper
        sx={{
          p: 2,
          mb: 1,
          borderRadius: 2,
          bgcolor: notification.type === 'incident' ? '#ffebee' : '#fff3e0',
          borderLeft: `4px solid ${notification.type === 'incident' ? '#f44336' : '#ff9800'}`,
          animation: `${slideIn} 0.3s ease-out`,
          cursor: 'pointer',
          '&:hover': { opacity: 0.9 }
        }}
        onClick={() => notification.onClick()}
      >
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <Stack direction="row" spacing={1} alignItems="center">
            {notification.type === 'incident' ? (
              <WhatshotIcon sx={{ color: '#f44336', fontSize: 20 }} />
            ) : (
              <WarningIcon sx={{ color: '#ff9800', fontSize: 20 }} />
            )}
            <Box>
              <Typography variant="subtitle2" fontWeight="bold">
                {notification.title}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                {notification.message}
              </Typography>
            </Box>
          </Stack>
          <IconButton size="small" onClick={(e) => { e.stopPropagation(); setVisible(false); setTimeout(() => onClose(notification.id), 300); }}>
            <CloseIcon sx={{ fontSize: 16 }} />
          </IconButton>
        </Box>
      </Paper>
    </Slide>
  );
};

const OverviewPage = () => {
  const navigate = useNavigate();
  
  // State for data
  const [overview, setOverview] = useState(null);
  const [latestIncidents, setLatestIncidents] = useState([]);
  const [latestAlerts, setLatestAlerts] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());
  const [animatedCards, setAnimatedCards] = useState({});
  
  // Track seen IDs to avoid duplicate notifications
  const seenIncidentIds = useRef(new Set());
  const seenAlertIds = useRef(new Set());
  const previousOverview = useRef(null);

  // Format source IPs
  const formatSourceIPs = (ips) => {
    if (!ips || ips.length === 0) return '-';
    if (ips.length === 1) return ips[0];
    return `${ips[0]} (+${ips.length - 1})`;
  };

  // Navigate to incident with drawer open
  const handleIncidentClick = (incidentId) => {
    navigate(`/incidents?id=${incidentId}`);
  };

  // Navigate to alert with drawer open
  const handleAlertClick = (alertId) => {
    navigate(`/alerts?id=${alertId}`);
  };

  // Check for new data and create notifications
  const checkForNewData = (newIncidents, newAlerts) => {
    const newNotifications = [];
    
    // Check for new incidents
    newIncidents.forEach(incident => {
      const incidentId = incident.id || incident._id;
      if (!seenIncidentIds.current.has(incidentId)) {
        seenIncidentIds.current.add(incidentId);
        const typeConfig = incidentTypeConfig[incident.type] || incidentTypeConfig.default;
        newNotifications.push({
          id: `incident-${incidentId}`,
          type: 'incident',
          title: incident.incident?.escalated ? '⚠️ Incident Escalated' : '🚨 Incident Created',
          message: `${typeConfig.label} on ${incident.host || 'unknown host'}`,
          onClick: () => handleIncidentClick(incidentId)
        });
      }
    });
    
    // Check for new alerts
    newAlerts.forEach(alert => {
      const alertId = alert._id;
      if (!seenAlertIds.current.has(alertId)) {
        seenAlertIds.current.add(alertId);
        newNotifications.push({
          id: `alert-${alertId}`,
          type: 'alert',
          title: '⚠️ Alert Detected',
          message: `${alert.rule?.name || 'Security Alert'} from ${alert.source?.ip || alert.host?.name || 'unknown source'}`,
          onClick: () => handleAlertClick(alertId)
        });
      }
    });
    
    if (newNotifications.length > 0) {
      setNotifications(prev => [...newNotifications, ...prev]);
    }
  };

  // Remove notification
  const removeNotification = (notificationId) => {
    setNotifications(prev => prev.filter(n => n.id !== notificationId));
  };

  // Animate KPI card
  const animateCard = (key) => {
    setAnimatedCards(prev => ({ ...prev, [key]: true }));
    setTimeout(() => {
      setAnimatedCards(prev => ({ ...prev, [key]: false }));
    }, 500);
  };

  // Check for KPI changes
  const checkKPIChanges = (newOverview) => {
    if (previousOverview.current) {
      if (previousOverview.current.total_alerts !== newOverview.total_alerts) {
        animateCard('total_alerts');
      }
      if (previousOverview.current.total_incidents !== newOverview.total_incidents) {
        animateCard('total_incidents');
      }
      if (previousOverview.current.open_incidents !== newOverview.open_incidents) {
        animateCard('open_incidents');
      }
      if (previousOverview.current.critical_alerts !== newOverview.critical_alerts) {
        animateCard('critical_alerts');
      }
      if (previousOverview.current.total_events !== newOverview.total_events) {
        animateCard('total_events');
      }
    }
    previousOverview.current = newOverview;
  };

  // Fetch overview data
  const fetchOverview = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/overview`);
      if (response.ok) {
        const data = await response.json();
        checkKPIChanges(data);
        setOverview(data);
      }
    } catch (err) {
      console.error('Overview fetch error:', err);
    }
  }, []);

  // Fetch latest incidents
  const fetchLatestIncidents = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/incidents?size=2`);
      if (response.ok) {
        const data = await response.json();
        const mappedIncidents = data.map(incident => ({
          id: incident._id,
          incident_id: incident.incident?.id || incident._id?.slice(-8),
          type: incident.incident?.incident_type || 'security_incident',
          status: incident.incident?.status || 'open',
          alert_count: incident.incident?.alert_count || 0,
          primary_user: incident.attack_context?.primary_user || incident.attack_context?.users_seen?.[0] || 'Unknown',
          host: incident.host?.name || 'Unknown',
          source_ips: incident.attack_context?.source_ips_seen || [],
          first_seen: incident.created_at,
          last_seen: incident.updated_at,
          updated_at: incident.updated_at,
          escalated: incident.incident?.type === 'account_compromise'
        }));
        
        // Check for new incidents
        checkForNewData(mappedIncidents, []);
        setLatestIncidents(mappedIncidents);
      }
    } catch (err) {
      console.error('Incidents fetch error:', err);
    }
  }, []);

  // Fetch latest alerts
  const fetchLatestAlerts = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/alerts?size=2`);
      if (response.ok) {
        const data = await response.json();
        const mappedAlerts = data.map(alert => ({
          _id: alert._id,
          severity: alert.rule?.severity || 'medium',
          rule_name: alert.rule?.name || alert.rule?.description || 'Security Alert',
          rule_id: alert.rule?.id,
          source_ip: alert.source?.ip,
          user: alert.user?.name,
          host: alert.host?.name,
          timestamp: alert['@timestamp'],
          description: alert.message || alert.rule?.description
        }));
        
        // Check for new alerts
        checkForNewData([], mappedAlerts);
        setLatestAlerts(mappedAlerts);
      }
    } catch (err) {
      console.error('Alerts fetch error:', err);
    }
  }, []);

  // Refresh all data
  const refreshData = useCallback(async () => {
    await Promise.all([
      fetchOverview(),
      fetchLatestIncidents(),
      fetchLatestAlerts()
    ]);
    setLastRefreshed(new Date());
  }, [fetchOverview, fetchLatestIncidents, fetchLatestAlerts]);

  // Manual refresh
  const handleManualRefresh = () => {
    refreshData();
  };

  // Auto-refresh every 2 seconds
  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 2000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // Get incident display config
  const getIncidentDisplay = (type) => {
    return incidentTypeConfig[type] || incidentTypeConfig.default;
  };

  // Get alert severity config
  const getAlertSeverity = (severity) => {
    return alertSeverityConfig[severity?.toLowerCase()] || alertSeverityConfig.medium;
  };

  return (
    <>
      <Helmet>
        <title>Security Overview | Abur SIEM</title>
      </Helmet>

      <Box sx={{ py: 4, px: 3, bgcolor: '#f5f5f5', minHeight: '100vh' }}>
        <Container maxWidth="xl">
          {/* Header */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
            <Box>
              <Typography variant="h4" sx={{ fontFamily: "'ClashDisplay', sans-serif", fontWeight: 600, color: '#1a237e' }}>
                Security Overview
              </Typography>
              <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 1 }}>
                <Chip
                  icon={<CircleIcon sx={{ fontSize: 10, color: '#4caf50' }} />}
                  label="Live monitoring active"
                  size="small"
                  sx={{ bgcolor: '#e8f5e9', color: '#2e7d32' }}
                />
                <Typography variant="caption" color="textSecondary">
                  Last refreshed: {lastRefreshed.toLocaleTimeString()}
                </Typography>
              </Stack>
            </Box>
            <IconButton onClick={handleManualRefresh} sx={{ bgcolor: 'white', boxShadow: 1 }}>
              <RefreshIcon />
            </IconButton>
          </Box>

          {/* KPI Cards */}
          {overview && (
            <Grid container spacing={3} sx={{ mb: 4 }}>
              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ 
                  borderRadius: 3, 
                  boxShadow: 2,
                  animation: animatedCards.total_events ? `${pulse} 0.5s ease` : 'none'
                }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Total Events</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#1a237e">
                      {overview.total_events?.toLocaleString() || 0}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">All time</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ 
                  borderRadius: 3, 
                  boxShadow: 2,
                  animation: animatedCards.total_alerts ? `${pulse} 0.5s ease` : 'none'
                }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Total Alerts</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#ff9800">
                      {overview.total_alerts || 0}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">Total detections</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ 
                  borderRadius: 3, 
                  boxShadow: 2,
                  animation: animatedCards.open_incidents ? `${pulse} 0.5s ease` : 'none'
                }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Open Incidents</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#f44336">
                      {overview.open_incidents || 0}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">Need investigation</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ 
                  borderRadius: 3, 
                  boxShadow: 2,
                  animation: animatedCards.critical_alerts ? `${pulse} 0.5s ease` : 'none'
                }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Critical Threats</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#f44336">
                      {overview.critical_alerts || 0}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">Immediate attention</Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}

          {/* Live Status Strip */}
          <Paper sx={{ p: 2, mb: 4, borderRadius: 3, bgcolor: '#1a237e' }}>
            <Grid container spacing={2} alignItems="center">
              <Grid item>
                <Chip icon={<CheckCircleIcon />} label="Detection Engine Online" size="small" sx={{ bgcolor: '#2e7d32', color: 'white' }} />
              </Grid>
              <Grid item>
                <Chip icon={<CheckCircleIcon />} label="API Connected" size="small" sx={{ bgcolor: '#2e7d32', color: 'white' }} />
              </Grid>
              <Grid item>
                <Chip icon={<RefreshIcon />} label="Auto Refresh ON (2s)" size="small" sx={{ bgcolor: '#ff9800', color: 'white' }} />
              </Grid>
              <Grid item>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Last update: {lastRefreshed.toLocaleTimeString()}
                </Typography>
              </Grid>
              <Grid item>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Latest alert: {latestAlerts[0]?.timestamp ? new Date(latestAlerts[0].timestamp).toLocaleTimeString() : '-'}
                </Typography>
              </Grid>
              <Grid item>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Latest incident: {latestIncidents[0]?.last_seen ? new Date(latestIncidents[0].last_seen).toLocaleTimeString() : '-'}
                </Typography>
              </Grid>
            </Grid>
          </Paper>

          {/* Two Column Layout */}
          <Grid container spacing={4}>
            {/* Latest Incidents Panel */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 3, height: '100%' }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
                  <Typography variant="h6" fontWeight="bold" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <WhatshotIcon color="error" /> Latest Incidents
                  </Typography>
                  <Chip label={`${latestIncidents.length} active`} size="small" color="error" />
                </Stack>
                
                {latestIncidents.length === 0 ? (
                  <Typography color="textSecondary">No incidents found</Typography>
                ) : (
                  <Stack spacing={2}>
                    {latestIncidents.map((incident, idx) => {
                      const display = getIncidentDisplay(incident.type);
                      return (
                        <Card 
                          key={incident.id || idx}
                          sx={{ 
                            cursor: 'pointer',
                            transition: 'transform 0.2s, box-shadow 0.2s',
                            '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 },
                            borderLeft: `4px solid ${display.color}`,
                            animation: idx === 0 && notifications.some(n => n.id.includes(incident.id)) ? `${glow} 0.5s ease` : 'none'
                          }}
                          onClick={() => handleIncidentClick(incident.id)}
                        >
                          <CardContent>
                            <Stack direction="row" justifyContent="space-between" alignItems="flex-start" sx={{ mb: 2 }}>
                              <Stack direction="row" spacing={1} alignItems="center">
                                <Typography variant="h6" sx={{ fontSize: '1.1rem' }}>{display.icon}</Typography>
                                <Typography variant="subtitle1" fontWeight="bold">{display.label}</Typography>
                                {incident.escalated && <Chip label="ESCALATED" size="small" color="error" />}
                              </Stack>
                              <Chip 
                                label={statusConfig[incident.status]?.label || incident.status} 
                                size="small"
                                sx={{ bgcolor: statusConfig[incident.status]?.color, color: 'white' }}
                              />
                            </Stack>
                            
                            <Grid container spacing={2} sx={{ mb: 2 }}>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <AccountCircleIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">{incident.primary_user}</Typography>
                                </Stack>
                              </Grid>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <DevicesIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">{incident.host}</Typography>
                                </Stack>
                              </Grid>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <RouterIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">{formatSourceIPs(incident.source_ips)}</Typography>
                                </Stack>
                              </Grid>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <ScheduleIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">Alert count: {incident.alert_count}</Typography>
                                </Stack>
                              </Grid>
                            </Grid>
                            
                            <Divider sx={{ my: 1 }} />
                            
                            <Stack direction="row" justifyContent="space-between">
                              <Typography variant="caption" color="textSecondary">
                                First seen: {new Date(incident.first_seen).toLocaleString()}
                              </Typography>
                              <Typography variant="caption" color="textSecondary">
                                Updated: {new Date(incident.updated_at).toLocaleString()}
                              </Typography>
                            </Stack>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </Stack>
                )}
              </Paper>
            </Grid>

            {/* Latest Alerts Panel */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 3, height: '100%' }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
                  <Typography variant="h6" fontWeight="bold" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <WarningIcon color="warning" /> Latest Alerts
                  </Typography>
                  <Chip label={`${latestAlerts.length} recent`} size="small" color="warning" />
                </Stack>
                
                {latestAlerts.length === 0 ? (
                  <Typography color="textSecondary">No alerts found</Typography>
                ) : (
                  <Stack spacing={2}>
                    {latestAlerts.map((alert, idx) => {
                      const severity = getAlertSeverity(alert.severity);
                      return (
                        <Card 
                          key={alert._id || idx}
                          sx={{ 
                            cursor: 'pointer',
                            transition: 'transform 0.2s, box-shadow 0.2s',
                            '&:hover': { transform: 'translateY(-2px)', boxShadow: 3 },
                            borderLeft: `4px solid ${severity.color}`,
                            animation: idx === 0 && notifications.some(n => n.id.includes(alert._id)) ? `${glow} 0.5s ease` : 'none'
                          }}
                          onClick={() => handleAlertClick(alert._id)}
                        >
                          <CardContent>
                            <Stack direction="row" justifyContent="space-between" alignItems="flex-start" sx={{ mb: 2 }}>
                              <Stack direction="row" spacing={1} alignItems="center">
                                {severity.icon}
                                <Typography variant="subtitle1" fontWeight="bold">{alert.rule_name}</Typography>
                              </Stack>
                              <Chip 
                                label={alert.severity?.toUpperCase()} 
                                size="small"
                                sx={{ bgcolor: severity.color, color: 'white' }}
                              />
                            </Stack>
                            
                            <Grid container spacing={2} sx={{ mb: 2 }}>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <RouterIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">{alert.source_ip || '-'}</Typography>
                                </Stack>
                              </Grid>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <AccountCircleIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">{alert.user || '-'}</Typography>
                                </Stack>
                              </Grid>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <DevicesIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">{alert.host || '-'}</Typography>
                                </Stack>
                              </Grid>
                              <Grid item xs={6}>
                                <Stack direction="row" spacing={1} alignItems="center">
                                  <ScheduleIcon sx={{ fontSize: 16, color: '#78909c' }} />
                                  <Typography variant="body2">{new Date(alert.timestamp).toLocaleTimeString()}</Typography>
                                </Stack>
                              </Grid>
                            </Grid>
                            
                            {alert.description && (
                              <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                                {alert.description}
                              </Typography>
                            )}
                          </CardContent>
                        </Card>
                      );
                    })}
                  </Stack>
                )}
              </Paper>
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* Notification Area */}
      <Box sx={{ position: 'fixed', top: 80, right: 20, zIndex: 1400, width: 360 }}>
        {notifications.map(notification => (
          <NotificationBanner
            key={notification.id}
            notification={notification}
            onClose={removeNotification}
          />
        ))}
      </Box>
    </>
  );
};

export default OverviewPage;