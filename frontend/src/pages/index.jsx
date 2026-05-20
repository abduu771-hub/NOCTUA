// src/pages/index.jsx
import React, { useEffect, useState, useRef } from 'react';
import { Helmet } from 'react-helmet-async';
import { Container, Box, Stack, Typography, SvgIcon, Unstable_Grid2 as Grid, keyframes } from '@mui/material';
import {
  BellIcon,
  ChartBarIcon,
  ShieldCheckIcon,
  RocketLaunchIcon,
  CloudIcon,
  LockClosedIcon,
  StarIcon
} from '@heroicons/react/24/solid';
import regularFont from '../assets/fonts/ClashDisplay-Regular.otf';
import boldFont from '../assets/fonts/ClashDisplay-Bold.otf';
import mediumFont from '../assets/fonts/ClashDisplay-Medium.otf';
import semiboldFont from '../assets/fonts/ClashDisplay-Semibold.otf';
import lightFont from '../assets/fonts/ClashDisplay-Light.otf';
import extralightFont from '../assets/fonts/ClashDisplay-Extralight.otf';
import backgroundImage from '/home/abdu/SIEM-AI/carpatin-dashboard-free-1.0.0/bgg.png';
// Animation keyframes
const fadeInUp = keyframes`
  from {
    opacity: 0;
    transform: translateY(50px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const fadeInLeft = keyframes`
  from {
    opacity: 0;
    transform: translateX(-50px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
`;

const fadeInRight = keyframes`
  from {
    opacity: 0;
    transform: translateX(50px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}`;

const float = keyframes`
  0%, 100% {
    transform: translateY(0px);
  }
  50% {
    transform: translateY(-20px);
  }
`;

const bounce = keyframes`
  0%, 100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-5px);
  }
`;

const LandingPage = () => {
  const [visibleSections, setVisibleSections] = useState({});
  const featuresRef = useRef(null);
  const futureRef = useRef(null);
  const testimonialsRef = useRef(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setVisibleSections((prev) => ({ ...prev, [entry.target.id]: true }));
          }
        });
      },
      { threshold: 0.1 }
    );

    if (featuresRef.current) observer.observe(featuresRef.current);
    if (futureRef.current) observer.observe(futureRef.current);
    if (testimonialsRef.current) observer.observe(testimonialsRef.current);

    return () => observer.disconnect();
  }, []);

  const clashFont = {
    fontFamily: "'ClashDisplay', 'Clash Display', sans-serif"
  };

  return (
    <>
      <Helmet>
        <title>Abur | Next Generation Cyber Defense</title>


// Inside Helmet, add this style:
<style>
  {`
    @font-face {
      font-family: 'ClashDisplay';
      src: url(${regularFont}) format('opentype');
      font-weight: 400;
    }
    @font-face {
      font-family: 'ClashDisplay';
      src: url(${boldFont}) format('opentype');
      font-weight: 700;
    }
    @font-face {
      font-family: 'ClashDisplay';
      src: url(${mediumFont}) format('opentype');
      font-weight: 500;
    }
    @font-face {
      font-family: 'ClashDisplay';
      src: url(${semiboldFont}) format('opentype');
      font-weight: 600;
    }
    @font-face {
      font-family: 'ClashDisplay';
      src: url(${lightFont}) format('opentype');
      font-weight: 300;
    }
    @font-face {
      font-family: 'ClashDisplay';
      src: url(${extralightFont}) format('opentype');
      font-weight: 200;
    }
  `}
</style>
      </Helmet>

      {/* Hero Section */}
      <Box
        sx={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          position: 'relative',
          backgroundImage: `url(${backgroundImage})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundAttachment: 'fixed',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'linear-gradient(135deg, rgba(10, 25, 41, 0.85) 0%, rgba(26, 35, 126, 0.75) 100%)',
            zIndex: 0
          }
        }}
      >
        <Container maxWidth="lg" sx={{ position: 'relative', zIndex: 1, py: { xs: 8, md: 12 } }}>
          <Stack spacing={4}>
            <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, flexWrap: 'wrap' }}>
              <Typography
                variant="h1"
                sx={{
                  ...clashFont,
                  fontWeight: 800,
                  fontSize: { xs: '4rem', md: '6rem', lg: '8rem' },
                  color: '#1a237e',
                  textTransform: 'uppercase',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer',
                  '&:hover': {
                    color: 'white'
                  }
                }}
              >
                AB
              </Typography>
              <Typography
                variant="h1"
                sx={{
                  ...clashFont,
                  fontWeight: 800,
                  fontSize: { xs: '4rem', md: '6rem', lg: '8rem' },
                  color: 'white',
                  textTransform: 'uppercase',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer',
                  '&:hover': {
                    color: '#1a237e'
                  }
                }}
              >
                UR
              </Typography>
            </Box>
            <Typography
              variant="h3"
              sx={{
                ...clashFont,
                fontWeight: 600,
                fontSize: { xs: '1.5rem', md: '2.5rem' },
                color: 'rgba(255,255,255,0.95)'
              }}
            >
              A New ERA of Cyber Defense
            </Typography>
            <Typography
              variant="h6"
              sx={{
                color: 'rgba(255,255,255,0.85)',
                lineHeight: 1.6,
                maxWidth: '60%',
                fontSize: '1.2rem',
                ...clashFont
              }}
            >
              Protect your digital infrastructure with AI-powered threat detection,
              real-time monitoring, and next-generation security protocols.
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={3}>
              <Box
                component="button"
                sx={{
                  px: 5,
                  py: 2,
                  background: 'linear-gradient(135deg, #1a237e 0%, #0d47a1 100%)',
                  color: 'white',
                  border: 'none',
                  borderRadius: 50,
                  cursor: 'pointer',
                  fontWeight: 'bold',
                  fontSize: '1rem',
                  ...clashFont,
                  transition: 'all 0.3s ease',
                  '&:hover': {
                    transform: 'translateY(-3px)',
                    boxShadow: '0 10px 30px rgba(26, 35, 126, 0.5)'
                  }
                }}
              >
                Get Started →
              </Box>
              <Box
                component="button"
                sx={{
                  px: 5,
                  py: 2,
                  border: '2px solid white',
                  color: 'white',
                  borderRadius: 50,
                  backgroundColor: 'transparent',
                  cursor: 'pointer',
                  fontWeight: 'bold',
                  fontSize: '1rem',
                  ...clashFont,
                  transition: 'all 0.3s ease',
                  '&:hover': {
                    backgroundColor: 'white',
                    color: '#1a237e',
                    transform: 'translateY(-3px)'
                  }
                }}
              >
                Learn More
              </Box>
            </Stack>
          </Stack>
        </Container>
      </Box>

      {/* Features Section */}
      <Box
        ref={featuresRef}
        id="features"
        sx={{
          py: { xs: 10, md: 14 },
          px: { xs: 3, md: 6 },
          background: 'linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%)',
          position: 'relative'
        }}
      >
        <Container maxWidth="lg">
          <Typography
            variant="h3"
            align="center"
            sx={{
              ...clashFont,
              fontWeight: 700,
              color: '#1a237e',
              mb: 2,
              fontSize: { xs: '2rem', md: '3rem' },
              opacity: visibleSections.features ? 1 : 0,
              transform: visibleSections.features ? 'translateY(0)' : 'translateY(30px)',
              transition: 'all 0.6s ease-out'
            }}
          >
            Why Choose Abur?
          </Typography>
          <Typography
            variant="body1"
            align="center"
            sx={{
              color: '#1a237e',
              mb: 6,
              maxWidth: 600,
              mx: 'auto',
              ...clashFont,
              opacity: visibleSections.features ? 1 : 0,
              transform: visibleSections.features ? 'translateY(0)' : 'translateY(30px)',
              transition: 'all 0.6s ease-out 0.1s'
            }}
          >
            Enterprise-grade security monitoring with intelligent features
          </Typography>

          <Grid container spacing={4}>
            <Grid xs={12} md={4} sx={{ opacity: visibleSections.features ? 1 : 0, transform: visibleSections.features ? 'translateY(0)' : 'translateY(30px)', transition: 'all 0.6s ease-out 0.2s' }}>
              <Box sx={{ p: 4, textAlign: 'center', borderRadius: 4, backgroundColor: 'white', transition: 'all 0.3s ease', '&:hover': { transform: 'translateY(-10px)', boxShadow: '0 20px 40px rgba(0,0,0,0.1)' } }}>
                <Box sx={{ width: 80, height: 80, borderRadius: '50%', background: 'linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', transition: 'transform 0.3s ease', '&:hover': { transform: 'scale(1.1)' } }}>
                  <SvgIcon component={BellIcon} sx={{ fontSize: 48, color: 'white' }} />
                </Box>
                <Typography variant="h5" fontWeight="bold" mb={2} sx={{ color: '#1a237e', ...clashFont }}>Real-time Alerts</Typography>
                <Typography sx={{ color: '#546e7a', ...clashFont }}>Instant notifications for critical security events delivered directly to your dashboard.</Typography>
              </Box>
            </Grid>
            <Grid xs={12} md={4} sx={{ opacity: visibleSections.features ? 1 : 0, transform: visibleSections.features ? 'translateY(0)' : 'translateY(30px)', transition: 'all 0.6s ease-out 0.3s' }}>
              <Box sx={{ p: 4, textAlign: 'center', borderRadius: 4, backgroundColor: 'white', transition: 'all 0.3s ease', '&:hover': { transform: 'translateY(-10px)', boxShadow: '0 20px 40px rgba(0,0,0,0.1)' } }}>
                <Box sx={{ width: 80, height: 80, borderRadius: '50%', background: 'linear-gradient(135deg, #4ecdc4 0%, #44bd9e 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', transition: 'transform 0.3s ease', '&:hover': { transform: 'scale(1.1)' } }}>
                  <SvgIcon component={ChartBarIcon} sx={{ fontSize: 48, color: 'white' }} />
                </Box>
                <Typography variant="h5" fontWeight="bold" mb={2} sx={{ color: '#1a237e', ...clashFont }}>Customizable Analytics</Typography>
                <Typography sx={{ color: '#546e7a', ...clashFont }}>Tailor dashboards and metrics specifically for your infrastructure needs.</Typography>
              </Box>
            </Grid>
            <Grid xs={12} md={4} sx={{ opacity: visibleSections.features ? 1 : 0, transform: visibleSections.features ? 'translateY(0)' : 'translateY(30px)', transition: 'all 0.6s ease-out 0.4s' }}>
              <Box sx={{ p: 4, textAlign: 'center', borderRadius: 4, backgroundColor: 'white', transition: 'all 0.3s ease', '&:hover': { transform: 'translateY(-10px)', boxShadow: '0 20px 40px rgba(0,0,0,0.1)' } }}>
                <Box sx={{ width: 80, height: 80, borderRadius: '50%', background: 'linear-gradient(135deg, #a8c0ff 0%, #3f2b96 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', transition: 'transform 0.3s ease', '&:hover': { transform: 'scale(1.1)' } }}>
                  <SvgIcon component={ShieldCheckIcon} sx={{ fontSize: 48, color: 'white' }} />
                </Box>
                <Typography variant="h5" fontWeight="bold" mb={2} sx={{ color: '#1a237e', ...clashFont }}>Secure & Reliable</Typography>
                <Typography sx={{ color: '#546e7a', ...clashFont }}>Protect your systems with enterprise-level security monitoring and 99.9% uptime.</Typography>
              </Box>
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* Gradient Section */}
      <Box
        ref={futureRef}
        id="future"
        sx={{
          py: { xs: 10, md: 14 },
          px: { xs: 3, md: 6 },
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%)'
        }}
      >
        <Container maxWidth="lg">
          <Grid container spacing={8} alignItems="center">
            <Grid xs={12} md={6}>
              <Typography variant="h2" sx={{ ...clashFont, fontWeight: 800, fontSize: { xs: '2rem', md: '3rem' }, color: 'white', mb: 3 }}>Powered by Next-Gen AI</Typography>
              <Typography variant="body1" sx={{ color: 'white', fontSize: '1.1rem', lineHeight: 1.8, ...clashFont, mb: 3 }}>Our advanced machine learning algorithms detect anomalies before they become threats. With predictive analytics and automated response systems, stay ahead of cyber criminals.</Typography>
              <Box component="button" sx={{ px: 4, py: 1.5, backgroundColor: 'white', color: '#667eea', border: 'none', borderRadius: 50, fontWeight: 'bold', ...clashFont, cursor: 'pointer', '&:hover': { transform: 'translateX(5px)' } }}>Explore Technology →</Box>
            </Grid>
            <Grid xs={12} md={6}>
              <Box sx={{ display: 'flex', gap: 3, justifyContent: 'center' }}>
                <Box textAlign="center"><Box sx={{ width: 100, height: 100, borderRadius: '50%', backgroundColor: 'rgba(255,255,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 2 }}><SvgIcon component={RocketLaunchIcon} sx={{ fontSize: 50, color: 'white' }} /></Box><Typography sx={{ color: 'white', ...clashFont }}>Lightning Fast</Typography></Box>
                <Box textAlign="center"><Box sx={{ width: 100, height: 100, borderRadius: '50%', backgroundColor: 'rgba(255,255,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 2 }}><SvgIcon component={CloudIcon} sx={{ fontSize: 50, color: 'white' }} /></Box><Typography sx={{ color: 'white', ...clashFont }}>Cloud Native</Typography></Box>
                <Box textAlign="center"><Box sx={{ width: 100, height: 100, borderRadius: '50%', backgroundColor: 'rgba(255,255,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 2 }}><SvgIcon component={LockClosedIcon} sx={{ fontSize: 50, color: 'white' }} /></Box><Typography sx={{ color: 'white', ...clashFont }}>Zero Trust</Typography></Box>
              </Box>
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* Testimonials Section */}
      <Box
        ref={testimonialsRef}
        id="testimonials"
        sx={{
          py: { xs: 10, md: 14 },
          px: { xs: 3, md: 6 },
          background: '#f5f5f5'
        }}
      >
        <Container maxWidth="lg">
          <Typography variant="h3" align="center" sx={{ ...clashFont, fontWeight: 700, color: '#1a237e', mb: 6, fontSize: { xs: '2rem', md: '3rem' } }}>What Our Clients Say</Typography>
          <Grid container spacing={4}>
            {[1, 2, 3].map((_, i) => (
              <Grid xs={12} md={4} key={i}>
                <Box sx={{ p: 4, backgroundColor: 'white', borderRadius: 4, textAlign: 'center', transition: 'all 0.3s ease', '&:hover': { transform: 'translateY(-8px)', boxShadow: '0 20px 40px rgba(0,0,0,0.1)' } }}>
                  <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>{[...Array(5)].map((_, j) => (<SvgIcon key={j} component={StarIcon} sx={{ fontSize: 20, color: '#ffc107' }} />))}</Box>
                  <Typography sx={{ ...clashFont, color: '#37474f', mb: 3, fontStyle: 'italic' }}>"Abur has transformed our security posture. The real-time alerts and AI-powered insights are game-changing."</Typography>
                  <Typography sx={{ ...clashFont, fontWeight: 'bold', color: '#1a237e' }}>Enterprise Security Lead</Typography>
                  <Typography sx={{ ...clashFont, fontSize: '0.875rem', color: '#78909c' }}>Fortune 500 Company</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>
    </>
  );
};

export default LandingPage;