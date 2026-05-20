import { Link as RouterLink, matchPath, useLocation } from 'react-router-dom';
import { Drawer, List, ListItem, ListItemIcon, ListItemText } from '@mui/material';
import { items } from './config';

const SIDE_NAV_WIDTH = 73;
const TOP_NAV_HEIGHT = 64;

export const SideNav = () => {
  const location = useLocation();

  return (
    <Drawer
      open
      variant="permanent"
      PaperProps={{
        sx: {
          backgroundColor: 'background.default',
          display: 'flex',
          flexDirection: 'column',
          height: `calc(100% - ${TOP_NAV_HEIGHT}px)`,
          p: 1,
          top: TOP_NAV_HEIGHT,
          width: SIDE_NAV_WIDTH,
          zIndex: (theme) => theme.zIndex.appBar - 100,
          // Override any animations
          transition: 'none',
          '& .MuiDrawer-paper': {
            transition: 'none'
          }
        }
      }}
      sx={{
        '& .MuiDrawer-paper': {
          transition: 'none !important',
          animation: 'none !important'
        }
      }}
    >
      <List sx={{ width: '100%' }}>
        {items.map((item) => {
          const active = matchPath({ path: item.href, end: true }, location.pathname);

          return (
            <ListItem
              disablePadding
              component={RouterLink}
              key={item.href}
              to={item.href}
              sx={{
                flexDirection: 'column',
                px: 2,
                py: 1.5,
                borderRadius: 2,
                mb: 0.5,
                transition: 'none !important',
                animation: 'none !important',
                '&:hover': {
                  backgroundColor: 'rgba(26, 35, 126, 0.08)',
                  '& .MuiListItemIcon-root': {
                    color: '#1a237e'
                  },
                  '& .MuiListItemText-primary': {
                    color: '#1a237e'
                  }
                },
                ...(active && {
                  backgroundColor: '#1a237e',
                  '&:hover': {
                    backgroundColor: '#0d47a1'
                  },
                  '& .MuiListItemIcon-root': {
                    color: 'white'
                  },
                  '& .MuiListItemText-primary': {
                    color: 'white'
                  }
                })
              }}
            >
              <ListItemIcon
                sx={{
                  minWidth: 'auto',
                  mb: 0.5,
                  color: active ? 'white' : 'neutral.400',
                  transition: 'none !important',
                  '& svg': {
                    fontSize: 24
                  }
                }}
              >
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  variant: 'caption',
                  sx: {
                    fontFamily: "'ClashDisplay', sans-serif",
                    fontSize: '0.7rem',
                    fontWeight: active ? 600 : 400,
                    color: active ? 'white' : 'text.secondary',
                    transition: 'none !important'
                  }
                }}
              />
            </ListItem>
          );
        })}
      </List>
    </Drawer>
  );
};