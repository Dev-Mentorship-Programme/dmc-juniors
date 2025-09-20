# OAuth 2.0 Social Login System (In-Memory Edition)

A comprehensive OAuth 2.0 implementation supporting multiple social login providers including Google, GitHub, and traditional local authentication using **in-memory storage** for educational purposes.

## 🚀 Features

- **Multiple OAuth Providers** - Google, GitHub integration
- **Local Authentication** - Traditional email/password with Passport Local
- **Account Linking** - Connect multiple social accounts to one user
- **Session Management** - Secure session handling with in-memory store
- **Profile Synchronization** - Automatic profile updates from social providers
- **Consent Management** - User control over data sharing and permissions
- **In-Memory Storage** - No database required for quick setup and learning

## 📋 Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Google OAuth App (optional for testing)
- GitHub OAuth App (optional for testing)
- **No database required!**

3. **Configure OAuth Applications**
   
   **Google OAuth Setup:**
   - Go to [Google Console](https://console.developers.google.com/)
   - Create new project or select existing
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add redirect URI: `http://localhost:3000/auth/google/callback`

   **GitHub OAuth Setup:**
   - Go to GitHub Settings > Developer settings > OAuth Apps
   - Create new OAuth App
   - Set Authorization callback URL: `http://localhost:3000/auth/github/callback`

4. **Update Environment Variables**
   ```env
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   GITHUB_CLIENT_ID=your_github_client_id
   GITHUB_CLIENT_SECRET=your_github_client_secret
   ```

5. **Run Development Server**
   ```bash
   npm run dev
   ```

## OAuth Flow

### Google OAuth
1. User clicks "Login with Google"
2. Redirect to Google authorization server
3. User grants permissions
4. Google redirects back with authorization code
5. Exchange code for access token
6. Retrieve user profile information
7. Create or update user account
8. Establish user session

### GitHub OAuth
1. User clicks "Login with GitHub"
2. Redirect to GitHub authorization
3. User authorizes application
4. GitHub redirects with code
5. Exchange code for access token
6. Fetch user profile and email
7. Create or update user account
8. Establish session

## Authentication Routes

### OAuth Routes
- `GET /auth/google` - Initiate Google OAuth flow
- `GET /auth/google/callback` - Handle Google OAuth callback
- `GET /auth/github` - Initiate GitHub OAuth flow
- `GET /auth/github/callback` - Handle GitHub OAuth callback

### Local Authentication
- `POST /auth/register` - Register with email/password
- `POST /auth/login` - Login with email/password
- `POST /auth/logout` - Logout current session

### Account Management
- `GET /profile` - View user profile
- `POST /profile/link` - Link additional social account
- `POST /profile/unlink` - Unlink social account

## User Model

```typescript
interface User {
  email: string;
  password?: string; // Only for local accounts
  firstName: string;
  lastName: string;
  avatar?: string;
  providers: {
    google?: {
      id: string;
      email: string;
      accessToken?: string;
      refreshToken?: string;
    };
    github?: {
      id: string;
      username: string;
      email: string;
      accessToken?: string;
    };
    local?: {
      email: string;
      password: string;
    };
  };
  preferences: {
    syncProfile: boolean;
    shareEmail: boolean;
  };
}
```

## Account Linking

Users can link multiple social accounts:

1. **Initial Registration** - Create account with any provider
2. **Add Provider** - Link additional social accounts
3. **Profile Sync** - Choose which profile data to sync
4. **Conflict Resolution** - Handle conflicting information

## Security Features

### OAuth Security
- State parameter to prevent CSRF attacks
- Scope limitation to required permissions only
- Token refresh handling for long-lived access
- Secure token storage in sessions

### Session Security
- HTTP-only session cookies
- Secure flag for HTTPS
- Session regeneration on login
- MongoDB session store with TTL

### Data Protection
- Profile data synchronization controls
- User consent for data sharing
- Minimal data collection principle
- Right to data deletion

## Configuration

### Passport Strategies

```typescript
// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  // Handle Google authentication
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
  // Handle GitHub authentication
}));
```

### Session Configuration

```typescript
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
```

## Frontend Integration

### Login Buttons
```html
<a href="/auth/google">Login with Google</a>
<a href="/auth/github">Login with GitHub</a>
```

### Profile Management
```html
<form action="/profile/link" method="post">
  <input type="hidden" name="provider" value="google">
  <button type="submit">Link Google Account</button>
</form>
```

## Error Handling

- OAuth callback errors
- Account linking conflicts
- Profile synchronization failures
- Network and API errors
- User cancellation scenarios

## Testing

```bash
# Run tests
npm test

# Test OAuth flows (requires valid credentials)
npm run test:integration
```

## Production Deployment

1. **HTTPS Configuration** - Required for OAuth in production
2. **Domain Registration** - Update OAuth app settings with production URLs
3. **Environment Security** - Secure storage of client secrets
4. **Session Store** - Use persistent session storage
5. **Rate Limiting** - Protect against OAuth abuse
