import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy, VerifyCallback } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { userStore, IUser } from '../models/UserStore';
import dotenv from 'dotenv';

dotenv.config();

// Serialize user for session
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await userStore.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Local Strategy (Email/Password)
passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password'
  },
  async (email: string, password: string, done) => {
    try {
      const user = await userStore.findByEmail(email);
      
      if (!user) {
        return done(null, false, { message: 'User not found' });
      }

      // Check if account is locked
      if (userStore.isLocked(user)) {
        return done(null, false, { message: 'Account temporarily locked due to failed login attempts' });
      }

      // Check if user has local authentication set up
      if (!user.providers.local) {
        return done(null, false, { message: 'This account uses social login. Please use Google or GitHub to sign in.' });
      }

      const isValidPassword = await userStore.comparePassword(user, password);
      
      if (!isValidPassword) {
        await userStore.incrementLoginAttempts(user.id);
        return done(null, false, { message: 'Invalid password' });
      }

      // Reset login attempts on successful login
      await userStore.resetLoginAttempts(user.id);
      
      // Update last login
      await userStore.updateUser(user.id, { lastLogin: new Date() });
      
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3002/auth/google/callback'
    },
    async (accessToken: string, refreshToken: string, profile: any, done: VerifyCallback) => {
      try {
        // Add tokens to profile for storage
        profile.accessToken = accessToken;
        profile.refreshToken = refreshToken;
        
        const user = await userStore.createOrUpdateGoogleUser(profile);
        return done(null, user);
      } catch (error) {
        return done(error as Error);
      }
    }
  ));
} else {
  console.warn('⚠️  Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.');
}

// GitHub OAuth Strategy
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3002/auth/github/callback'
    },
    async (accessToken: string, refreshToken: string, profile: any, done: any) => {
      try {
        // Add token to profile for storage
        profile.accessToken = accessToken;
        
        const user = await userStore.createOrUpdateGitHubUser(profile);
        return done(null, user);
      } catch (error) {
        return done(error as Error);
      }
    }
  ));
} else {
  console.warn('⚠️  GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.');
}

export default passport;
