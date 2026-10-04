import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import GithubProvider from 'next-auth/providers/github';
import bcrypt from 'bcryptjs';
import dbConnect from '@/lib/dbConnect';
import UserModel from '@/model/User';

export const authOptions: NextAuthOptions = {
  providers: [
    GithubProvider({
      clientId: process.env.GITHUB_ID as string,
      clientSecret: process.env.GITHUB_SECRET as string,
    }),
    CredentialsProvider({
      id: 'credentials',
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials: any): Promise<any> {
        await dbConnect();
        try {
          const user = await UserModel.findOne({
            $or: [
              { email: credentials.identifier },
              { username: credentials.identifier },
            ],
          });
          if (!user) {
            throw new Error('No user found with this email');
          }
          if (!user.isVerified) {
            throw new Error('Please verify your account before logging in');
          }
          const isPasswordCorrect = await bcrypt.compare(
            credentials.password,
            user.password
          );
          if (isPasswordCorrect) {
            return user;
          } else {
            throw new Error('Incorrect password');
          }
        } catch (err: any) {
          throw new Error(err);
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, account }) {
      if (account && account.provider === 'github') {
        await dbConnect();
        try {
          const email = user?.email;
          let dbUser = await UserModel.findOne({ email });
          
          if (!dbUser) {
            // Create a new user if they don't exist in our DB
            const baseUsername = user?.name?.replace(/\s+/g, '').toLowerCase() || email?.split('@')[0] || 'user';
            const uniqueUsername = baseUsername + Math.floor(1000 + Math.random() * 9000).toString(); // e.g. john1234
            
            dbUser = new UserModel({
              email: email,
              username: uniqueUsername,
              // Generate random strings for required fields that aren't relevant for OAuth
              password: await bcrypt.hash(Math.random().toString(36).slice(-8), 10),
              verifyCode: Math.random().toString(36).slice(-8),
              verifyCodeExpiry: new Date(Date.now() + 3600000), 
              isVerified: true, // Auto-verify OAuth users
              isAcceptingMessages: true,
            });
            await dbUser.save();
          }
          
          // Populate token with DB user data
          token._id = dbUser._id.toString();
          token.isVerified = dbUser.isVerified;
          token.isAcceptingMessages = dbUser.isAcceptingMessages;
          token.username = dbUser.username;
        } catch (error) {
          console.error("Error creating/fetching github user", error);
        }
      } else if (user) {
        // Credentials provider logic
        token._id = user._id?.toString(); 
        token.isVerified = user.isVerified;
        token.isAcceptingMessages = user.isAcceptingMessages;
        token.username = user.username;
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user._id = token._id;
        session.user.isVerified = token.isVerified;
        session.user.isAcceptingMessages = token.isAcceptingMessages;
        session.user.username = token.username;
      }
      return session;
    },
  },
  session: {
    strategy: 'jwt',
  },
  secret: process.env.NEXTAUTH_SECRET,
  pages: {
    signIn: '/sign-in',
  },
};
