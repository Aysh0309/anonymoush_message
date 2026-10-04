import 'next-auth';

// By default, NextAuth only knows about a few basic properties for a user, like name, email, and image. If you try to attach extra information to a user (like their database ID or a username) during the authentication process, TypeScript will complain because it doesn't know those properties exist on the NextAuth Session, User, or JWT objects.

// The Solution: Module Augmentation

declare module 'next-auth' {
  interface Session {
    user: {
      _id?: string;
      isVerified?: boolean;
      isAcceptingMessages?: boolean;
      username?: string;
    } & DefaultSession['user'];
  }

  interface User {
    _id?: string;
    isVerified?: boolean;
    isAcceptingMessages?: boolean;
    username?: string;
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    _id?: string;
    isVerified?: boolean;
    isAcceptingMessages?: boolean;
    username?: string;
  }
}
