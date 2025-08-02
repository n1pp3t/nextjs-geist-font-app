"use client";

import React from 'react';
import Link from 'next/link';

export default function UserProfilePage() {
  return (
    <div className="min-h-screen bg-background text-foreground p-8">
      <h1 className="text-3xl font-bold mb-6">User Profile & Sessions</h1>
      <p className="mb-4">
        Manage your user profile, saved sessions, and preferences for the FSociety Toolkit.
      </p>
      <p>
        This feature will allow users to save their work, manage settings, and personalize their experience.
      </p>
      <Link href="/" className="text-primary underline mt-4 inline-block">
        Back to Home
      </Link>
    </div>
  );
}
