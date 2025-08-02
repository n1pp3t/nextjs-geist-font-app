"use client";

import React from 'react';
import Link from 'next/link';

export default function DocumentationPage() {
  return (
    <div className="min-h-screen bg-background text-foreground p-8">
      <h1 className="text-3xl font-bold mb-6">Documentation & Help Center</h1>
      <p className="mb-4">
        Comprehensive documentation and support resources for the FSociety Toolkit.
      </p>
      <ul className="list-disc list-inside space-y-2">
        <li>Getting Started Guide</li>
        <li>Tool Usage Instructions</li>
        <li>Payload Generation Tutorials</li>
        <li>Mobile Hacking Guidelines</li>
        <li>Reconnaissance Techniques</li>
        <li>Automation Script Examples</li>
        <li>Python Tools Usage</li>
        <li>Network Attack Procedures</li>
        <li>AI Tools Integration</li>
        <li>Frequently Asked Questions (FAQ)</li>
      </ul>
      <p className="mt-6">
        For further assistance, please contact support or visit our community forums.
      </p>
      <Link href="/" className="text-primary underline mt-4 inline-block">
        Back to Home
      </Link>
    </div>
  );
}
