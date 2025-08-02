"use client";

import React, { useState } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { FSocietyCard } from '@/components/FSocietyCard';
import { toolkitData } from '@/lib/toolkitData';

export default function SQLInjectionPage() {
  const sqlTools = toolkitData.filter(tool => tool.category === 'Web Exploitation' && tool.title.toLowerCase().includes('sql'));

  const [searchTerm, setSearchTerm] = useState('');
  const filteredTools = sqlTools.filter(tool =>
    tool.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    tool.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <h1 className="text-2xl font-bold text-foreground">
                FSociety Toolkit
              </h1>
              <div className="hidden md:flex space-x-6">
                <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
                  Tools
                </Link>
                <Link href="/payload" className="text-muted-foreground hover:text-primary transition-colors">
                  Payload Generator
                </Link>
                <Link href="/mobile" className="text-muted-foreground hover:text-primary transition-colors">
                  Mobile Hacking
                </Link>
                <Link href="/wordlist" className="text-muted-foreground hover:text-primary transition-colors">
                  Wordlist Generator
                </Link>
                <Link href="/recon" className="text-muted-foreground hover:text-primary transition-colors">
                  Reconnaissance
                </Link>
                <Link href="/automation" className="text-muted-foreground hover:text-primary transition-colors">
                  Automation Scripts
                </Link>
                <Link href="/python-tools" className="text-muted-foreground hover:text-primary transition-colors">
                  Python Tools
                </Link>
                <Link href="/data-analysis" className="text-muted-foreground hover:text-primary transition-colors">
                  Data Analysis
                </Link>
                <Link href="/scripting" className="text-muted-foreground hover:text-primary transition-colors">
                  Scripting Playground
                </Link>
                <Link href="/ai-tools" className="text-muted-foreground hover:text-primary transition-colors">
                  AI Tools
                </Link>
                <Link href="/network-attack" className="text-muted-foreground hover:text-primary transition-colors">
                  Network Attack
                </Link>
                <Link href="/xss" className="text-muted-foreground hover:text-primary transition-colors">
                  XSS Payloads
                </Link>
                <Link href="/sql-injection" className="text-foreground hover:text-primary transition-colors">
                  SQL Injection
                </Link>
              </div>
            </div>
            <div className="text-sm text-muted-foreground">
              SQL Injection Payloads and Scripts
            </div>
          </div>
        </div>
      </nav>

      {/* Header */}
      <section className="py-12 px-4">
        <div className="container mx-auto text-center">
          <h2 className="text-4xl font-bold text-foreground mb-4">
            SQL Injection Payloads and Scripts
          </h2>
          <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            Explore various SQL injection payloads and scripts for testing and educational purposes.
          </p>
        </div>
      </section>

      {/* Search */}
      <section className="py-8 px-4 bg-muted/20">
        <div className="container mx-auto max-w-4xl">
          <input
            type="text"
            placeholder="Search SQL injection payloads..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full rounded-md border border-border bg-background px-4 py-2 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>
      </section>

      {/* Tools Grid */}
      <section className="py-12 px-4">
        <div className="container mx-auto max-w-6xl">
          {filteredTools.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              No SQL injection payloads found matching your criteria.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredTools.map(tool => (
                <FSocietyCard key={tool.id} tool={tool} />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/40 py-8 px-4 mt-12">
        <div className="container mx-auto text-center">
          <p className="text-muted-foreground text-sm">
            FSociety Toolkit - SQL Injection Payloads and Scripts
          </p>
          <p className="text-muted-foreground text-xs mt-2">
            For educational and authorized security testing purposes only
          </p>
        </div>
      </footer>
    </div>
  );
}
