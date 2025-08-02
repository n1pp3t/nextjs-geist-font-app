"use client";

import React, { useState } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { FSocietyCard } from '@/components/FSocietyCard';
import { toolkitData } from '@/lib/toolkitData';

export default function WifiNetworkHackingPage() {
  const wifiNetworkTools = toolkitData.filter(tool => tool.category === 'Wireless Security' || tool.category === 'Network Attack');

  const [searchTerm, setSearchTerm] = useState('');
  const filteredTools = wifiNetworkTools.filter(tool =>
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
                <Link href="/wifi-network-hacking" className="text-foreground hover:text-primary transition-colors">
                  WiFi & Network Hacking
                </Link>
              </div>
            </div>
            <div className="text-sm text-muted-foreground">
              WiFi & Network Hacking Tools
            </div>
          </div>
        </div>
      </nav>

      {/* Header */}
      <section className="py-12 px-4">
        <div className="container mx-auto text-center">
          <h2 className="text-4xl font-bold text-foreground mb-4">
            WiFi & Network Hacking Tools
          </h2>
          <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            Tools for wireless network auditing, vulnerability scanning, and network attacks.
          </p>
        </div>
      </section>

      {/* Search */}
      <section className="py-8 px-4 bg-muted/20">
        <div className="container mx-auto max-w-4xl">
          <Input
            placeholder="Search WiFi & Network tools..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full"
          />
        </div>
      </section>

      {/* Tools Grid */}
      <section className="py-12 px-4">
        <div className="container mx-auto max-w-6xl">
          {filteredTools.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              No WiFi or Network Hacking tools found matching your criteria.
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
            FSociety Toolkit - WiFi & Network Hacking Tools
          </p>
          <p className="text-muted-foreground text-xs mt-2">
            For educational and authorized security testing purposes only
          </p>
        </div>
      </footer>
    </div>
  );
}
