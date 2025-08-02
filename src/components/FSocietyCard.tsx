"use client";

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tool } from '@/lib/toolkitData';
import { ToolExplanationModal } from './ToolExplanationModal';

interface FSocietyCardProps {
  tool: Tool;
}

export function FSocietyCard({ tool }: FSocietyCardProps) {
  const [showModal, setShowModal] = useState(false);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Beginner':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'Intermediate':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'Advanced':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  return (
    <>
      <Card className="bg-card/50 border-border/50 hover:bg-card/80 transition-all duration-300 hover:shadow-lg hover:shadow-primary/10">
        <CardHeader>
          <div className="flex justify-between items-start mb-2">
            <CardTitle className="text-lg font-semibold text-foreground">
              {tool.title}
            </CardTitle>
            <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
              {tool.difficulty}
            </Badge>
          </div>
          <Badge variant="outline" className="w-fit text-xs">
            {tool.category}
          </Badge>
        </CardHeader>
        
        <CardContent>
          <CardDescription className="text-muted-foreground mb-4">
            {tool.description}
          </CardDescription>
          
          <div className="bg-muted/30 rounded-md p-3 mb-4">
            <p className="text-xs text-muted-foreground mb-1">Usage Example:</p>
            <code className="text-sm font-mono text-primary">
              {tool.usage}
            </code>
          </div>
        </CardContent>
        
        <CardFooter className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            className="flex-1"
            onClick={() => setShowModal(true)}
          >
            Learn More
          </Button>
          <Button 
            variant="default" 
            size="sm" 
            className="flex-1"
          >
            View Details
          </Button>
        </CardFooter>
      </Card>

      <ToolExplanationModal
        tool={tool}
        isOpen={showModal}
        onClose={() => setShowModal(false)}
      />
    </>
  );
}
