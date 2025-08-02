"use client";

import React from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Tool } from '@/lib/toolkitData';

interface ToolExplanationModalProps {
  tool: Tool;
  isOpen: boolean;
  onClose: () => void;
}

export function ToolExplanationModal({ tool, isOpen, onClose }: ToolExplanationModalProps) {
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
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center gap-3 mb-2">
            <DialogTitle className="text-xl font-bold text-foreground">
              {tool.title}
            </DialogTitle>
            <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
              {tool.difficulty}
            </Badge>
          </div>
          <Badge variant="outline" className="w-fit text-sm">
            {tool.category}
          </Badge>
        </DialogHeader>

        <div className="space-y-4">
          <DialogDescription className="text-muted-foreground text-base leading-relaxed">
            {tool.description}
          </DialogDescription>

          <Separator />

          <div>
            <h3 className="text-lg font-semibold text-foreground mb-3">
              Educational Overview
            </h3>
            <p className="text-muted-foreground leading-relaxed">
              {tool.explanation}
            </p>
          </div>

          <Separator />

          <div>
            <h3 className="text-lg font-semibold text-foreground mb-3">
              Basic Usage Example
            </h3>
            <div className="bg-muted/30 rounded-lg p-4">
              <code className="text-sm font-mono text-primary block">
                {tool.usage}
              </code>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              ⚠️ This is for educational purposes only. Always ensure you have proper authorization before using security tools.
            </p>
          </div>

          <Separator />

          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
            <h4 className="text-sm font-semibold text-yellow-400 mb-2">
              Ethical Usage Notice
            </h4>
            <p className="text-xs text-muted-foreground">
              This tool should only be used for legitimate security testing, research, and educational purposes. 
              Unauthorized access to computer systems is illegal and unethical. Always obtain proper permission 
              before conducting security assessments.
            </p>
          </div>

          <div className="flex justify-end pt-4">
            <Button onClick={onClose} variant="outline">
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
