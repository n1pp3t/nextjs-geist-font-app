"use client";

import React, { useState, useEffect } from 'react';

interface Notification {
  id: number;
  message: string;
  type: 'info' | 'warning' | 'error';
}

export function NotificationCenter() {
  const [notifications, setNotifications] = useState<Notification[]>([]);

  useEffect(() => {
    // Example: Add a welcome notification on mount
    addNotification({ message: 'Welcome to FSociety Toolkit!', type: 'info' });
  }, []);

  const addNotification = (notification: Omit<Notification, 'id'>) => {
    const id = Date.now();
    setNotifications((prev) => [...prev, { id, ...notification }]);
    // Auto-remove after 5 seconds
    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    }, 5000);
  };

  return (
    <div className="fixed top-4 right-4 w-80 space-y-2 z-50">
      {notifications.map(({ id, message, type }) => (
        <div
          key={id}
          className={"p-3 rounded shadow text-white " + (type === 'info' ? 'bg-blue-600' : type === 'warning' ? 'bg-yellow-600' : 'bg-red-600')}
        >
          {message}
        </div>
      ))}
    </div>
  );
}
