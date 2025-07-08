import React, { useState } from 'react';

const initialAlerts = [
  { id: 1, text: 'Assignment 1 due tomorrow', read: false },
  { id: 2, text: 'New course available', read: true },
];

export default function Alerts() {
  const [alerts, setAlerts] = useState(initialAlerts);
  const toggle = id => {
    setAlerts(a => a.map(al => (al.id === id ? { ...al, read: !al.read } : al)));
  };
  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Alerts</h1>
      <ul>
        {alerts.map(al => (
          <li key={al.id} className="flex items-center justify-between mb-2">
            <span className={al.read ? 'text-gray-400' : ''}>{al.text}</span>
            <button
              className="text-sm text-blue-600"
              onClick={() => toggle(al.id)}
            >
              {al.read ? 'Mark unread' : 'Mark read'}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
