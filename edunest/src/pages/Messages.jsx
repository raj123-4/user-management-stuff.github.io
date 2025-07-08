import React from 'react';

const messages = [
  { id: 1, sender: 'Instructor', preview: 'Please submit...', time: '1h ago', unread: true },
  { id: 2, sender: 'Admin', preview: 'Welcome to EduNest!', time: '1d ago', unread: false },
];

export default function Messages() {
  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Messages</h1>
      <ul>
        {messages.map(m => (
          <li key={m.id} className="border-b py-2">
            <div className="flex justify-between">
              <span className="font-semibold">{m.sender}</span>
              {m.unread && <span className="text-xs bg-blue-600 text-white rounded px-2">New</span>}
            </div>
            <p className="text-sm text-gray-500">{m.preview}</p>
            <span className="text-xs text-gray-400">{m.time}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
