import React from 'react';

export default function Calendar() {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];
  const schedule = [
    { day: 'Mon', subject: 'Math' },
    { day: 'Wed', subject: 'Science' },
    { day: 'Fri', subject: 'History' },
  ];
  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Calendar</h1>
      <ul>
        {days.map(d => (
          <li key={d} className="mb-2">
            <span className="font-semibold mr-2">{d}:</span>
            {schedule.find(s => s.day === d)?.subject || '—'}
          </li>
        ))}
      </ul>
    </div>
  );
}
