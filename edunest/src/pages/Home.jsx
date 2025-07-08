import React from 'react';
import ProgressBar from '../components/ProgressBar';
import assignments from '../data/assignments';

export default function Home() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Welcome back!</h1>
      <p className="mb-2">Your progress:</p>
      <ProgressBar value={70} />
      <h2 className="text-xl font-semibold mt-6 mb-2">Upcoming Assignments</h2>
      <ul className="list-disc list-inside">
        {assignments.map(a => (
          <li key={a.id}>{a.title} - due {a.due}</li>
        ))}
      </ul>
    </div>
  );
}
