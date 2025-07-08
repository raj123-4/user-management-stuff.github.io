import React from 'react';
import courses from '../data/courses';

export default function MyCourses() {
  const enrolled = courses.slice(0, 2);
  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">My Courses</h1>
      <ul className="list-disc list-inside">
        {enrolled.map(c => (
          <li key={c.id}>{c.title} - 50% complete</li>
        ))}
      </ul>
    </div>
  );
}
