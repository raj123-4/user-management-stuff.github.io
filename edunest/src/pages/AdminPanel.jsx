import React, { useState } from 'react';
import courses from '../data/courses';

export default function AdminPanel() {
  const [list, setList] = useState(courses);
  const [title, setTitle] = useState('');

  const addCourse = () => {
    if (!title) return;
    setList([...list, { id: list.length + 1, title, instructor: 'Admin', tags: [] }]);
    setTitle('');
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Admin Panel</h1>
      <div className="mb-4">
        <input
          className="border px-3 py-2 rounded mr-2"
          placeholder="New course title"
          value={title}
          onChange={e => setTitle(e.target.value)}
        />
        <button className="bg-blue-600 text-white px-3 py-2 rounded" onClick={addCourse}>Add</button>
      </div>
      <h2 className="text-xl font-semibold mb-2">Courses</h2>
      <ul className="list-disc list-inside">
        {list.map(c => (
          <li key={c.id}>{c.title}</li>
        ))}
      </ul>
    </div>
  );
}
