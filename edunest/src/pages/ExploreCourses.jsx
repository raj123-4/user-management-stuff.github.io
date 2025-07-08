import React, { useState } from 'react';
import courses from '../data/courses';
import CourseCard from '../components/CourseCard';

export default function ExploreCourses() {
  const [search, setSearch] = useState('');
  const filtered = courses.filter(c =>
    c.title.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <div className="mb-4">
        <input
          className="border px-3 py-2 rounded w-full"
          placeholder="Search courses"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        {filtered.map(course => (
          <CourseCard key={course.id} course={course} />
        ))}
      </div>
    </div>
  );
}
