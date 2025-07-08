import React from 'react';

export default function CourseCard({ course }) {
  return (
    <div className="border rounded p-4 shadow-sm bg-white dark:bg-gray-800">
      <h3 className="text-lg font-semibold">{course.title}</h3>
      <p className="text-sm text-gray-500">Instructor: {course.instructor}</p>
      <div className="mt-2 space-x-1">
        {course.tags.map(tag => (
          <span
            key={tag}
            className="inline-block bg-gray-200 dark:bg-gray-700 text-xs px-2 py-1 rounded"
          >
            {tag}
          </span>
        ))}
      </div>
    </div>
  );
}
