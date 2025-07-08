import React from 'react';
import { NavLink } from 'react-router-dom';

export default function Sidebar() {
  const links = [
    { to: 'home', label: 'Home' },
    { to: 'explore', label: 'Explore Courses' },
    { to: 'my-courses', label: 'My Courses' },
    { to: 'fees', label: 'Fees' },
    { to: 'alerts', label: 'Alerts' },
    { to: 'messages', label: 'Messages' },
    { to: 'calendar', label: 'Calendar' },
    { to: 'settings', label: 'Settings' },
  ];
  return (
    <aside className="w-60 bg-white dark:bg-gray-900 h-screen p-4 shadow-md">
      <h2 className="text-xl font-bold mb-4">EduNest</h2>
      <nav className="flex flex-col space-y-2">
        {links.map(link => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              `py-2 px-3 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${
                isActive ? 'bg-gray-200 dark:bg-gray-700 font-semibold' : ''
              }`
            }
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
