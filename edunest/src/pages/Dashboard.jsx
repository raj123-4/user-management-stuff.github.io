import React from 'react';
import { NavLink, Outlet, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import ThemeToggle from '../components/ThemeToggle';
import Home from './Home';
import ExploreCourses from './ExploreCourses';
import MyCourses from './MyCourses';
import Fees from './Fees';
import Alerts from './Alerts';
import Messages from './Messages';
import Calendar from './Calendar';
import Settings from './Settings';

export default function Dashboard() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex-1 p-6 bg-gray-50 dark:bg-gray-900">
        <div className="flex justify-end mb-4">
          <ThemeToggle />
        </div>
        <Routes>
          <Route path="home" element={<Home />} />
          <Route path="explore" element={<ExploreCourses />} />
          <Route path="my-courses" element={<MyCourses />} />
          <Route path="fees" element={<Fees />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="messages" element={<Messages />} />
          <Route path="calendar" element={<Calendar />} />
          <Route path="settings" element={<Settings />} />
          <Route path="" element={<Navigate to="home" />} />
        </Routes>
        <Outlet />
      </div>
    </div>
  );
}
