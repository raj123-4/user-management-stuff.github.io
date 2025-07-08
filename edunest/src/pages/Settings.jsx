import React from 'react';
import { useAuth } from '../context/AuthContext';

export default function Settings() {
  const { logout } = useAuth();
  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Settings</h1>
      <button
        onClick={logout}
        className="bg-red-600 text-white px-3 py-2 rounded"
      >
        Logout
      </button>
    </div>
  );
}
