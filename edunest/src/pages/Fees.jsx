import React from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement);

const data = {
  labels: ['Paid', 'Pending'],
  datasets: [
    {
      label: 'Fees',
      data: [1200, 300],
      backgroundColor: ['#4ade80', '#f87171'],
    },
  ],
};

export default function Fees() {
  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Fees Overview</h1>
      <Bar data={data} />
    </div>
  );
}
