import { useEffect, useState } from "react";
import { fetchMLStatus, type MLStatus } from "../api/client";

export function MLStatusCard() {
  const [status, setStatus] = useState<MLStatus | null>(null);

  useEffect(() => {
    const load = () => fetchMLStatus().then(setStatus).catch(() => {});
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  if (!status) return null;

  const progress = Math.min(
    100,
    Math.round((status.buffer_size / status.min_train_samples) * 100)
  );

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
      <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">
        ML Model
      </h2>

      <div className="space-y-2 text-sm">
        {/* Status */}
        <div className="flex items-center justify-between">
          <span className="text-gray-400">Status</span>
          <span
            className={`font-medium ${
              status.is_ready ? "text-green-400" : "text-yellow-400"
            }`}
          >
            {status.is_ready ? "Active" : "Learning"}
          </span>
        </div>

        {/* Training progress */}
        {!status.is_ready && (
          <div>
            <div className="flex justify-between text-xs text-gray-500 mb-1">
              <span>Training data</span>
              <span>
                {status.buffer_size} / {status.min_train_samples}
              </span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-1.5">
              <div
                className="bg-blue-500 rounded-full h-1.5 transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Train count */}
        <div className="flex items-center justify-between">
          <span className="text-gray-400">Training cycles</span>
          <span className="text-white">{status.train_count}</span>
        </div>

        {/* Model params */}
        <div className="flex items-center justify-between">
          <span className="text-gray-400">Estimators</span>
          <span className="text-white">{status.n_estimators}</span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-gray-400">Contamination</span>
          <span className="text-white">{(status.contamination * 100).toFixed(0)}%</span>
        </div>

        {/* Last trained */}
        {status.last_trained && (
          <div className="flex items-center justify-between">
            <span className="text-gray-400">Last trained</span>
            <span className="text-white text-xs">
              {new Date(status.last_trained * 1000).toLocaleTimeString()}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
