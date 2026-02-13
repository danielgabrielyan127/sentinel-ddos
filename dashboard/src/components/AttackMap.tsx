import { useEffect, useRef, useState, useCallback } from "react";
import * as d3 from "d3";
import type { AttackMapPoint } from "../api/client";
import { fetchAttackMap } from "../api/client";

// Simplified world GeoJSON boundaries (equirectangular projection)
const WORLD_OUTLINE: [number, number][] = [
  [-180, -90], [180, -90], [180, 90], [-180, 90], [-180, -90],
];

const ACTION_COLORS: Record<string, string> = {
  blocked: "#ef4444",
  auto_blocked: "#dc2626",
  rate_limited: "#f59e0b",
  challenged: "#3b82f6",
};

export function AttackMap() {
  const svgRef = useRef<SVGSVGElement>(null);
  const [points, setPoints] = useState<AttackMapPoint[]>([]);
  const [byCountry, setByCountry] = useState<{ code: string; count: number }[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState(false);

  const load = useCallback(() => {
    fetchAttackMap()
      .then((data) => {
        setPoints(data.points);
        setByCountry(data.by_country);
        setTotal(data.total_attacking_ips);
        setError(false);
      })
      .catch(() => setError(true));
  }, []);

  // Poll every 5 seconds
  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  // D3 rendering
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth || 600;
    const height = Math.max(250, width * 0.45);

    svg.attr("viewBox", `0 0 ${width} ${height}`);
    svg.selectAll("*").remove();

    // Equirectangular projection
    const projection = d3.geoEquirectangular()
      .fitSize([width - 20, height - 20], {
        type: "Feature",
        geometry: {
          type: "Polygon",
          coordinates: [WORLD_OUTLINE],
        },
        properties: {},
      } as any)
      .translate([width / 2, height / 2]);

    // Background
    svg.append("rect")
      .attr("width", width)
      .attr("height", height)
      .attr("fill", "#0a0a1a")
      .attr("rx", 8);

    // Graticule (grid lines)
    const graticule = d3.geoGraticule();
    const path = d3.geoPath().projection(projection);
    svg.append("path")
      .datum(graticule())
      .attr("d", path as any)
      .attr("fill", "none")
      .attr("stroke", "#1a1a3a")
      .attr("stroke-width", 0.5);

    // World outline
    svg.append("path")
      .datum({ type: "Polygon", coordinates: [WORLD_OUTLINE] } as any)
      .attr("d", path as any)
      .attr("fill", "none")
      .attr("stroke", "#2a2a5a")
      .attr("stroke-width", 1);

    // Attack points with pulse animation
    const g = svg.append("g");

    points.forEach((pt) => {
      const coords = projection([pt.longitude, pt.latitude]);
      if (!coords) return;

      const color = ACTION_COLORS[pt.action] || "#ef4444";

      // Outer pulse ring
      g.append("circle")
        .attr("cx", coords[0])
        .attr("cy", coords[1])
        .attr("r", 6)
        .attr("fill", "none")
        .attr("stroke", color)
        .attr("stroke-width", 1)
        .attr("opacity", 0.4);

      // Inner dot
      g.append("circle")
        .attr("cx", coords[0])
        .attr("cy", coords[1])
        .attr("r", 3)
        .attr("fill", color)
        .attr("opacity", 0.8);

      // Tooltip on hover (title)
      g.append("title")
        .text(
          `${pt.ip}\n${pt.country_name} (${pt.country_code})\n` +
          `Action: ${pt.action}` +
          (pt.attack_type ? `\nType: ${pt.attack_type}` : "") +
          (pt.score != null ? `\nScore: ${pt.score}` : "")
        );
    });

  }, [points]);

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
          Attack Map
        </h2>
        <span className="text-xs text-gray-500">
          {total} attacking IP{total !== 1 ? "s" : ""}
        </span>
      </div>

      {error ? (
        <p className="text-xs text-red-400 text-center py-8">
          Failed to load attack map data
        </p>
      ) : (
        <svg
          ref={svgRef}
          className="w-full rounded"
          style={{ minHeight: 250 }}
        />
      )}

      {/* Top countries */}
      {byCountry.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {byCountry.slice(0, 8).map((c) => (
            <span
              key={c.code}
              className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded"
            >
              {c.code}: {c.count}
            </span>
          ))}
        </div>
      )}

      {/* Legend */}
      <div className="mt-2 flex gap-4 text-xs text-gray-500">
        {Object.entries(ACTION_COLORS).map(([action, color]) => (
          <span key={action} className="flex items-center gap-1">
            <span
              className="inline-block w-2 h-2 rounded-full"
              style={{ backgroundColor: color }}
            />
            {action.replace("_", " ")}
          </span>
        ))}
      </div>
    </div>
  );
}
