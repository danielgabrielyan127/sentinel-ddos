import React, { useRef, useEffect } from "react";
import * as d3 from "d3";
import type { TrafficPoint } from "../hooks/useWebSocket";

interface Props {
  data: TrafficPoint[];
}

export const TrafficChart: React.FC<Props> = ({ data }) => {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || data.length < 2) return;

    const svg = d3.select(svgRef.current);
    const { width, height } = svgRef.current.getBoundingClientRect();

    const margin = { top: 12, right: 16, bottom: 28, left: 48 };
    const w = width - margin.left - margin.right;
    const h = height - margin.top - margin.bottom;

    svg.selectAll("*").remove();

    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);

    const xScale = d3
      .scaleLinear()
      .domain([data[0].timestamp, data[data.length - 1].timestamp])
      .range([0, w]);

    const maxRps = d3.max(data, (d) => d.rps) ?? 1;
    const yScale = d3.scaleLinear().domain([0, maxRps * 1.15]).range([h, 0]);

    // Grid lines
    g.append("g")
      .attr("class", "grid")
      .call(
        d3
          .axisLeft(yScale)
          .ticks(5)
          .tickSize(-w)
          .tickFormat(() => "")
      )
      .selectAll("line")
      .attr("stroke", "#1f2937")
      .attr("stroke-dasharray", "2,4");

    g.selectAll(".grid .domain").remove();

    // Area gradient
    const areaGradient = svg
      .append("defs")
      .append("linearGradient")
      .attr("id", "areaGrad")
      .attr("x1", "0")
      .attr("y1", "0")
      .attr("x2", "0")
      .attr("y2", "1");
    areaGradient.append("stop").attr("offset", "0%").attr("stop-color", "#3b82f6").attr("stop-opacity", 0.3);
    areaGradient.append("stop").attr("offset", "100%").attr("stop-color", "#3b82f6").attr("stop-opacity", 0.0);

    const area = d3
      .area<TrafficPoint>()
      .x((d) => xScale(d.timestamp))
      .y0(h)
      .y1((d) => yScale(d.rps))
      .curve(d3.curveBasis);

    g.append("path").datum(data).attr("fill", "url(#areaGrad)").attr("d", area);

    // Line
    const line = d3
      .line<TrafficPoint>()
      .x((d) => xScale(d.timestamp))
      .y((d) => yScale(d.rps))
      .curve(d3.curveBasis);

    g.append("path")
      .datum(data)
      .attr("fill", "none")
      .attr("stroke", "#3b82f6")
      .attr("stroke-width", 2)
      .attr("d", line);

    // Y Axis
    g.append("g")
      .call(d3.axisLeft(yScale).ticks(5).tickFormat(d3.format(".0f")))
      .selectAll("text")
      .attr("fill", "#9ca3af")
      .attr("font-size", "11px");

    g.selectAll(".domain").attr("stroke", "#374151");
    g.selectAll(".tick line").attr("stroke", "#374151");

    // X Axis –time labels
    g.append("g")
      .attr("transform", `translate(0,${h})`)
      .call(
        d3
          .axisBottom(xScale)
          .ticks(6)
          .tickFormat((d) => {
            const date = new Date((d as number) * 1000);
            return date.toLocaleTimeString([], { minute: "2-digit", second: "2-digit" });
          })
      )
      .selectAll("text")
      .attr("fill", "#9ca3af")
      .attr("font-size", "10px");

  }, [data]);

  return (
    <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-4">
      <h2 className="text-sm font-semibold text-gray-400 mb-3">
        Traffic — Requests per Second
      </h2>
      <svg ref={svgRef} className="w-full" style={{ height: 220 }} />
      {data.length < 2 && (
        <div className="flex items-center justify-center h-32 text-gray-600 text-sm">
          Waiting for traffic data…
        </div>
      )}
    </div>
  );
};
