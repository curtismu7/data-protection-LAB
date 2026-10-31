import { useEffect, useState } from "react";
import PatternDiagram from "./PatternDiagram";
import { getJson } from "../api";

const NAMES = [["inspection-flow", "Inspection in and out"], ["sealed-prompt", "Sealed to your key"]];

// Diagrams are diagram-studio/1 data loaded by name from the server (rule 17); nothing is drawn from hand-built nodes here.
export default function DiagramTab({ vertical, resetSignal }) {
  const [pattern, setPattern] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState("inspection-flow");
  useEffect(() => { setPattern(null); getJson(`/api/diagram?vertical=${encodeURIComponent(vertical)}&name=${name}`).then(setPattern, (e) => setError(e.message)); }, [vertical, name]);
  if (error) return <p className="field-error" role="alert">Could not load the diagram ({error}).</p>;
  return (
    <>
      <div className="seg" role="group" aria-label="Diagram">
        {NAMES.map(([id, label]) => <button key={id} type="button" aria-pressed={name === id} onClick={() => setName(id)} data-testid={`dg-${id}`}>{label}</button>)}
      </div>
      {pattern ? <PatternDiagram key={name} pattern={pattern} resetSignal={resetSignal} /> : <p className="muted">Loading...</p>}
    </>
  );
}
