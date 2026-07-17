// NO "use client" directive, uses useState, imported by server component app/page.tsx
// -> Next.js 16 fails the build. Per-file rules cannot see this (file is not under app/).
import { useState } from 'react';

export function Hooky() {
  const [n, setN] = useState(0);
  return <button onClick={() => setN(n + 1)}>{n}</button>;
}
