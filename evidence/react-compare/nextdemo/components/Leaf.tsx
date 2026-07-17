// NO directive, uses useState, but ONLY imported from ClientParent.tsx ("use client")
// -> LEGAL: inherits the client boundary through the module graph.
import { useState } from 'react';

export function Leaf() {
  const [t] = useState('leaf');
  return <span>{t}</span>;
}
