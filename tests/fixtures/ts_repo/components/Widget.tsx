"use client";
import { useEffect, useState } from 'react';

export function Widget({ items, html }: { items: string[]; html: string }) {
  const [visible, setVisible] = useState(false);
  if (visible) {
    const [extra] = useState('');
  }
  useEffect(() => {
    setVisible(true);
  });
  return (
    <div dangerouslySetInnerHTML={{ __html: html }}>
      {items.map((item, index) => (
        <span key={index}>{item}</span>
      ))}
    </div>
  );
}
