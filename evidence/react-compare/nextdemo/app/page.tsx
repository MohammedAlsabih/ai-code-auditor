// Server Component (no "use client"). Imports Hooky (which calls useState with NO
// directive) -> Next.js 16 build error at the import boundary, not in this file.
import { Hooky } from '../components/Hooky';
import { ClientParent } from '../components/ClientParent';

export default function Page() {
  return (
    <main>
      <h1>Module-graph demo</h1>
      <Hooky />
      <ClientParent />
    </main>
  );
}
