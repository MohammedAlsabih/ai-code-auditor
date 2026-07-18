// EXPECT-ESLINT: rules-of-hooks (Hooks.useState — a PascalCase object member
// call IS treated as a hook by eslint-plugin-react-hooks; here it is called
// conditionally). Auditor must AGREE (R001).
export function PascalObj({ flag }: { flag: boolean }) {
  if (flag) {
    const [v] = Hooks.useState(0);
    return <p>{v}</p>;
  }
  return null;
}
