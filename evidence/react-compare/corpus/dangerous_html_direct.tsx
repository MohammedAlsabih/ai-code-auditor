// EXPECT-AUDITOR: R007 (dangerouslySetInnerHTML with a non-literal identifier)
export function Danger({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={html as any} />;
}
