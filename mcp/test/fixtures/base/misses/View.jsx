// Near-misses for js-dangerouslySetInnerHTML.
//
// The second one is the discriminating case: the identifier
// `dangerouslySetInnerHTML` appears, spelled exactly, as an OBJECT PROPERTY
// rather than as a JSX attribute. It is silent BECAUSE the pattern is a JSX
// element and semgrep is matching the tree — any regex over the file, and any
// pattern that dropped the `<$EL ... />` frame, would flag it. Building the
// props object is also legitimate: React only treats the key as raw HTML when
// it reaches an element, which is what the first form does and this does not.

export function Escaped(props) {
  return <div className="post-body">{props.text}</div>;
}

export function PropsBag(html) {
  const attributes = { dangerouslySetInnerHTML: { __html: html } };
  return attributes;
}

export function Sanitised(props) {
  return <article title={props.title} lang="pt">{props.body}</article>;
}
