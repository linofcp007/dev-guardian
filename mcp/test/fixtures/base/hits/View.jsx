// Hits for js-dangerouslySetInnerHTML.
//
// Three element shapes, because the rule is written as a self-closing element
// carrying exactly one attribute — `<$EL dangerouslySetInnerHTML={...} />` —
// and it was not obvious from reading it that the other two forms match at all.
// Measured, they do: semgrep treats JSX attributes as a set the pattern must be
// a subset of, and closes a `<el></el>` pair into the same node. All three are
// pinned so that a future rewrite of the pattern cannot silently drop one.

export function Bare(props) {
  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
}

export function WithSiblingAttributes(props) {
  return <div className="post-body" id="main" dangerouslySetInnerHTML={{ __html: props.html }} />;
}

export function NotSelfClosing(props) {
  return <section dangerouslySetInnerHTML={{ __html: props.html }}></section>;
}
