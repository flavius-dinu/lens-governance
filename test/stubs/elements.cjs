// Plain-HTML stand-ins for Lens's UI packages, for rendering the views outside Lens.
const React = require("react");

const strip = (props) => {
  const out = {};
  for (const [key, value] of Object.entries(props)) {
    if (key.startsWith("$") || key === "Icon" || key === "small" || key === "label") continue;
    out[key] = value;
  }
  if (props.$tooltip && typeof props.$tooltip === "string") out.title = props.$tooltip;
  return out;
};

const element = (tag) => (props) => React.createElement(tag, strip(props), props.children);

module.exports = {
  Div: element("div"), Span: element("span"), Button: element("button"), A: element("a"), P: element("p"),
  H1: element("h1"), H2: element("h2"), H3: element("h3"), Code: element("code"), Pre: element("pre"),
  Table: element("table"), Tr: element("tr"), Th: element("th"), Td: element("td"), Ul: element("ul"), Li: element("li"),
  Svg: element("svg"), Input: element("input"),
  TextArea: (props) => React.createElement("textarea", { ...strip(props), readOnly: true, value: props.value }),
  ClickableDiv: (props) => React.createElement("div", { ...strip(props), "data-clickable": "" }, props.children),
};
