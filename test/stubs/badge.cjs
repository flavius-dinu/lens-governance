const React = require("react");
module.exports = { Badge: (props) => React.createElement("span", { "data-badge": "", title: props.$tooltip }, "[", props.label ?? props.children, "]") };
