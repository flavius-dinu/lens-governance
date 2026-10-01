const React = require("react");
const strip = (props) => Object.fromEntries(Object.entries(props).filter(([key]) => !key.startsWith("$") && key !== "Icon"));
module.exports = {
  TextInput: (props) => React.createElement("input", { ...strip(props), readOnly: true }),
  PlainButton: (props) => React.createElement("button", strip(props), props.children),
  PrimaryButton: (props) => React.createElement("button", strip(props), props.children),
  DangerButton: (props) => React.createElement("button", strip(props), props.children),
};
