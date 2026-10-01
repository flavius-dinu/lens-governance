const React = require("react");
module.exports = {
  LightWeightTabs: ({ tabs, selected }) =>
    React.createElement("nav", null, tabs.map((tab) => React.createElement("b", { key: tab.id }, tab.id === selected ? `<${tab.label}>` : ` ${tab.label} `, tab.badge))),
};
