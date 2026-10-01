// Every glyph of @k8slens/icon as a placeholder element. The names come from the package's
// declarations: requiring the package here would resolve to this stub, as the tests alias it.
const fs = require("fs");
const path = require("path");
const React = require("react");
const declarations = fs.readFileSync(path.join(process.env.RG_PROJECT, "node_modules/@k8slens/icon/dist/index.d.ts"), "utf8");
const names = [...new Set(declarations.match(/\b[A-Z][A-Za-z0-9]*Icon\b/g))];
module.exports = Object.fromEntries(names.map((name) => [name, () => React.createElement("i", { "data-icon": name })]));
