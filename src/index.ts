import { getFeature, registerInjectablesFromModules } from "@k8slens/feature-core";
import modulesWithInjectables from "./**/*.injectable.(ts|tsx)";
import stylesheets from "./**/!(_*).(scss|css)";

export const realGovernanceFeature = getFeature({
  id: "real-governance",
  register: (di) => {
    // Auto-discovers every `*.injectable.(ts|tsx)` file under this directory and registers
    // it. Preferred over registering injectables one by one — adding a new injectable file
    // automatically wires it up; you can't forget to register it.
    // Every `.scss`, `.css`, `.module.scss` and `.module.css` you import becomes a stylesheet
    // injectable when the extension builds, and rides along here the same way; a `_partial.scss`
    // stays out of the glob.
    registerInjectablesFromModules(di, [...modulesWithInjectables, ...stylesheets]);

  },
});
