import { getInjectable2 } from "@k8slens/injectable";
import { action, observable } from "mobx";
import type { Protocol } from "../engines/net/model";

export type NetworkSubView = "simulate" | "matrix" | "coverage" | "policies";

/**
 * An end of a simulated flow, as the pickers write it: `pod:<namespace>/<name>`,
 * `svc:<namespace>/<name>`, or an IP address outside the cluster.
 */
export type EndpointChoice = string;

/** What the user has chosen in a cluster's network view. One per cluster, kept while Lens runs. */
export const networkStateInjectable = getInjectable2({
  id: "real-governance-network-state",

  instantiate: () => (_clusterId: string) => {
    const state = {
      subView: observable.box<NetworkSubView>("simulate"),
      source: observable.box<EndpointChoice>(""),
      destination: observable.box<EndpointChoice>(""),
      port: observable.box("443"),
      protocol: observable.box<Protocol>("TCP"),
      /** For a service destination: which of its ports, by its port number. */
      servicePort: observable.box(""),
      matrixNamespaces: observable.set<string>(),
      matrixPortMode: observable.box<"declared" | "fixed">("declared"),
      matrixPort: observable.box("443"),
      matrixProtocol: observable.box<Protocol>("TCP"),
      policySearch: observable.box(""),
      coverageHideSystem: observable.box(true),
    };

    return {
      ...state,
      setSubView: action((view: NetworkSubView) => state.subView.set(view)),
      setSource: action((value: string) => state.source.set(value)),
      setDestination: action((value: string) => {
        state.destination.set(value);
        state.servicePort.set("");
      }),
      swap: action(() => {
        const source = state.source.get();

        state.source.set(state.destination.get().startsWith("svc:") ? "" : state.destination.get());
        state.destination.set(source);
        state.servicePort.set("");
      }),
      setPort: action((value: string) => state.port.set(value)),
      setProtocol: action((value: Protocol) => state.protocol.set(value)),
      setServicePort: action((value: string) => state.servicePort.set(value)),
      toggleMatrixNamespace: action((namespace: string) =>
        state.matrixNamespaces.has(namespace) ? state.matrixNamespaces.delete(namespace) : state.matrixNamespaces.add(namespace),
      ),
      /** Picks exactly these namespaces; none brings back the default of a few. */
      setMatrixNamespaces: action((namespaces: readonly string[]) => state.matrixNamespaces.replace(namespaces)),
      setMatrixPortMode: action((value: "declared" | "fixed") => state.matrixPortMode.set(value)),
      setMatrixPort: action((value: string) => state.matrixPort.set(value)),
      setMatrixProtocol: action((value: Protocol) => state.matrixProtocol.set(value)),
      setPolicySearch: action((value: string) => state.policySearch.set(value)),
      setCoverageHideSystem: action((value: boolean) => state.coverageHideSystem.set(value)),

      /** Opens the simulator with a flow between two pods filled in, as a matrix cell asks. */
      simulateBetween: action((source: string, destination: string, port?: number, protocol?: Protocol) => {
        state.subView.set("simulate");
        state.source.set(source);
        state.destination.set(destination);
        state.servicePort.set("");

        if (port !== undefined) state.port.set(String(port));
        if (protocol) state.protocol.set(protocol);
      }),

      /** Opens the simulator from one pod, as a menu asks. */
      simulateFrom: action((namespace: string, name: string) => {
        state.subView.set("simulate");
        state.source.set(`pod:${namespace}/${name}`);
      }),
    };
  },
});

export type NetworkState = ReturnType<ReturnType<(typeof networkStateInjectable)["instantiate"]>>;
