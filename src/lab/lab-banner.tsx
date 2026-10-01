import { Div, Span } from "@k8slens/element-components";
import { LayersIcon } from "@k8slens/icon";
import { PlainButton } from "@k8slens/input-components";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import { openGovernanceViewInjectable } from "../navigation.injectable";
import { Notice, plural } from "../ui/common";
import { isPolicyDocument, labModelInjectable } from "./lab-model.injectable";

/** Says, in a view that simulates, that the policy lab's drafts are part of what it shows. */
export const LabBanner = observer(({ clusterId }: { clusterId: string }) => {
  const lab = useInject(labModelInjectable)(clusterId);
  const openView = useInject(openGovernanceViewInjectable)();

  if (!lab.overlay.get().active) return null;

  const documents = lab.documents.get();
  const drafts = documents.filter(isPolicyDocument).length;

  return (
    <Notice>
      <Div $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center", wrap: true }}>
        <Span $flexChild>
          Simulating with the policy lab: {plural(drafts, "draft policy", "draft policies")} and {plural(documents.length - drafts, "test manifest")} laid over the
          cluster. Drafts are marked “draft”.
        </Span>
        <PlainButton Icon={LayersIcon} onClick={() => void openView(clusterId, "lab")}>
          Open the lab
        </PlainButton>
        <PlainButton onClick={() => lab.state.setApplyDrafts(false)}>Ignore the drafts</PlainButton>
      </Div>
    </Notice>
  );
});
