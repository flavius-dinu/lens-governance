import { getInjectable2 } from "@k8slens/injectable";
import { action, observable } from "mobx";

/** Whether one search picker's list is open, and which row the keyboard is on. One per picker. */
export const searchPickerStateInjectable = getInjectable2({
  id: "real-governance-search-picker-state",

  instantiate: () => (_pickerId: string) => {
    const state = {
      open: observable.box(false),
      highlighted: observable.box(0),
      /** Typed into since the list opened: until then the list shows everything, whatever the box holds. */
      typing: observable.box(false),
    };

    return {
      ...state,
      show: action(() => {
        if (!state.open.get()) {
          state.highlighted.set(0);
          state.typing.set(false);
        }

        state.open.set(true);
      }),
      type: action(() => {
        state.open.set(true);
        state.typing.set(true);
        state.highlighted.set(0);
      }),
      hide: action(() => state.open.set(false)),
      highlight: action((index: number) => state.highlighted.set(index)),
    };
  },
});
