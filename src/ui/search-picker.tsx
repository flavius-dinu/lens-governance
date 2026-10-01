/**
 * A text box with a searchable list under it: for picking one of many pods or services, where a
 * browser's own suggestion list is too small to find anything in. It still takes any typed value,
 * such as an IP address.
 */

import { Badge } from "@k8slens/badge";
import { Div, Span } from "@k8slens/element-components";
import { TextInput } from "@k8slens/input-components";
import { useInject } from "@k8slens/use-inject";
import { observer } from "mobx-react";
import { type KeyboardEvent, useId } from "react";
import { filterOptions, type SearchOption } from "./search-filter";
import styles from "./governance.module.scss";
import { searchPickerStateInjectable } from "./search-picker-state.injectable";

/** The most rows drawn at once; the user narrows the rest by typing. */
const rowLimit = 150;

export const SearchPicker = observer(
  ({
    value,
    onChange,
    options,
    placeholder,
    hint = "or type any value",
  }: {
    value: string;
    onChange: (value: string) => void;
    options: readonly SearchOption[];
    placeholder?: string;
    /** What else the box takes, said under the count. */
    hint?: string;
  }) => {
    const picker = useInject(searchPickerStateInjectable)(useId());
    const open = picker.open.get();
    const matching = !open ? [] : picker.typing.get() ? filterOptions(options, value, value) : options;
    const shown = matching.slice(0, rowLimit);
    const highlighted = Math.min(picker.highlighted.get(), Math.max(shown.length - 1, 0));

    const choose = (option: SearchOption) => {
      onChange(option.value);
      picker.hide();
    };

    const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();

        if (!open) return picker.show();

        picker.highlight((highlighted + (event.key === "ArrowDown" ? 1 : shown.length - 1)) % Math.max(shown.length, 1));
      } else if (event.key === "Enter" && open && shown[highlighted]) {
        event.preventDefault();
        choose(shown[highlighted]!);
      } else if (event.key === "Escape") {
        picker.hide();
      }
    };

    return (
      <Div $anchor $width="full">
        <TextInput
          value={value}
          placeholder={placeholder}
          spellCheck={false}
          autoComplete="off"
          onChange={(event) => {
            onChange(event.target.value);
            picker.type();
          }}
          onFocus={picker.show}
          onClick={picker.show}
          onBlur={picker.hide}
          onKeyDown={onKeyDown}
          $width="full"
        />
        {open && (
          <Div $anchoredAt={{ position: "bottom span-right", gap: "xxs" }} $className={styles.pickerPanel} $backgroundColor="backgroundPrimary" $boxShadow="elevated">
            <Div $padding={{ horizontal: "s", vertical: "xs" }} $className={styles.pickerSummary} $backgroundColor="backgroundPrimary">
              <Span $font={{ size: "s" }} $color="textMuted">
                {matching.length === options.length ? `${options.length} to pick from` : `${matching.length} of ${options.length} match`}
                {matching.length > rowLimit ? ` · showing ${rowLimit}, type to narrow` : ""} · {hint}
              </Span>
            </Div>
            {shown.length === 0 && (
              <Div $padding="s">
                <Span $font={{ size: "s" }} $color="textMuted">
                  Nothing matches: what you typed is used as it is.
                </Span>
              </Div>
            )}
            {shown.map((option, index) => (
              <Div key={option.value}>
                {option.group && (index === 0 || shown[index - 1]!.group !== option.group) && (
                  <Div $padding={{ horizontal: "s", top: "xs" }} $className={styles.pickerGroup}>
                    <Span $font={{ size: "xs", bold: true, uppercase: true }} $color="textMuted">
                      {option.group}
                    </Span>
                  </Div>
                )}
                <Div
                  $className={[styles.pickerRow, { [styles.pickerRowActive]: index === highlighted, [styles.pickerRowCurrent]: option.value === value }]}
                  $padding={{ horizontal: "s", vertical: "xxs" }}
                  $flex={{ direction: "horizontal", gap: "s", verticalAlign: "center" }}
                  // Mouse down, not click: picking must happen before the text box loses focus and closes the list.
                  onMouseDown={(event) => {
                    event.preventDefault();
                    choose(option);
                  }}
                  onMouseEnter={() => picker.highlight(index)}
                >
                  {option.kind && <Badge small label={option.kind} />}
                  <Div $flex={{ direction: "vertical", gap: "zero" }} $flexChild="shrinkable">
                    <Span $font={{ textOverflow: "ellipsis", noWrap: true }}>{option.name}</Span>
                    {option.detail && (
                      <Span $font={{ size: "xs", textOverflow: "ellipsis", noWrap: true }} $color="textMuted">
                        {option.detail}
                      </Span>
                    )}
                  </Div>
                </Div>
              </Div>
            ))}
          </Div>
        )}
      </Div>
    );
  },
);
