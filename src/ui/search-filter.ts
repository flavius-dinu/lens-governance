/** What a search picker lists, and which of it a typed query keeps. */

export interface SearchOption {
  readonly value: string;
  /** What the option is: Pod, Service, … Shown as a badge when given. */
  readonly kind?: string;
  readonly name: string;
  /** Options are listed under their group, such as a namespace, when given. */
  readonly group?: string;
  /** A second line: the workload, the ports. */
  readonly detail?: string;
}

/** Every word typed has to appear somewhere in the option, in any order. */
export const filterOptions = (options: readonly SearchOption[], query: string, current: string) => {
  const text = query.trim().toLowerCase();

  // A value just picked shows the whole list again, with the pick in it.
  if (!text || options.some((option) => option.value === current && option.value.toLowerCase() === text)) return options;

  const words = text.split(/\s+/);

  return options.filter((option) => {
    const haystack = `${option.value} ${option.kind ?? ""} ${option.group ?? ""} ${option.name} ${option.detail ?? ""}`.toLowerCase();

    return words.every((word) => haystack.includes(word));
  });
};
