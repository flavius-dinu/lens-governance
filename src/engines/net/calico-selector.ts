/**
 * Calico's selector language: `app == 'web' && has(tier)`, `role in {'db', 'cache'}`, `all()`.
 * Parsed once into a predicate over labels.
 */

export type CalicoSelector = (labels: Readonly<Record<string, string>>) => boolean;

type Token =
  | { type: "string"; value: string }
  | { type: "word"; value: string }
  | { type: "op"; value: "==" | "!=" | "&&" | "||" | "!" | "(" | ")" | "{" | "}" | "," };

const tokenize = (text: string): Token[] => {
  const tokens: Token[] = [];
  let index = 0;

  while (index < text.length) {
    const char = text[index]!;

    if (/\s/.test(char)) {
      index++;
      continue;
    }

    const two = text.slice(index, index + 2);

    if (two === "==" || two === "!=" || two === "&&" || two === "||") {
      tokens.push({ type: "op", value: two });
      index += 2;
      continue;
    }

    if ("!(){},".includes(char)) {
      tokens.push({ type: "op", value: char as "!" });
      index++;
      continue;
    }

    if (char === "'" || char === '"') {
      const end = text.indexOf(char, index + 1);

      if (end === -1) throw new Error(`Unterminated string in selector "${text}"`);

      tokens.push({ type: "string", value: text.slice(index + 1, end) });
      index = end + 1;
      continue;
    }

    const word = /^[A-Za-z0-9_./\-]+/.exec(text.slice(index));

    if (!word) throw new Error(`Unexpected "${char}" in selector "${text}"`);

    tokens.push({ type: "word", value: word[0] });
    index += word[0].length;
  }

  return tokens;
};

export const parseCalicoSelector = (text: string | undefined | null): CalicoSelector => {
  const source = (text ?? "").trim();

  if (source === "") return () => true;

  const tokens = tokenize(source);
  let position = 0;

  const peek = () => tokens[position];
  const next = () => tokens[position++];
  const isOp = (value: string) => peek()?.type === "op" && peek()!.value === value;
  const isWord = (value: string) => peek()?.type === "word" && peek()!.value === value;

  const expect = (value: string) => {
    const token = next();

    if (!token || token.value !== value || token.type === "string") throw new Error(`Expected "${value}" in selector "${source}"`);
  };

  const readString = () => {
    const token = next();

    if (token?.type !== "string") throw new Error(`Expected a quoted value in selector "${source}"`);

    return token.value;
  };

  const readSet = () => {
    expect("{");

    const values: string[] = [];

    while (!isOp("}")) {
      values.push(readString());

      if (isOp(",")) next();
    }

    expect("}");

    return values;
  };

  const parsePrimary = (): CalicoSelector => {
    if (isOp("(")) {
      next();

      const inner = parseOr();

      expect(")");

      return inner;
    }

    if (isOp("!")) {
      next();

      const inner = parsePrimary();

      return (labels) => !inner(labels);
    }

    const word = next();

    if (word?.type !== "word") throw new Error(`Expected a label in selector "${source}"`);

    if ((word.value === "all" || word.value === "global") && isOp("(")) {
      next();
      expect(")");

      return () => true;
    }

    if (word.value === "has" && isOp("(")) {
      next();

      const key = next();

      if (key?.type !== "word") throw new Error(`Expected a label in has() in selector "${source}"`);

      expect(")");

      return (labels) => Object.prototype.hasOwnProperty.call(labels, key.value);
    }

    const key = word.value;

    if (isOp("==")) {
      next();

      const value = readString();

      return (labels) => labels[key] === value;
    }

    if (isOp("!=")) {
      next();

      const value = readString();

      // Calico: a selector `a != 'x'` also matches endpoints without the label.
      return (labels) => labels[key] !== value;
    }

    if (isWord("in")) {
      next();

      const values = readSet();

      return (labels) => labels[key] !== undefined && values.includes(labels[key]!);
    }

    if (isWord("not")) {
      next();

      if (!isWord("in")) throw new Error(`Expected "in" after "not" in selector "${source}"`);

      next();

      const values = readSet();

      return (labels) => labels[key] === undefined || !values.includes(labels[key]!);
    }

    if (isWord("contains")) {
      next();

      const value = readString();

      return (labels) => labels[key]?.includes(value) ?? false;
    }

    if (isWord("starts") || isWord("ends")) {
      const which = next()!.value;

      if (!isWord("with")) throw new Error(`Expected "with" in selector "${source}"`);

      next();

      const value = readString();

      return (labels) => (which === "starts" ? labels[key]?.startsWith(value) : labels[key]?.endsWith(value)) ?? false;
    }

    throw new Error(`Expected an operator after "${key}" in selector "${source}"`);
  };

  const parseAnd = (): CalicoSelector => {
    let left = parsePrimary();

    while (isOp("&&")) {
      next();

      const right = parsePrimary();
      const current = left;

      left = (labels) => current(labels) && right(labels);
    }

    return left;
  };

  const parseOr = (): CalicoSelector => {
    let left = parseAnd();

    while (isOp("||")) {
      next();

      const right = parseAnd();
      const current = left;

      left = (labels) => current(labels) || right(labels);
    }

    return left;
  };

  const selector = parseOr();

  if (position < tokens.length) throw new Error(`Unexpected "${tokens[position]!.value}" in selector "${source}"`);

  return selector;
};

/** A selector that does not parse selects nothing, and says why. */
export const safeCalicoSelector = (text: string | undefined | null): { selector: CalicoSelector; error?: string } => {
  try {
    return { selector: parseCalicoSelector(text) };
  } catch (error) {
    return { selector: () => false, error: error instanceof Error ? error.message : String(error) };
  }
};
