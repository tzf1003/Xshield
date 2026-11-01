// CSV and TSV cells that spreadsheet software will not execute (docs/07 7.9.9): a cell that starts
// with a formula character gets a leading apostrophe.

const FORMULA_START = /^[=+\-@\t\r]/;

export function safeCell(value: string | number | boolean | null | undefined): string {
  const text = value === null || value === undefined ? "" : String(value);
  return FORMULA_START.test(text) ? `'${text}` : text;
}

/** One CSV field: quoted when it holds a comma, a quote or a line break. */
export function csvCell(value: string | number | boolean | null | undefined): string {
  const text = safeCell(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function csvLine(cells: Array<string | number | boolean | null | undefined>): string {
  return cells.map((cell) => csvCell(cell)).join(",");
}

/** One TSV field: tabs and line breaks become spaces so the row stays on one line. */
export function tsvCell(value: string | number | boolean | null | undefined): string {
  return safeCell(value).replace(/[\t\r\n]+/g, " ");
}

export function tsvLine(cells: Array<string | number | boolean | null | undefined>): string {
  return cells.map((cell) => tsvCell(cell)).join("\t");
}
