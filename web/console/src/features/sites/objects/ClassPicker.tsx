// The class choice of a row (console design 1.3): a native select like the declaration dialog's, with the classes on
// offer and a last entry that asks for a new class. The new class's id and name are asked for by the row beside it.

import { OBJECT_TEXT } from "../../../lib/vocab.ts";

/** The select's value for a class that does not exist yet; never a valid class id, which is lower-case letters. */
export const NEW_CLASS = "__new__";

type Props = {
  label: string;
  value: string;
  options: ReadonlyArray<{ id: string; name: string }>;
  disabled?: boolean;
  onChange: (value: string) => void;
};

export function ClassPicker({ label, value, options, disabled = false, onChange }: Props) {
  const listed = options.some((item) => item.id === value) || value === NEW_CLASS;
  return (
    <select
      className="native-input obj-class-pick"
      aria-label={label}
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
    >
      {listed ? null : <option value={value}>{value}</option>}
      {options.map((item) => (
        <option key={item.id} value={item.id}>
          {item.name} {item.id}
        </option>
      ))}
      <option value={NEW_CLASS}>{OBJECT_TEXT.coldStart.newClass}</option>
    </select>
  );
}
