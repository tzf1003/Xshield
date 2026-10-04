import { CloseCircleFilled, ExclamationCircleFilled, LoadingOutlined } from "@ant-design/icons";
import { Form, InputNumber, type InputNumberProps, Switch } from "antd";
import { cloneElement, type ReactElement, type ReactNode } from "react";
import type { Issue } from "../../sites/model/validation.ts";

type FieldProps = {
  /** Id of the control: the label points at it, the messages describe it. */
  id: string;
  label: ReactNode;
  /** Plain guidance and examples shown under the control. */
  hint?: ReactNode;
  /** The client-side finding for this field (error or warning). */
  issue?: Issue;
  required?: boolean;
  /** For radio groups and other controls a label cannot point at: label them with `aria-label`. */
  group?: boolean;
  children: ReactElement;
};

/**
 * One labelled control with its guidance and validation message. The control is controlled by
 * the caller (the draft lives in the workspace, not in the form), so the Form.Item is only the
 * layout: label, hint and the finding. Messages are linked with `aria-describedby`; they are
 * deliberately not live regions, so typing never makes a screen reader talk over the operator.
 */
export function Field({ id, label, hint, issue, required, group, children }: FieldProps) {
  const messageId = `${id}-msg`;
  const status = issue ? (issue.severity === "error" ? "error" : "warning") : undefined;
  const described = hint || issue ? messageId : undefined;
  const control = group
    ? children
    : cloneElement(children as ReactElement<Record<string, unknown>>, {
        id,
        status,
        "aria-describedby": described,
      });
  return (
    <Form.Item
      label={label}
      htmlFor={group ? undefined : id}
      required={required}
      validateStatus={status}
      extra={
        hint || issue ? (
          <span id={messageId} className="xs-field-msg">
            {issue && (
              <span className={`xs-field-issue xs-field-issue--${issue.severity}`}>
                {issue.severity === "error" ? (
                  <CloseCircleFilled aria-hidden="true" />
                ) : (
                  <ExclamationCircleFilled aria-hidden="true" />
                )}{" "}
                {issue.message}
              </span>
            )}
            {hint && <span className="xs-field-hint">{hint}</span>}
          </span>
        ) : undefined
      }
    >
      {control}
    </Form.Item>
  );
}

/**
 * Button `loading` with an icon that is not announced: antd's default one reads "loading" and
 * stays in the button's accessible name, so "保存草稿" would become "loading 保存草稿".
 */
export const busy = (on: boolean) =>
  on ? { icon: <LoadingOutlined aria-hidden="true" /> } : false;

type ToggleProps = {
  checked: boolean;
  onChange: (checked: boolean) => void;
  /** Accessible name of the switch (the form label is visual only). */
  label: string;
  onText?: string;
  offText?: string;
};

/** A switch whose state is also written next to it, so colour is never the only signal. */
export function Toggle({
  checked,
  onChange,
  label,
  onText = "启用",
  offText = "关闭",
}: ToggleProps) {
  return (
    <span className="xs-toggle">
      <Switch checked={checked} aria-label={label} onChange={onChange} />
      <span className="xs-toggle-text">{checked ? onText : offText}</span>
    </span>
  );
}

type NumProps = Omit<InputNumberProps<number>, "value" | "onChange"> & {
  value: number;
  onChange: (value: number) => void;
  unit?: string;
};

/** Whole numbers with their unit beside them; an emptied box is NaN, which validation flags. */
export function NumInput({ value, onChange, unit, ...rest }: NumProps) {
  return (
    <InputNumber<number>
      {...rest}
      className="xs-num"
      precision={0}
      changeOnWheel={false}
      suffix={unit}
      value={Number.isFinite(value) ? value : null}
      onChange={(next) => onChange(next === null ? Number.NaN : next)}
    />
  );
}
