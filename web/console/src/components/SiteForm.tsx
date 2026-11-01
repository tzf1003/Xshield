import { Button, Form, Input, Radio, Select, Space, Switch } from "antd";
import { useEffect } from "react";
import type { ReactNode } from "react";
import type { SiteSpecJson } from "../types.ts";

/** The form's internal shape: multi-line text areas for the array fields, split/joined on the edges. */
interface SiteFormValues {
  name: string;
  hosts: string;
  origin: string;
  sessionKind: "cookie" | "header";
  sessionValue: string;
  entries: string;
  bypass: string;
  mode: "observe" | "enforce";
  on_jev_unavailable: "deny" | "allow";
}

function linesToList(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function specToFormValues(spec: SiteSpecJson): SiteFormValues {
  return {
    name: spec.name,
    hosts: spec.hosts.join("\n"),
    origin: spec.origin,
    sessionKind: "cookie" in spec.session ? "cookie" : "header",
    sessionValue: "cookie" in spec.session ? spec.session.cookie : spec.session.header,
    entries: spec.entries.join("\n"),
    bypass: spec.bypass.join("\n"),
    mode: spec.mode,
    on_jev_unavailable: spec.on_jev_unavailable,
  };
}

export const EMPTY_SITE_FORM_VALUES: SiteFormValues = {
  name: "",
  hosts: "",
  origin: "",
  sessionKind: "cookie",
  sessionValue: "SESSIONID",
  entries: "",
  bypass: "",
  mode: "observe",
  on_jev_unavailable: "deny",
};

export function formValuesToSpec(values: SiteFormValues): SiteSpecJson {
  return {
    name: values.name.trim(),
    hosts: linesToList(values.hosts),
    origin: values.origin.trim(),
    session:
      values.sessionKind === "cookie"
        ? { cookie: values.sessionValue.trim() }
        : { header: values.sessionValue.trim() },
    entries: linesToList(values.entries),
    bypass: linesToList(values.bypass),
    mode: values.mode,
    on_jev_unavailable: values.on_jev_unavailable,
  };
}

interface SiteFormProps {
  initialValues: SiteFormValues;
  nameEditable: boolean;
  submitting: boolean;
  submitLabel: string;
  onSubmit: (spec: SiteSpecJson) => void;
  extraActions?: ReactNode;
}

export function SiteForm({
  initialValues,
  nameEditable,
  submitting,
  submitLabel,
  onSubmit,
  extraActions,
}: SiteFormProps) {
  const [form] = Form.useForm<SiteFormValues>();

  // Keep the form in sync when the server-loaded record changes (e.g. after a rollback).
  useEffect(() => {
    form.setFieldsValue(initialValues);
  }, [form, initialValues]);

  function handleFinish(values: SiteFormValues) {
    onSubmit(formValuesToSpec(values));
  }

  return (
    <Form<SiteFormValues>
      form={form}
      layout="vertical"
      initialValues={initialValues}
      onFinish={handleFinish}
    >
      <Form.Item
        label="站点名"
        name="name"
        rules={[
          { required: true, message: "请输入站点名" },
          { pattern: /^[a-z0-9_-]+$/, message: "仅允许小写字母、数字、下划线、短横线" },
        ]}
      >
        <Input disabled={!nameEditable} placeholder="emr" />
      </Form.Item>

      <Form.Item
        label="域名（每行一个）"
        name="hosts"
        rules={[{ required: true, message: "请至少填写一个域名" }]}
      >
        <Input.TextArea rows={2} placeholder="emr.example.com" />
      </Form.Item>

      <Form.Item
        label="源站地址"
        name="origin"
        rules={[{ required: true, message: "请输入源站地址，例如 http://10.0.0.5:8080" }]}
      >
        <Input placeholder="http://10.0.0.5:8080" />
      </Form.Item>

      <Form.Item label="会话凭证位置" required>
        <Space.Compact style={{ display: "flex" }}>
          <Form.Item name="sessionKind" noStyle>
            <Radio.Group>
              <Radio.Button value="cookie">Cookie</Radio.Button>
              <Radio.Button value="header">Header</Radio.Button>
            </Radio.Group>
          </Form.Item>
          <Form.Item
            name="sessionValue"
            noStyle
            rules={[{ required: true, message: "请输入 Cookie 名或 Header 名" }]}
          >
            <Input style={{ flex: 1 }} placeholder="SESSIONID" />
          </Form.Item>
        </Space.Compact>
      </Form.Item>

      <Form.Item
        label="入口路径（每行一个，* 结尾表示任意后缀）"
        name="entries"
        rules={[{ required: true, message: "请至少填写一个入口路径" }]}
      >
        <Input.TextArea rows={4} placeholder={"/login\n/api/home\n/share/*"} />
      </Form.Item>

      <Form.Item label="跳过路径（不判定、不记录，每行一个）" name="bypass">
        <Input.TextArea rows={2} placeholder={"/static/*\n/favicon.ico"} />
      </Form.Item>

      <Form.Item label="模式" name="mode">
        <ModeSwitch />
      </Form.Item>

      <Form.Item label="Jev 不可用时" name="on_jev_unavailable">
        <Select
          options={[
            { value: "deny", label: "拒绝（默认）" },
            { value: "allow", label: "放行（在判定日志中单独标注）" },
          ]}
        />
      </Form.Item>

      <Form.Item>
        <div style={{ display: "flex", gap: 12 }}>
          <Button type="primary" htmlType="submit" loading={submitting}>
            {submitLabel}
          </Button>
          {extraActions}
        </div>
      </Form.Item>
    </Form>
  );
}

/** Renders mode as an Observe/Enforce switch while the form field keeps the plain string value. */
function ModeSwitch({
  value,
  onChange,
}: {
  value?: "observe" | "enforce";
  onChange?: (value: "observe" | "enforce") => void;
}) {
  const checked = value === "enforce";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <Switch checked={checked} onChange={(next) => onChange?.(next ? "enforce" : "observe")} />
      <span>{checked ? "拦截（enforce）" : "观察（observe）"}</span>
    </div>
  );
}
