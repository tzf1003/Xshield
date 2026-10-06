import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Input } from "antd";
import { useState } from "react";
import type { SiteRouteConfig, SiteSensorHtmlAdapter } from "../../../api.ts";
import {
  emptySensorBuild,
  MAX_SENSOR_BUILDS,
  sensorBuilds,
} from "../../../sites/model/route-flow.ts";
import { formatBytes } from "../../../sites/model/units.ts";
import type { Issue } from "../../../sites/model/validation.ts";
import { Field, NumInput } from "../fields";
import { PageDigestPanel } from "./PageDigestPanel";
import { FlowGroup, type FlowGroupProps } from "./route-flow-groups";

/*
 * The SENSOR_HTML group of the route drawer: the approved builds of a static page, each with
 * the in-browser helper that computes its digest and `</head>` byte offset. Kept apart from the
 * other flow groups (route-flow-groups.tsx) because the build list and the helper make it the
 * largest of them.
 */

/** One approved build: its revision, digest and offset, and the helper that computes the two. */
function BuildFields({
  index,
  build,
  route,
  issueFor,
  disabled,
  onChange,
  onRemove,
}: {
  index: number;
  build: SiteSensorHtmlAdapter;
  route: SiteRouteConfig;
  issueFor: (field: string) => Issue | undefined;
  disabled: boolean;
  onChange: (build: SiteSensorHtmlAdapter) => void;
  onRemove?: () => void;
}) {
  const [helper, setHelper] = useState(false);
  const at = index === 0 ? "sensor_html" : `sensor_html.additional_adapters.${index - 1}`;
  const name = index === 0 ? "主构建" : `附加构建 ${index}`;
  const id = `flow-build-${index}`;
  return (
    <fieldset className="xs-flow-build">
      <legend>{name}</legend>
      <Field
        id={`${id}-revision`}
        label="构建版本"
        required
        issue={issueFor(`${at}.adapter_revision`)}
        hint="给这一版页面起的标识，例如 app-r1；字母、数字和 _ . -。"
      >
        <Input
          value={build.adapter_revision}
          maxLength={128}
          spellCheck={false}
          onChange={(event) => onChange({ ...build, adapter_revision: event.target.value })}
        />
      </Field>
      <Field
        id={`${id}-digest`}
        label="页面摘要（SHA-256）"
        required
        issue={issueFor(`${at}.origin_sha256`)}
        hint="源站返回的完整页面字节的 SHA-256，64 位小写十六进制。"
      >
        <Input
          className="mono"
          value={build.origin_sha256}
          maxLength={64}
          spellCheck={false}
          onChange={(event) => onChange({ ...build, origin_sha256: event.target.value })}
        />
      </Field>
      <Field
        id={`${id}-offset`}
        label="注入偏移（字节）"
        required
        issue={issueFor(`${at}.injection_offset`)}
        hint={`第一个 </head> 在页面字节中的位置（字节，不是字符），须小于响应上限（${formatBytes(route.max_response_bytes)}）。`}
      >
        <NumInput
          value={build.injection_offset}
          min={0}
          unit="字节"
          onChange={(value) => onChange({ ...build, injection_offset: value })}
        />
      </Field>
      <div className="xs-flow-build-actions">
        <Button
          aria-expanded={helper}
          aria-controls={`${id}-helper`}
          disabled={disabled}
          onClick={() => setHelper((open) => !open)}
        >
          {index === 0 ? "从页面源码计算" : `从页面源码计算（${name}）`}
        </Button>
        {onRemove && (
          <Button
            danger
            icon={<DeleteOutlined aria-hidden="true" />}
            disabled={disabled}
            onClick={onRemove}
          >
            移除{name}
          </Button>
        )}
      </div>
      {helper && (
        <div id={`${id}-helper`}>
          <PageDigestPanel
            id={id}
            maxResponseBytes={route.max_response_bytes}
            disabled={disabled}
            onDigest={(digest) =>
              onChange({
                ...build,
                origin_sha256: digest.sha256,
                injection_offset: digest.injectionOffset,
              })
            }
          />
        </div>
      )}
    </fieldset>
  );
}

/** SENSOR_HTML 页面构建: the approved builds of a static page (the response mode turns it on). */
export function SensorHtmlGroup(props: FlowGroupProps) {
  const { route, issueFor, disabled, onBuilds } = props;
  if (!route.sensor_html) return null;
  const builds = sensorBuilds(route);
  const replace = (at: number, build: SiteSensorHtmlAdapter) =>
    onBuilds(builds.map((item, index) => (index === at ? build : item)));
  return (
    <FlowGroup
      title="SENSOR_HTML 页面构建"
      note="edge 只放行完整字节的 SHA-256 与某个已批准构建一致的源站页面，并在该构建的 </head> 处注入浏览器探针；其他字节在释放前一律拒绝。页面必须是 UTF-8、GET，且站点要启用浏览器探针。源站发布新页面时，把新构建加为附加构建，确认生效后再移除旧的。"
      issue={issueFor("sensor_html")}
    >
      {builds.map((build, index) => (
        <BuildFields
          // A build has no identity of its own while its revision is being typed.
          // biome-ignore lint/suspicious/noArrayIndexKey: builds are positional
          key={index}
          index={index}
          build={build}
          route={route}
          issueFor={issueFor}
          disabled={disabled}
          onChange={(next) => replace(index, next)}
          onRemove={
            index === 0 ? undefined : () => onBuilds(builds.filter((_, at) => at !== index))
          }
        />
      ))}
      <Button
        icon={<PlusOutlined aria-hidden="true" />}
        disabled={disabled || builds.length >= MAX_SENSOR_BUILDS}
        onClick={() => onBuilds([...builds, emptySensorBuild()])}
      >
        添加附加构建
      </Button>
      <p className="muted xs-flow-count">
        共 {builds.length} 个构建（最多 {MAX_SENSOR_BUILDS} 个）。
      </p>
    </FlowGroup>
  );
}
