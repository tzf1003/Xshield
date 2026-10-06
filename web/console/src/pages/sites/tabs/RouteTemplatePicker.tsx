import { Button, Modal, Popconfirm, Radio } from "antd";
import { useState } from "react";
import {
  applyRouteTemplate,
  type RouteTemplate,
  routeTemplates,
  spaTemplate,
} from "../../../sites/model/route-templates.ts";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";

/** Which example, what it is, and what applying it changes besides the route list. */
function TemplateChoice({
  chosen,
  onChoose,
}: {
  chosen: RouteTemplate;
  onChoose: (template: RouteTemplate) => void;
}) {
  return (
    <>
      <Radio.Group
        aria-label="示例模板"
        className="xs-choice xs-template-choice"
        value={chosen.id}
        onChange={(event) =>
          onChoose(routeTemplates.find((item) => item.id === event.target.value) ?? spaTemplate)
        }
      >
        {routeTemplates.map((template) => (
          <Radio key={template.id} value={template.id}>
            <span className="xs-choice-title">{template.title}</span>
          </Radio>
        ))}
      </Radio.Group>
      <p>{chosen.description}</p>
      {chosen.requiresSensor && (
        <p className="muted">
          套用后同时启用浏览器探针：SENSOR_HTML
          页面只有在探针启用时才会被注入和放行（变更栏会列出这一项）。
        </p>
      )}
    </>
  );
}

/**
 * The wizard's 快速开始 card: choose an example and apply it. Applying replaces the route list
 * (after a confirmation once the operator has routes of their own).
 */
export function WizardTemplatePicker({ ws }: { ws: WorkspaceApi }) {
  const [chosen, setChosen] = useState<RouteTemplate>(spaTemplate);
  const draft = ws.draft;
  if (!draft) return null;
  const customized = draft.policy.routes.length > 0;
  const apply = () => ws.update((current) => applyRouteTemplate(current, chosen));
  const label = `套用示例：${chosen.title}`;
  return (
    <>
      <TemplateChoice chosen={chosen} onChoose={setChosen} />
      {customized ? (
        <Popconfirm
          title="套用示例会替换当前的路由列表。"
          okText="替换"
          cancelText="取消"
          onConfirm={apply}
        >
          <Button disabled={ws.locked}>{label}</Button>
        </Popconfirm>
      ) : (
        <Button disabled={ws.locked} onClick={apply}>
          {label}
        </Button>
      )}
    </>
  );
}

/**
 * 套用示例 on an existing site's route table: the same examples in a dialog that says what is
 * replaced. It only changes the draft; the change bar shows the result and can discard it.
 */
export function RoutesTemplateButton({ ws, disabled }: { ws: WorkspaceApi; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [chosen, setChosen] = useState<RouteTemplate>(spaTemplate);
  const count = ws.draft?.policy.routes.length ?? 0;
  return (
    <>
      <Button disabled={disabled} onClick={() => setOpen(true)}>
        套用示例
      </Button>
      <Modal
        open={open}
        title="套用示例"
        destroyOnHidden
        onCancel={() => setOpen(false)}
        footer={
          <>
            <Button onClick={() => setOpen(false)}>取消</Button>
            <Button
              type="primary"
              danger
              disabled={disabled}
              onClick={() => {
                ws.update((current) => applyRouteTemplate(current, chosen));
                setOpen(false);
              }}
            >
              替换路由列表
            </Button>
          </>
        }
      >
        <TemplateChoice chosen={chosen} onChoose={setChosen} />
        <p className="xs-template-note">
          {count > 0
            ? `套用会用示例替换当前的 ${count} 条路由。只改动草稿：变更栏会列出全部差异，可以放弃，保存后才生效。`
            : "套用会用示例替换默认入口路由。只改动草稿，保存后才生效。"}
        </p>
      </Modal>
    </>
  );
}
