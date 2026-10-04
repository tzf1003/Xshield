import {
  ApartmentOutlined,
  AuditOutlined,
  DatabaseOutlined,
  ExperimentOutlined,
  ExportOutlined,
  FileSearchOutlined,
  FolderOpenOutlined,
  HomeOutlined,
  KeyOutlined,
  LockOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
} from "@ant-design/icons";
import type { ReactNode } from "react";
import type { IconKey } from "./nav-model.ts";

const icons: Record<IconKey, ReactNode> = {
  home: <HomeOutlined />,
  site: <ApartmentOutlined />,
  "search-doc": <FileSearchOutlined />,
  model: <ExperimentOutlined />,
  agent: <RobotOutlined />,
  ledger: <TeamOutlined />,
  case: <FolderOpenOutlined />,
  evidence: <SafetyCertificateOutlined />,
  hold: <LockOutlined />,
  export: <ExportOutlined />,
  jobs: <DatabaseOutlined />,
  audit: <AuditOutlined />,
  calibration: <AuditOutlined />,
  key: <KeyOutlined />,
  session: <SettingOutlined />,
};

export function navIcon(key: IconKey): ReactNode {
  return icons[key];
}
