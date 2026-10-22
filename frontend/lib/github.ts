export const GITHUB_NONCE_COOKIE = "aspm_gh_nonce";

export interface GitHubInstallation {
  id: number;
  account_login?: string;
  account_type?: string;
  repository_selection?: "all" | "selected";
  status: "active" | "suspended";
  updated_at?: string;
}

export interface InstallationSummary {
  installation: GitHubInstallation;
  repositories: number;
  revoked: number;
}

export function manageInstallationUrl(installation: GitHubInstallation): string {
  if (installation.account_type === "Organization" && installation.account_login) {
    return `https://github.com/organizations/${encodeURIComponent(installation.account_login)}/settings/installations/${installation.id}`;
  }
  return `https://github.com/settings/installations/${installation.id}`;
}

export const INSTALL_ERRORS: Record<string, string> = {
  invalid: "GitHub sent back an incomplete request. Start the connection again.",
  state: "The connection link expired or doesn't belong to this session. Start again.",
  conflict: "That GitHub installation is already linked to another ASPM account.",
  notfound: "GitHub doesn't know that installation. Start the connection again.",
  unconfigured: "GitHub isn't set up on this server yet.",
  github: "GitHub didn't answer. Try again in a moment.",
  unreachable: "The ASPM service isn't responding right now. Try again in a moment.",
};
