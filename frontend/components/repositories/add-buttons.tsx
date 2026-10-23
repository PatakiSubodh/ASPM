"use client";

import { ArrowUpRight, Plus } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import type { AvailableRepository, BranchList } from "@/lib/github";
import { ASSET_TYPES, ENVIRONMENTS, type ActionResult } from "@/lib/repositories";

import { ComboField, SelectField, TextField, ToggleField } from "./fields";
import { FormDialog } from "./form-dialog";
import { BUTTON_PRIMARY, BUTTON_SECONDARY } from "./styles";

type Action = (formData: FormData) => Promise<ActionResult>;

export interface GitHubPicker {
  connected: boolean;
  manageUrl?: string;
  loadRepositories: () => Promise<AvailableRepository[]>;
  loadBranches: (repo: string) => Promise<BranchList | null>;
}

function sameAddress(a: string, b: string): boolean {
  const clean = (value: string) =>
    value.trim().replace(/\/+$/, "").replace(/\.git$/i, "").toLowerCase();
  return clean(a) === clean(b);
}

export function AddRepositoryButton({
  action,
  prominent,
  github,
}: {
  action: Action;
  prominent?: boolean;
  github?: GitHubPicker;
}) {
  const [open, setOpen] = useState(false);
  const [repositories, setRepositories] = useState<AvailableRepository[]>([]);
  const [url, setUrl] = useState("");
  const [loaded, setLoaded] = useState<{ repo: string; branches: string[] } | null>(null);
  const connected = github?.connected === true;
  const loadRepositories = github?.loadRepositories;
  const loadBranches = github?.loadBranches;

  const matched = repositories.find((repo) => repo.url && sameAddress(repo.url, url));
  const branches = matched && loaded?.repo === matched.full_name ? loaded.branches : [];

  useEffect(() => {
    if (!open || !connected || !loadRepositories) return;
    let cancelled = false;
    loadRepositories().then((found) => {
      if (!cancelled) setRepositories(found);
    });
    return () => {
      cancelled = true;
    };
  }, [open, connected, loadRepositories]);

  const matchedName = matched?.full_name;
  useEffect(() => {
    if (!matchedName || !loadBranches) return;
    let cancelled = false;
    loadBranches(matchedName).then((result) => {
      if (!cancelled) setLoaded({ repo: matchedName, branches: result?.branches ?? [] });
    });
    return () => {
      cancelled = true;
    };
  }, [matchedName, loadBranches]);

  return (
    <>
      <Button
        variant="outline"
        className={prominent ? BUTTON_PRIMARY : BUTTON_SECONDARY}
        onClick={() => setOpen(true)}
      >
        <Plus className="size-4" />
        Add repository
      </Button>
      <FormDialog
        open={open}
        onOpenChange={setOpen}
        title="Add a repository"
        description="This is the code ASPM will look at for vulnerable packages and risky code. Paste the address you would use to clone it."
        submitLabel="Add repository"
        action={action}
      >
        <input type="hidden" name="github_repo" value={matched?.full_name ?? ""} />
        <div className="space-y-2">
          <ComboField
            id="repo-url"
            name="url"
            type="url"
            required
            autoFocus
            label="Repository address"
            placeholder="https://github.com/your-team/your-repo"
            hint={
              connected
                ? "Paste an address, or pick one of your GitHub repositories from the list."
                : "The name is taken from the end of the address."
            }
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            options={repositories
              .filter((repo) => repo.url)
              .map((repo) => ({
                value: repo.url as string,
                label: repo.private ? `${repo.full_name} (private)` : repo.full_name,
              }))}
          />
          {connected && github?.manageUrl && (
            <a
              href={github.manageUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-0.5 font-mono text-[11px] font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
            >
              Missing a repository? Give ASPM access on GitHub
              <ArrowUpRight className="size-3.5" />
            </a>
          )}
          {github && !connected && (
            <Link
              href="/settings/github"
              className="inline-flex items-center gap-0.5 font-mono text-[11px] font-bold underline decoration-2 underline-offset-4 hover:bg-acid"
            >
              Connect GitHub to pick from your repositories
              <ArrowUpRight className="size-3.5" />
            </Link>
          )}
        </div>
        <div className="grid gap-5 sm:grid-cols-2">
          <ComboField
            id="repo-branch"
            name="branch"
            label="Branch (optional)"
            placeholder={matched?.branch ?? "main"}
            hint="Leave empty for the default branch."
            options={branches.map((branch) => ({ value: branch }))}
          />
          <TextField
            id="repo-language"
            name="language"
            label="Language (optional)"
            placeholder="Python"
          />
        </div>
      </FormDialog>
    </>
  );
}

export function AddAssetButton({
  action,
  prominent,
}: {
  action: Action;
  prominent?: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button
        variant="outline"
        className={prominent ? BUTTON_PRIMARY : BUTTON_SECONDARY}
        onClick={() => setOpen(true)}
      >
        <Plus className="size-4" />
        Add asset
      </Button>
      <FormDialog
        open={open}
        onOpenChange={setOpen}
        title="Add an asset"
        description="An asset is a place your code runs: a service, container, server or database. ASPM uses it to judge how risky a vulnerability really is."
        submitLabel="Add asset"
        action={action}
      >
        <TextField
          id="asset-name"
          name="name"
          required
          autoFocus
          label="Name"
          placeholder="payments-api"
          hint="Any name you will recognise."
        />
        <div className="grid gap-5 sm:grid-cols-2">
          <SelectField
            id="asset-environment"
            name="environment"
            label="Environment"
            options={ENVIRONMENTS}
            defaultValue="production"
          />
          <SelectField id="asset-type" name="type" label="Type" options={ASSET_TYPES} />
        </div>
        <ToggleField
          id="asset-public"
          name="internet_facing"
          label="Reachable from the internet"
          hint="Public assets rank higher, because anyone can attack them."
        />
      </FormDialog>
    </>
  );
}
