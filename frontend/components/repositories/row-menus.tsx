"use client";

import { ArrowUpRight, Link2, MoreHorizontal, Pencil, Trash2, X } from "lucide-react";
import { useActionState, useEffect, useState } from "react";

import { AuthNotice } from "@/components/auth-notice";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetTitle,
} from "@/components/ui/sheet";
import type { BranchList } from "@/lib/github";
import {
  ASSET_TYPES,
  ENVIRONMENTS,
  type ActionResult,
  withCurrent,
} from "@/lib/repositories";

import { ComboField, SelectField, ToggleField } from "./fields";
import { FormDialog } from "./form-dialog";
import {
  BUTTON_PRIMARY,
  BUTTON_SECONDARY,
  BUTTON_SMALL,
  BUTTON_SMALL_ACID,
  ICON_BUTTON,
  MENU_CONTENT,
  MENU_ITEM,
  PANEL_CLOSE,
  PANEL_HEADER,
  PANEL_TITLE,
  SHEET_CONTENT,
} from "./styles";

type Action = (formData: FormData) => Promise<ActionResult>;

export interface AssetOption {
  name: string;
  environment: string;
  type: string;
  internet_facing: boolean;
}

export function RepositoryActions({
  name,
  url,
  branch,
  assets,
  linked,
  branchAction,
  assetsAction,
  githubRepo,
  loadBranches,
}: {
  name: string;
  url: string;
  branch?: string;
  assets: AssetOption[];
  linked: string[];
  branchAction: Action;
  assetsAction: Action;
  githubRepo?: string;
  loadBranches?: (repo: string) => Promise<BranchList | null>;
}) {
  const [branchOpen, setBranchOpen] = useState(false);
  const [branches, setBranches] = useState<string[]>([]);

  useEffect(() => {
    if (!branchOpen || !githubRepo || !loadBranches) return;
    let cancelled = false;
    loadBranches(githubRepo).then((result) => {
      if (!cancelled) setBranches(result?.branches ?? []);
    });
    return () => {
      cancelled = true;
    };
  }, [branchOpen, githubRepo, loadBranches]);
  const [assetsOpen, setAssetsOpen] = useState(false);

  return (
    <div className="flex items-center gap-2">
      <Button
        variant="outline"
        className={linked.length === 0 ? BUTTON_SMALL_ACID : BUTTON_SMALL}
        onClick={() => setAssetsOpen(true)}
      >
        <Link2 className="size-3.5" />
        Link assets
      </Button>
      <DropdownMenu>
        <DropdownMenuTrigger
          aria-label={`More actions for ${name}`}
          render={<Button variant="outline" className={ICON_BUTTON} />}
        >
          <MoreHorizontal className="size-4" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" sideOffset={8} className={MENU_CONTENT}>
          <DropdownMenuItem className={MENU_ITEM} onClick={() => setBranchOpen(true)}>
            <Pencil className="size-4" />
            Change branch
          </DropdownMenuItem>
          <DropdownMenuItem
            className={MENU_ITEM}
            render={<a href={url} target="_blank" rel="noopener noreferrer" />}
          >
            <ArrowUpRight className="size-4" />
            Open repository
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <FormDialog
        open={branchOpen}
        onOpenChange={setBranchOpen}
        title="Change branch"
        description={`Which branch of ${name} should be scanned? Leave it empty to use the repository's default branch.`}
        submitLabel="Save branch"
        action={branchAction}
      >
        <ComboField
          id={`branch-${name}`}
          name="branch"
          label="Branch"
          defaultValue={branch ?? ""}
          placeholder="default branch"
          autoFocus
          options={branches.map((value) => ({ value }))}
        />
      </FormDialog>

      <Sheet open={assetsOpen} onOpenChange={setAssetsOpen}>
        <SheetContent showCloseButton={false} className={SHEET_CONTENT}>
          <LinkAssetsForm
            name={name}
            assets={assets}
            linked={linked}
            action={assetsAction}
            onClose={() => setAssetsOpen(false)}
          />
        </SheetContent>
      </Sheet>
    </div>
  );
}

function LinkAssetsForm({
  name,
  assets,
  linked,
  action,
  onClose,
}: {
  name: string;
  assets: AssetOption[];
  linked: string[];
  action: Action;
  onClose: () => void;
}) {
  const [state, formAction, pending] = useActionState(
    async (_: ActionResult, formData: FormData) => {
      const result = await action(formData);
      if (result.ok) onClose();
      return result;
    },
    {},
  );

  return (
    <form action={formAction} className="flex h-full min-h-0 flex-col">
      <div className={PANEL_HEADER}>
        <div className="space-y-1">
          <SheetTitle className={PANEL_TITLE}>Where does it run?</SheetTitle>
          <p className="font-mono text-xs text-background/70">{name}</p>
        </div>
        <SheetClose className={PANEL_CLOSE} aria-label="Close">
          <X className="size-4" />
        </SheetClose>
      </div>
      <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-6 py-6">
        <SheetDescription className="text-base leading-snug text-foreground">
          Tick every asset that runs this code. Its vulnerabilities will then be ranked by how
          exposed those assets are.
        </SheetDescription>
        {state.error && <AuthNotice tone="error">{state.error}</AuthNotice>}
        {assets.length === 0 ? (
          <div className="border-2 border-dashed border-foreground/40 p-4 font-mono text-sm">
            You have no assets yet. Close this panel, use <strong>Add asset</strong>, then come back.
          </div>
        ) : (
          <ul className="space-y-3">
            {assets.map((asset) => (
              <li key={asset.name}>
                <label className="brutal-lift flex items-start gap-3 border-2 border-foreground bg-card p-3 shadow-brutal-sm has-data-checked:bg-acid/30">
                  <Checkbox
                    name="assets"
                    value={asset.name}
                    defaultChecked={linked.includes(asset.name)}
                    className="mt-0.5 size-5 rounded-none border-2 border-foreground bg-card data-checked:bg-foreground data-checked:text-acid"
                  />
                  <span className="space-y-1">
                    <span className="block font-mono text-sm font-bold">{asset.name}</span>
                    <span className="flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase text-muted-foreground">
                      {asset.environment} · {asset.type}
                      {asset.internet_facing && (
                        <span className="-rotate-2 border-2 border-foreground bg-foreground px-1.5 py-0.5 font-bold text-acid">
                          ● Public
                        </span>
                      )}
                    </span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="flex items-center justify-end gap-3 border-t-2 border-foreground bg-card px-6 py-4">
        <SheetClose render={<Button type="button" variant="outline" className={BUTTON_SECONDARY} />}>
          Cancel
        </SheetClose>
        <Button type="submit" variant="outline" disabled={pending} className={BUTTON_PRIMARY}>
          {pending ? "Saving…" : "Save"}
        </Button>
      </div>
    </form>
  );
}

export function AssetActions({
  asset,
  updateAction,
  deleteAction,
}: {
  asset: AssetOption;
  updateAction: Action;
  deleteAction: Action;
}) {
  const [editOpen, setEditOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger
          aria-label={`More actions for ${asset.name}`}
          render={<Button variant="outline" className={ICON_BUTTON} />}
        >
          <MoreHorizontal className="size-4" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" sideOffset={8} className={MENU_CONTENT}>
          <DropdownMenuItem className={MENU_ITEM} onClick={() => setEditOpen(true)}>
            <Pencil className="size-4" />
            Edit
          </DropdownMenuItem>
          <DropdownMenuItem
            className={`${MENU_ITEM} focus:bg-crit`}
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="size-4" />
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <FormDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        title="Edit asset"
        description={`Change how ${asset.name} is described. Risk scores update straight away.`}
        submitLabel="Save changes"
        action={updateAction}
      >
        <SelectField
          id={`env-${asset.name}`}
          name="environment"
          label="Environment"
          options={withCurrent(ENVIRONMENTS, asset.environment)}
          defaultValue={asset.environment}
        />
        <SelectField
          id={`type-${asset.name}`}
          name="type"
          label="Type"
          options={withCurrent(ASSET_TYPES, asset.type)}
          defaultValue={asset.type}
        />
        <ToggleField
          id={`public-${asset.name}`}
          name="internet_facing"
          label="Reachable from the internet"
          hint="Public assets rank higher, because anyone can attack them."
          defaultChecked={asset.internet_facing}
        />
      </FormDialog>

      <FormDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete asset"
        description={`Delete ${asset.name}? It is unlinked from every repository, and findings stop inheriting its environment and exposure. This cannot be undone.`}
        submitLabel="Delete asset"
        action={deleteAction}
        danger
      />
    </>
  );
}
