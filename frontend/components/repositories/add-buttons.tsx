"use client";

import { Plus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { ASSET_TYPES, ENVIRONMENTS, type ActionResult } from "@/lib/repositories";

import { SelectField, TextField, ToggleField } from "./fields";
import { FormDialog } from "./form-dialog";
import { BUTTON_PRIMARY, BUTTON_SECONDARY } from "./styles";

type Action = (formData: FormData) => Promise<ActionResult>;

export function AddRepositoryButton({
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
        <TextField
          id="repo-url"
          name="url"
          type="url"
          required
          autoFocus
          label="Repository address"
          placeholder="https://github.com/your-team/your-repo"
          hint="The name is taken from the end of the address."
        />
        <div className="grid gap-5 sm:grid-cols-2">
          <TextField
            id="repo-branch"
            name="branch"
            label="Branch (optional)"
            placeholder="main"
            hint="Leave empty for the default branch."
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
