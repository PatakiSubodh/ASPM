"use client";

import { X } from "lucide-react";
import { type ReactNode, useActionState } from "react";

import { AuthNotice } from "@/components/auth-notice";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog";
import type { ActionResult } from "@/lib/repositories";

import {
  BUTTON_DANGER,
  BUTTON_PRIMARY,
  BUTTON_SECONDARY,
  DIALOG_CONTENT,
  PANEL_CLOSE,
  PANEL_HEADER,
  PANEL_TITLE,
} from "./styles";

export interface FormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  submitLabel: string;
  action: (formData: FormData) => Promise<ActionResult>;
  danger?: boolean;
  children?: ReactNode;
}

export function FormDialog({ open, onOpenChange, ...props }: FormDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent showCloseButton={false} className={DIALOG_CONTENT}>
        <DialogBody onClose={() => onOpenChange(false)} {...props} />
      </DialogContent>
    </Dialog>
  );
}

function DialogBody({
  onClose,
  title,
  description,
  submitLabel,
  action,
  danger,
  children,
}: Omit<FormDialogProps, "open" | "onOpenChange"> & { onClose: () => void }) {
  const [state, formAction, pending] = useActionState(
    async (_: ActionResult, formData: FormData) => {
      const result = await action(formData);
      if (result.ok) onClose();
      return result;
    },
    {},
  );

  return (
    <form action={formAction} className="flex flex-col">
      <div className={PANEL_HEADER}>
        <DialogTitle className={PANEL_TITLE}>{title}</DialogTitle>
        <DialogClose className={PANEL_CLOSE} aria-label="Close">
          <X className="size-4" />
        </DialogClose>
      </div>
      <div className="space-y-5 px-6 py-6">
        <DialogDescription className="text-base leading-snug text-foreground">
          {description}
        </DialogDescription>
        {state.error && <AuthNotice tone="error">{state.error}</AuthNotice>}
        {children}
      </div>
      <div className="flex justify-end gap-3 border-t-2 border-dashed border-foreground/30 px-6 py-4">
        <DialogClose render={<Button type="button" variant="outline" className={BUTTON_SECONDARY} />}>
          Cancel
        </DialogClose>
        <Button
          type="submit"
          variant="outline"
          disabled={pending}
          className={danger ? BUTTON_DANGER : BUTTON_PRIMARY}
        >
          {pending ? "Working…" : submitLabel}
        </Button>
      </div>
    </form>
  );
}
